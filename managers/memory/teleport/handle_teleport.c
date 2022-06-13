#include <lego/slab.h>
#include <lego/kernel.h>
#include <lego/uaccess.h>
#include <lego/fit_ibapi.h>
#include <lego/time.h>

#include <teleport/pushdown.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/thread_pool.h>
#include <memory/teleport_syncmem.h>

#include <asm/tlbflush.h>

static void syncmem_error(u32 retval, struct lego_task_struct *p,
                  u64 vaddr, struct thpool_buffer *tb)
{
    int *reply = thpool_buffer_tx(tb);

    *reply = retval;
    tb_set_tx_size(tb, sizeof(*reply));

    dump_lego_tasks();
    if (p) {
        pr_info("synmem error - src_nid:%u,pid:%u,vaddr:%#Lx\n", p->node, p->pid, vaddr);
        dump_all_vmas_simple(p->mm);
    }
    WARN_ON_ONCE(1);
}

static void do_handle_p2m_syncmem(struct lego_task_struct *p,
        u64 vaddr, u32 flags, u32 offset_head, u32 size, struct thpool_buffer *tb) {
    int ret;
    unsigned long new_page;

    ret = common_handle_p2m_miss(p, vaddr, flags, &new_page);
    if (unlikely(ret & VM_FAULT_ERROR)) {
        if (ret & VM_FAULT_OOM)
            ret = RET_ENOMEM;
        else if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
            ret = RET_ESIGSEGV;

        syncmem_error(ret, p, vaddr, tb);
        return;
    }

    tb_set_private_tx(tb, ((void *)new_page + offset_head));
    tb_set_tx_size(tb, size);
}

void handle_p2m_syncmem(struct p2m_syncmem_m2p_msg *msg,
                        struct thpool_buffer *tb) {
    u32 tgid, flags, offset_head, size;
    u64 vaddr;
    unsigned int src_nid;
    struct lego_task_struct *p;

    src_nid = to_common_header(msg)->src_nid;
    tgid   = msg->tgid;
    flags  = msg->flags;
    vaddr  = msg->missing_vaddr;
    offset_head = msg->offset_head;
    size = msg->size;

    p = find_lego_task_by_pid(src_nid, tgid);
    if (unlikely(!p)) {
        pr_info("%s(): src_nid: %d tgid: %d\n", __func__, src_nid, tgid);
        syncmem_error(RET_ESRCH, p, vaddr, tb);
        return;
    }

    do_handle_p2m_syncmem(p, vaddr, flags, offset_head, size, tb);
}

void handle_p2m_pushdow(struct p2m_pushdown_payload *payload,
        struct common_header *hdr, struct thpool_buffer *tb) {
    struct pushdown_instantiate_info *inst;
    int response_code;
#ifdef TELEPORT_PRINTING
    struct timeval req_recv_timeval;
#endif

    inst = kmalloc(sizeof(*inst), GFP_KERNEL);
    if(!inst) {
        response_code = -1;
        goto out;
    }
    inst->src_nid = hdr->src_nid;
    inst->pid = payload->pid;
    inst->tgid = payload->tgid;
    inst->parent_tgid = payload->parent_tgid;
    inst->func = payload->func;
    inst->arg = payload->arg;
    inst->page_count = payload->page_count;
    inst->resp_length = payload->resp_length;
    
    // create response buffer
    inst->response_buffer = kmalloc(sizeof(struct common_header) + inst->resp_length, GFP_KERNEL);
    inst->response = (struct teleport_response *)((char *)inst->response_buffer + sizeof(struct common_header));
#ifdef TELEPORT_PRINTING
    do_gettimeofday(&req_recv_timeval);
    inst->response->time_profile.req_recv_time = timeval_to_ns(&req_recv_timeval);
#endif

    inst->is_coherent = payload->is_coherent;
#ifdef TELEPORT_COMPRESSION
    inst->addr_count = payload->addr_count;
    inst->dirty_count = payload->dirty_count;
    inst->pageinfo_addr_list = (struct p2m_pushdown_pageinfo_addr_compression*) (((void*)payload) + sizeof(*payload));
    inst->pageinfo_dirty_list = (struct p2m_pushdown_pageinfo_dirty_compression*) (((void*)payload) + sizeof(*payload)
                    + sizeof(struct p2m_pushdown_pageinfo_addr_compression) * payload->addr_count);
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
    inst->embedded_count = payload->embedded_count;
    inst->pageinfo_list = (struct p2m_pushdown_pageinfo_compression*) (((void*)payload) + sizeof(*payload));
#else
    inst->pageinfo_list = (struct p2m_pushdown_pageinfo*) (((void*)payload) + sizeof(*payload));
#endif
    inst->result = 0;

    // init spin lock
    spin_lock_init(&inst->coherence_ready_lock);

    if (inst->is_coherent) {
        int i;

        // initialize access list
        inst->access_list = kmalloc(sizeof(struct accessinfo) * TELEPORT_ACCESS_TABLE_LENGTH, GFP_KERNEL);
        if (unlikely(!inst->access_list)) {
            panic("TELEPORT: failed to allocate memory for access_list\n");
        }
        for (i = 0; i != TELEPORT_ACCESS_TABLE_LENGTH; i++) {
            inst->access_list[i].addr = 0;
            spin_lock_init(&inst->access_list[i].update_lock);
        }
    } else {
        inst->access_list = NULL;
    }

    inst->t_context_time = 0;
    inst->execution_start_time = 0;
    inst->execution_end_time = 0;

    pr_debug("TELEPORT: pid: %u, func: %#Lx, arg:%#Lx\n",
        inst->pid, inst->func, inst->arg);

    pushdown_instantiate(inst);

    // return immediately
    response_code = 0;

out:
    tb_set_tx_size(tb, sizeof(int));
    *((int *)(tb->tx)) = response_code;
}

void handle_p2m_pcache_invalid(struct p2m_pcache_invalid_payload *msg,
			    struct common_header *hdr, struct thpool_buffer *tb) {
	u32 tgid;
	unsigned long vaddr, addr;
	unsigned int src_nid;
	struct lego_task_struct *p;
    struct lego_mm_struct *lego_mm;
    struct mm_struct *mm;
    pgd_t *lego_pgd;
    pud_t *lego_pud;
    pmd_t *lego_pmd;
    pte_t *lego_pte;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    spinlock_t *lego_ptl, *ptl;
    struct accessinfo *recent_access;
    int access_index;
    struct pushdown_instantiate_info *teleport_instance = NULL;

    do {
        int i;
        for (i = 0; i != TELEPORT_PARALLELISM; i++) {
            if (teleport_instances[i] && (teleport_instances[i]->tgid == msg->tgid)) {
                teleport_instance = teleport_instances[i];
                break;
            }
        }
    } while (false);

    if ((!teleport_instance) || !(teleport_instance->is_coherent)) {
        goto good_ret;
    }
	src_nid = hdr->src_nid;
	tgid  = msg->tgid;
	vaddr = msg->invalid_vaddr;
    addr = vaddr & PAGE_MASK;

    // check if the address if recently accessed
    access_index = hash_min(addr, 64) % TELEPORT_ACCESS_TABLE_LENGTH;
    recent_access = &teleport_instance->access_list[access_index];

    if (spin_is_locked(&recent_access->update_lock)) {
        // page access is locked, so retry
        goto retry_ret;
    }

    if (recent_access->addr == addr) {
        spin_lock(&recent_access->update_lock);
        recent_access->addr = 1;
        spin_unlock(&recent_access->update_lock);
            
        // page recently accessed, so retry
        goto retry_ret;
    }

	p = find_lego_task_by_pid(src_nid, tgid);
	if (unlikely(!p)) {
		pr_info("%s(): src_nid: %d tgid: %d\n", __func__, src_nid, tgid);
		goto bad_ret;
	}

    lego_mm = p->mm;
    if (teleport_instance && teleport_instance->task) {
        mm = teleport_instance->task->mm;
    } else {
        goto good_ret;
    }

    lego_pgd = lego_pgd_offset(lego_mm, addr);	
    lego_pud = lego_pud_offset(lego_pgd, addr);
    lego_pmd = lego_pmd_offset(lego_pud, addr);
    lego_pte = lego_pte_offset(lego_pmd, addr);

    lego_ptl = lego_pte_lockptr(lego_mm, lego_pmd);

    // check if lego_ptl is locked
    if (spin_is_locked(lego_ptl)) {
        // lego_ptl is locked means that memory node is working on the page
        // this request should back off and retry
        goto retry_ret;
    }

    // lock this page for TELEPORT coherence
    spin_lock(&recent_access->update_lock);

    // lock the page table
    spin_lock(lego_ptl);

    pgd = pgd_offset(mm, addr);
    pud = pud_offset(pgd, addr);
    if (unlikely(pud_none(*pud))) {
        goto unlock_invalid;
    }
    pmd = pmd_offset(pud, addr);
    if (unlikely(pmd_none(*pmd))) {
        goto unlock_invalid;
    }
    pte = pte_offset(pmd, addr);
    if (pte_none(*pte)) {
        goto unlock_invalid;
    }
    if (pte_present(*pte)) {
        ptl = pte_lockptr(mm, pmd);
        if (ptl != lego_ptl) {
            spin_lock(ptl);
        }

        // invalidate the page in default coherence
        if (teleport_instance->is_coherent == 1) {
            pte_clear(pte);
        } else {
            // only write-protect the page in weak coherence
            pte_t entry = ptep_get_and_clear(0, pte);
            entry = pte_wrprotect(entry);
            entry = pte_mkclean(entry);
            pte_set(pte, entry);
        }

        // flush TLB
        flush_tlb_mm_range(mm, addr, addr + PAGE_SIZE - 1);

        if (ptl != lego_ptl) {
            spin_unlock(ptl);
        }
    }
unlock_invalid:
	tb_set_tx_size(tb, sizeof(int));
    *((int *)(tb->tx)) = 0;

    recent_access->addr = 42;
    spin_unlock(&recent_access->update_lock);

	spin_unlock(lego_ptl);

    return;

good_ret:
	tb_set_tx_size(tb, sizeof(int));
    *((int *)(tb->tx)) = 0;

    return;
retry_ret:

    tb_set_tx_size(tb, sizeof(int));
    *((int *)(tb->tx)) = 1;

    return;

bad_ret: 
    // error happened when invalidating the page
    tb_set_tx_size(tb, sizeof(int));
    *((int *)(tb->tx)) = -1;
}
