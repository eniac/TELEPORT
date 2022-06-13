#include <lego/mm.h>
#include <lego/smp.h>
#include <lego/slab.h>
#include <lego/log2.h>
#include <lego/kernel.h>
#include <lego/pgfault.h>
#include <lego/syscalls.h>
#include <lego/ratelimit.h>
#include <lego/checksum.h>
#include <lego/profile.h>
#include <lego/fit_ibapi.h>

#include <lego/rpc/struct_common.h>
#include <lego/rpc/struct_p2m.h>

#include <memory/pid.h>
#include <memory/task.h>
#include <memory/vm.h>

#include <teleport/pushdown.h>

/*
    Get the local page.
*/
int common_handle_fault_local_teleport_get_user_pages(struct lego_task_struct *p,
        u64 vaddr, u32 flags, struct vm_area_struct **vma)
{
    unsigned long dst_page;
	int ret = 0;

    down_read(&p->mm->mmap_sem);
	ret = get_user_pages(p, vaddr, 1, 0, &dst_page, NULL);
	up_read(&p->mm->mmap_sem);

    if (likely(ret == 1))
        memset((void *)dst_page, 0, PCACHE_LINE_SIZE);
    else {
		WARN_ON_ONCE(1);
    }

    return ret == 1 ? 0 : -1;
}

/*
    Handle page faults during pushdown execution.
*/
int teleport_handle_fault(struct mm_struct *mm, int pid, int tgid,
        unsigned long address, __u32 flags, __u32 node_id, bool write,
        __u8 coherence_bits, struct pushdown_instantiate_info *teleport_instance)
{
    __u32 len_msg;
    void *msg;
    struct common_header *hdr;
    struct m2p_fault_payload *payload;

    void* local_addr;
    ssize_t retlen;
    bool must_fetch = false;

    struct lego_task_struct *lego_tsk;
    struct lego_mm_struct *lego_mm;
	struct lego_mm_struct *actual_mm;
	struct vm_area_struct *vma;
    pgd_t *lego_pgd;
    pud_t *lego_pud;
    pmd_t *lego_pmd;
    pte_t *lego_pte;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t real_pte;
    spinlock_t *src_ptl, *dst_ptl;
    struct accessinfo *recent_access;
    int access_index;

    int res = 0;

    if (coherence_bits) {
        // put this page in the access list first
        access_index = hash_min(address, 64) % TELEPORT_ACCESS_TABLE_LENGTH;
        recent_access = &teleport_instance->access_list[access_index];

        if (recent_access->addr == 1) {
            // this accessed was retried
            return 0;
        }

        // acquire coherence lock
        spin_lock(&recent_access->update_lock);
    }
    
    lego_tsk = find_lego_task_by_pid(node_id, tgid);
    lego_mm = lego_tsk->mm;

	down_read(&lego_mm->mmap_sem);
	vma = find_vma(lego_mm, address);
	up_read(&lego_mm->mmap_sem);

	if (unlikely(!vma)) {
		pr_info("fail to find vma\n");
        if (coherence_bits) {
            spin_unlock(&recent_access->update_lock);
        }
		return VM_FAULT_SIGSEGV;
	}

	actual_mm = vma->vm_mm;

    // make sure there is a physical page locally
    lego_pgd = lego_pgd_offset(actual_mm, address);	
    lego_pud = lego_pud_offset(lego_pgd, address);
    lego_pmd = lego_pmd_offset(lego_pud, address);
    lego_pte = lego_pte_offset(lego_pmd, address);
    if (((unsigned long)lego_pte) < PAGE_SIZE) {
        lego_pte = NULL;
    }

    if (!lego_pte || pte_none(*lego_pte)) {
        // local processing
        common_handle_fault_local_teleport_get_user_pages(lego_tsk, address, flags, &vma);

        lego_pgd = lego_pgd_offset(actual_mm, address);	
        lego_pud = lego_pud_offset(lego_pgd, address);
        lego_pmd = lego_pmd_offset(lego_pud, address);
        lego_pte = lego_pte_offset(lego_pmd, address);
        if (((unsigned long)lego_pte) < PAGE_SIZE) {
            if (coherence_bits) {
                spin_unlock(&recent_access->update_lock);
            }
            return -1;
        }
        must_fetch = true;
    }

    local_addr = (void*)(lego_pte_to_virt(*lego_pte));
    real_pte = *lego_pte;

    if (!coherence_bits) {
        // directly fetch from compute pool
        goto fetch_from_compute;
    }
	if (write) {
        pgd = pgd_offset(mm, address);	
        pud = pud_offset(pgd, address);
        if (unlikely(pud_none(*pud))) {
            goto fetch_from_compute;
        }
        pmd = pmd_offset(pud, address);
        if (unlikely(pmd_none(*pmd))) {
            goto fetch_from_compute;
        }
        pte = pte_offset(pmd, address);
        if (pte_none(*pte)) {
            goto fetch_from_compute;
        }
        if (must_fetch) {
            goto fetch_from_compute;
        }
    } else {
        // read has to be fetched from compute pool
        goto fetch_from_compute;
    }

    // just invalidate the page in compute pool
    len_msg = sizeof(struct common_header) + sizeof(struct m2p_fault_payload);
    msg = kzalloc(len_msg, GFP_KERNEL);
    if (IS_ERR(msg)) {
        spin_unlock(&recent_access->update_lock);
        return -ENOMEM;
    }

    hdr = msg;
    hdr->opcode = M2P_TELEPORT_INVALIDATE;
    hdr->src_nid = node_id;

    payload = msg + sizeof(*hdr);
    payload->addr = (__u64)address;
    payload->pid = pid;
    payload->tgid = tgid;
    payload->write = (__u8)write;
    payload->coherent = (__u8)coherence_bits;

    retlen = ibapi_send_reply_imm(node_id, msg, len_msg,
            &res, sizeof(res), false);
    if (unlikely(retlen != sizeof(res))) {
        // failed to invalidate
        WARN_ON_ONCE(1);
        res = -EFAULT;
        goto out;
    }
    
    if (unlikely(res != 0)) {
        if (likely(res == 1)) {
            // retry
            recent_access->addr = 1;
            res = 0;
        } else {
            // unknown result M2C invalidation
            WARN_ON_ONCE(1);
            res = -EFAULT;
        }
        goto out;
    }
    
    // lock on lego pte to prevent race from page fault request from compute pool
    src_ptl = lego_pte_lockptr(lego_mm, lego_pmd);
    spin_lock(src_ptl);

    dst_ptl = pte_lockptr(mm, pmd);
    if (src_ptl != dst_ptl) {
        spin_lock(dst_ptl);
    }
    *pte = pte_mkwrite(*pte);
    if (src_ptl != dst_ptl) {
        spin_unlock(dst_ptl);
    }
    spin_unlock(src_ptl);

    // only record this access if it succeeds
    recent_access->addr = address;

    goto out;

fetch_from_compute:
    pgd = pgd_offset(mm, address);

    pud = pud_alloc(mm, pgd, address);
    if (!pud) {
        goto oom_out;
    }

    pmd = pmd_alloc(mm, pud, address);
    if (!pmd) {
        goto oom_out;
    }

    pte = pte_alloc(mm, pmd, address);
    if (!pte) {
        goto oom_out;
    }

    // fetch the page from compute pool
    len_msg = sizeof(struct common_header) + sizeof(struct m2p_fault_payload);
    msg = kzalloc(len_msg, GFP_KERNEL);
    if (IS_ERR(msg)) {
        if (coherence_bits) {
            spin_unlock(&recent_access->update_lock);
        }
        return -ENOMEM;
    }

    hdr = msg;
    hdr->opcode = M2P_TELEPORT_PAGE_FAULT;
    hdr->src_nid = node_id;

    payload = msg + sizeof(*hdr);
    payload->addr = (__u64)address;
    payload->pid = pid;
    payload->tgid = tgid;
    payload->write = write;
    payload->coherent = coherence_bits;
    
    retlen = ibapi_send_reply_imm(node_id, msg, len_msg,
            local_addr, PCACHE_LINE_SIZE, false);
    
    if (unlikely(retlen != PCACHE_LINE_SIZE)) {
        if (likely(retlen == sizeof(int))) {
            int ack_result = *((int *)local_addr);
            if (unlikely(ack_result != 1)) {
                if (likely(ack_result == 0)) {
                    // page has been evicted
                    goto out;
                } else {
                    panic("TELEPORT: unknown result (%d) for %p\n", ack_result, address);
                }
            }
            goto out;
        } else {
            panic("TELEPORT: failed to fetch a page %p!\n", address);
        }
    }

    // page fecthed, update page table 
    dst_ptl = pte_lockptr(mm, pmd);
    spin_lock(dst_ptl);
    src_ptl = lego_pte_lockptr(lego_mm, lego_pmd);
    if (src_ptl != dst_ptl) {
        spin_lock(src_ptl);
    }

    real_pte = pfn_pte(virt_to_pfn(lego_pte_to_virt(real_pte)), vma->vm_page_prot);
    real_pte = pte_mkold(real_pte);
    real_pte = pte_mkclean(real_pte);
    if (write || !coherence_bits) {
        real_pte = pte_mkwrite(real_pte);
    } else {
        real_pte = pte_wrprotect(real_pte);
    }
    pte_set(pte, real_pte);

    spin_unlock(dst_ptl);
    if (src_ptl != dst_ptl) {
        spin_unlock(src_ptl);
    }
    // done

    if (coherence_bits) {
        recent_access->addr = address;
    }
    
out:
    if (coherence_bits) {
        spin_unlock(&recent_access->update_lock);
    }

    kfree(msg);
    return res;

oom_out:
    if (coherence_bits) {
        spin_unlock(&recent_access->update_lock);
    }
    return VM_FAULT_OOM;
}
