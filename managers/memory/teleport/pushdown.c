#include <lego/completion.h>
#include <lego/fit_ibapi.h>
#include <lego/kthread.h>
#include <lego/mm.h>
#include <lego/ptrace.h>
#include <lego/slab.h>
#include <lego/sched.h>
#include <lego/signal.h>
#include <lego/spinlock.h>
#include <lego/time.h>
#include <memory/task.h>
#include <memory/loader.h>
#include <memory/pid.h>
#include <memory/vm.h>

#include <processor/fs.h>
#include <asm/tlbflush.h>

#include <teleport/pushdown.h>
#include <memory/teleport_vm.h>

// kernel thread for pushdown
static DEFINE_SPINLOCK(pushdown_instantiate_lock);
static LIST_HEAD(pushdown_instantiate_list);
struct task_struct *pushdown_task;

struct pushdown_instantiate_info* teleport_instances[TELEPORT_PARALLELISM];
DEFINE_SPINLOCK(teleport_instantiate_update_lock);

static inline void __pushdown_instantiate(struct pushdown_instantiate_info *inst)
{
    init_completion(&inst->done);

    spin_lock(&pushdown_instantiate_lock);
    list_add_tail(&inst->list, &pushdown_instantiate_list);
    spin_unlock(&pushdown_instantiate_lock);

    wake_up_process(pushdown_task);
}

/*
    This function instantiates a context to execute compute logic.
 */
void pushdown_instantiate(struct pushdown_instantiate_info *inst)
{
    __pushdown_instantiate(inst);
}

/*
    Copy a lego vm to executable vm.
*/
static void from_lego_mm_to_mm(struct lego_mm_struct *src, struct mm_struct *dst,
        struct lego_task_struct *src_task, struct task_struct *dst_task)
{
    dst->task_size = src->task_size;
    dst->highest_vm_end = src->highest_vm_end;
    dst->map_count = src->map_count;
    dst->total_vm = src->total_vm;
    dst->data_vm = src->data_vm;
    dst->exec_vm = src->exec_vm;
    dst->stack_vm = src->stack_vm;
    dst->def_flags = src->def_flags;
    dst->start_code = src->start_code;
    dst->end_code = src->end_code;
    dst->start_data = src->start_data;
    dst->end_data = src->end_data;
    dst->start_brk = src->start_brk;
    dst->brk = src->brk;
    dst->start_stack = src->start_stack;
    dst->arg_start = src->arg_start;
    dst->arg_end = src->arg_end;
    dst->env_start = src->env_start;
    dst->env_end = src->env_end;

    recover_mm_from_lego_mm(dst, src, dst_task, src_task);
}

static void from_lego_mm_to_mm_with_table(struct lego_mm_struct *src, struct mm_struct *dst,
        struct lego_task_struct *src_task, struct task_struct *dst_task, struct hlist_head* pageinfo_table,
        int hash_bits, struct pushdown_instantiate_info *inst)
{
    dst->task_size = src->task_size;
    dst->highest_vm_end = src->highest_vm_end;
    dst->map_count = src->map_count;
    dst->total_vm = src->total_vm;
    dst->data_vm = src->data_vm;
    dst->exec_vm = src->exec_vm;
    dst->stack_vm = src->stack_vm;
    dst->def_flags = src->def_flags;
    dst->start_code = src->start_code;
    dst->end_code = src->end_code;
    dst->start_data = src->start_data;
    dst->end_data = src->end_data;
    dst->start_brk = src->start_brk;
    dst->brk = src->brk;
    dst->start_stack = src->start_stack;
    dst->arg_start = src->arg_start;
    dst->arg_end = src->arg_end;
    dst->env_start = src->env_start;
    dst->env_end = src->env_end;

    recover_mm_from_lego_mm_with_table(dst, src, dst_task, src_task, pageinfo_table, hash_bits, inst->is_coherent);
}

/*
    Specification of a TELEPORT compute.
*/
typedef long (*teleport_compute)(unsigned long);
typedef unsigned long teleport_arg;

static int t_context(void *_inst)
{
    struct pushdown_instantiate_info *inst = _inst;
    unsigned int nid = inst->src_nid;
    unsigned int pid = inst->tgid; // lego_task uses tgid as identifier for memory management
    struct lego_task_struct *lego_tsk;
    struct lego_mm_struct *lego_mm;
    struct task_struct *tsk = current;
    struct mm_struct *old_mm, *new_mm;
    unsigned long func=inst->func;
    int num_pages_to_sync = inst->page_count;
    
    teleport_compute compute;
    teleport_arg arg;

#ifdef TELEPORT_PRINTING
    struct timeval cur_time;
    
    do_gettimeofday(&cur_time);
    inst->t_context_time = timeval_to_ns(&cur_time);
#endif

    lego_tsk = find_lego_task_by_pid(nid, pid);
    lego_mm = lego_tsk->mm;
    
    // emulate exec_mmap()
    // translate parent->mm (lego) to current->mm (linux)
    old_mm = tsk->mm;
    
    // allocate a new struct mm
    new_mm = mm_alloc();
    if (!new_mm)
        return -ENOMEM;

    if (num_pages_to_sync > 0) {
        // convert lego_mm to mm
        from_lego_mm_to_mm_with_table(lego_mm, new_mm, lego_tsk, tsk, inst->pageinfo_table, inst->bits_to_hash, inst);
    } else {
        // Convert lego_mm to mm
        from_lego_mm_to_mm(lego_mm, new_mm, lego_tsk, tsk);
    }

    // switch vm
    mm_release(tsk, old_mm);
    mmput(old_mm);
    task_lock(tsk);
    tsk->mm = new_mm;
    tsk->active_mm = new_mm;
    activate_mm(old_mm, new_mm);
    task_unlock(tsk);

    inst->task = tsk;
    inst->local_pid = tsk->pid;
    
    // disable old page table
    flush_tlb();

    // coherence is ready
    spin_unlock(&inst->coherence_ready_lock);
	
    // start executing pushdown function
    compute = (teleport_compute)func;
    arg = inst->arg;

#ifdef TELEPORT_PRINTING
    do_gettimeofday(&cur_time);
    inst->execution_start_time = timeval_to_ns(&cur_time);
#endif
    
    // execute
    inst->result = compute(arg);

#ifdef TELEPORT_PRINTING
    do_gettimeofday(&cur_time);
    inst->execution_end_time = timeval_to_ns(&cur_time);
#endif

    // post pushdown
    // build up the bloom filter for lazy sync
    if ((inst->page_count > 0) && !(inst->is_coherent)) {
        int i, dirty_count;
        dirty_count = 0;

        bloom_init(&(inst->response->page_filter), inst->page_count, (void *)((char *)inst->response) + sizeof(*(inst->response)));
        
        for (i = 0; i != inst->page_count; i++) {
            pgd_t *pgd;
            pud_t *pud;
            pmd_t *pmd;
            pte_t *pte;
            unsigned long addr = inst->hash_items[i].addr;
            struct mm_struct *mm = tsk->mm;

            pgd = pgd_offset(mm, addr);
            pud = pud_offset(pgd, addr);
            pmd = pmd_offset(pud, addr);
            pte = pte_offset(pmd, addr);

            if ((!pte) || (pte_none(*pte))) continue;

            if (likely(pte_dirty(*pte))) {
                bloom_add(&(inst->response->page_filter), &addr, sizeof(addr));
            }
        }
    }
    complete(&inst->done);

    preempt_disable();
    do_task_dead(); // never returns

    BUG();

    return 0;
}

/*
    Instantiate the context here to execute the pushdown function by
    creating a new task which shares the targeted task VM.
*/
static void instantiate_context(struct pushdown_instantiate_info *inst)
{
    pid_t pid;

    int num_pages_to_sync = inst->page_count;

    inst->hash_items = NULL;
    inst->pageinfo_table = NULL;

    if (num_pages_to_sync > 0) {
#ifdef TELEPORT_COMPRESSION
        struct p2m_pushdown_pageinfo_addr_compression* addr_list;
        struct p2m_pushdown_pageinfo_dirty_compression* dirty_list;
        int d;
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
        struct p2m_pushdown_pageinfo_compression* p_list;
        int d;
#else
        struct p2m_pushdown_pageinfo* p_list;
#endif
        int i;
        // hash table for pageinfo look up
        inst->bits_to_hash = ilog2(num_pages_to_sync);
        inst->pageinfo_table = kmalloc(sizeof(struct hlist_head)*(1 << inst->bits_to_hash), GFP_KERNEL);
        if (!inst->pageinfo_table) {
            // failed to allocate memory for hash table
            goto fail;
        }
        hash_init_with_bits(inst->pageinfo_table, inst->bits_to_hash);

        inst->hash_items = kmalloc(sizeof(struct pageinfo)*num_pages_to_sync, GFP_KERNEL);
        if (!inst->hash_items) {
            // failed to allocate memory for hash table items
            goto fail;
        }
#ifdef TELEPORT_COMPRESSION
        // dirty bit construction
        addr_list = inst->pageinfo_addr_list;
        dirty_list = inst->pageinfo_dirty_list;
        d = 0;
        for (i = 0; i != inst->dirty_count; i++) {
            int j;
            int count = dirty_list[i].count;
            for (j = 0; j != count; j++) {
                inst->hash_items[d].is_dirty = dirty_list[i].is_dirty;
                d++;
            }
        }

        // address construction
        d = 0;
        for (i = 0; i != inst->addr_count; i++) {
            int j;
            int count = addr_list[i].count;
            for (j = 0; j != count; j++) {
                inst->hash_items[d].addr = addr_list[i].start_addr + j * PAGE_SIZE;
                hash_add_with_bits(inst->pageinfo_table, &(inst->hash_items[d].next), inst->hash_items[d].addr, inst->bits_to_hash);
                d++;
            }
        }
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
        // page list construction
        p_list = inst->pageinfo_list;
        d = 0;
        for (i = 0; i != inst->embedded_count; i++) {
            int j;
            int count = p_list[i].count;
            for (j = 0; j != count; j++) {
                inst->hash_items[d].addr = (p_list[i].start_addr_dirty_embedded & PAGE_MASK) + j * PAGE_SIZE;
                inst->hash_items[d].is_dirty = (char)(p_list[i].start_addr_dirty_embedded & 0x01);
                hash_add_with_bits(inst->pageinfo_table, &(inst->hash_items[d].next), inst->hash_items[d].addr, inst->bits_to_hash);
                d++;
            }
        }
#else
        p_list = inst->pageinfo_list;
        for (i = 0; i != num_pages_to_sync; i++) {
            inst->hash_items[i].addr = p_list->addr;
            inst->hash_items[i].is_dirty = p_list->is_dirty;
            hash_add_with_bits(inst->pageinfo_table, &(inst->hash_items[i].next), inst->hash_items[i].addr, inst->bits_to_hash);
            p_list++;
        }
#endif
    }

    // coherence is not ready, so lock it
    spin_lock(&inst->coherence_ready_lock);

    // update teleport_instances
    spin_lock(&teleport_instantiate_update_lock);
    do {
        int i;
        for (i = 0; i != TELEPORT_PARALLELISM; i++) {
            if (teleport_instances[i] == NULL) {
                break;
            }
        }
        if(unlikely(i == TELEPORT_PARALLELISM)) {
            printk("TELEPORT: failed to find a teleport_instance.\n");
        } else {
            teleport_instances[i] = inst;
        }
    } while (false);
    spin_unlock(&teleport_instantiate_update_lock);


    pid = kernel_thread(t_context, inst, 0);

    if (pid < 0) {
        // if user was SIGKILLed, release the structure
        goto fail;
    }

    return;

fail:
    // failed to instantiate t_context
    complete(&inst->done);
}

int pushdown(void *unused)
{
    struct task_struct *tsk = current;

    // setup a context for children to inherit
    set_task_comm(tsk, "pushdown");

    ignore_signals(tsk);

    set_cpus_allowed_ptr(tsk, cpu_possible_mask);

    pr_info("%s(pid:%d/cpu:%d) is running as daemon\n",
            current->comm, current->pid, smp_processor_id());

    for (;;) {
        set_current_state(TASK_INTERRUPTIBLE);
        if (list_empty(&pushdown_instantiate_list))
            schedule();
        __set_current_state(TASK_RUNNING);

        spin_lock(&pushdown_instantiate_lock);
        while (!list_empty(&pushdown_instantiate_list)) {
            struct pushdown_instantiate_info *inst;
            int retlen, res;

            inst = list_entry(pushdown_instantiate_list.next,
                    struct pushdown_instantiate_info, list);
            list_del_init(&inst->list);
            spin_unlock(&pushdown_instantiate_lock);

            // process a pushdown
            instantiate_context(inst);

            // wait for the completion
            wait_for_completion(&inst->done);

            // one pushdown instance is completed
            // respond back to the compute pool
            inst->response->pid = inst->pid;
            inst->response->retval = inst->result;
            #ifdef TELEPORT_PRINTING
                inst->response->time_profile.t_context_time = inst->t_context_time;
                inst->response->time_profile.execution_start_time = inst->execution_start_time;
                inst->response->time_profile.execution_end_time = inst->execution_end_time;
            #endif

            ((struct common_header *)inst->response_buffer)->opcode = M2P_TELEPORT_COMPLETE;
            ((struct common_header *)inst->response_buffer)->src_nid = inst->src_nid;

            retlen = ibapi_send_reply_imm(inst->src_nid, inst->response_buffer, sizeof(struct common_header) + inst->resp_length,
                &res, sizeof(res), false);

            if (unlikely(retlen != sizeof(res))) {
                panic("TELEPORT: failed to send response\n");
            }

            if (inst->hash_items) {
                kfree(inst->hash_items);   
                inst->hash_items = NULL;

                kfree(inst->pageinfo_table);
                inst->pageinfo_table = NULL;
            }

            if (inst->access_list) {
                kfree(inst->access_list);
                inst->access_list = NULL;
            }

            kfree((void *)inst->response_buffer);
            inst->response_buffer = NULL;

            do {
                int i;
                for (i = 0; i != TELEPORT_PARALLELISM; i++) {
                    if (teleport_instances[i] == inst) {
                        teleport_instances[i] = NULL;
                        break;
                    }
                }
            } while (false);

            kfree(inst);
            inst = NULL;

            spin_lock(&pushdown_instantiate_lock);
        }
        spin_unlock(&pushdown_instantiate_lock);
    }

    return 0;
}
