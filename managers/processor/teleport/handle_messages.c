#include <lego/pid.h>
#include <processor/pcache_types.h>
#include <processor/pcache.h>
#include <teleport/pushdown.h>

static void* resp;

void init_pfault_resp(void) {
    resp = kmalloc(PCACHE_LINE_SIZE, GFP_KERNEL);
    if (!resp)
        panic("TELEPORT: Unable to allocate response buffer for lazy sync.");
}

static __always_inline void get_pmd_and_pte(struct mm_struct *mm, unsigned long addr, pmd_t **pmd, pte_t** pte)
{
    pgd_t *pgd;
    pud_t *pud;

    pgd = pgd_offset(mm, addr);

    pud = pud_offset(pgd, addr);
    
    *pmd = pmd_offset(pud, addr);
    
    *pte = pte_offset(*pmd, addr);
}

/*
    The handler that processes coherence protocol messages.
*/
static inline void teleport_coherence_message_handler(void *fit_ctx, void *fit_imm,
        struct common_header *msg_hdr, void *msg_payload, int node_id, int fit_offset) {
    struct m2p_fault_payload *payload;
    struct common_header *hdr;
    struct task_struct* task;
    int task_id;
    unsigned long page_addr;
    void *page_kva_pcm;
    pmd_t *pmd;
    pte_t *pte;
    struct pcache_meta* pcm;
    int ack_result;
    int access_index;
    u32 hash_value;

    hdr = msg_hdr;
    payload = (struct m2p_fault_payload *)(msg_payload);
    
    hash_value = hash_min(payload->addr, 64);
    access_index = hash_value % TELEPORT_ACCESS_TABLE_LENGTH;

    // data profiling
    teleport_online_pagefaults++;

    // check if the access is already locked
    if (spin_is_locked(&compute_pool_access_list[access_index].update_lock)) {
        // memory pool needs to back off and retry
        goto ack_reply_retry;
    }

    // acquire lock on the page
    spin_lock(&compute_pool_access_list[access_index].update_lock);

	if (hdr->opcode == M2P_TELEPORT_INVALIDATE) {
        goto invalidate_and_reply_int;
    } else if (hdr->opcode == M2P_TELEPORT_PAGE_FAULT) {
        goto reply_page;
    } else {
        goto ack_reply_bad;
    }

invalidate_and_reply_int:
    // invalidate the page
    task_id = payload->pid;
    page_addr = payload->addr;

    task = find_task_by_pid(task_id);
    get_pmd_and_pte(task->mm, page_addr, &pmd, &pte);

    // this can happen because the page might have been evicted, so just safely return
    if ((!pte) || pte_none(*pte)) {
        goto unlock;
    }

    pcm = pte_to_pcache_meta(*pte);
    lock_pcache(pcm);
    if (payload->coherent == 1) {
        // invalidate
        int i = 0;
        int refs = 0;
        pcache_try_to_unmap(pcm);
        __ClearPcacheReclaim(pcm);
        __ClearPcacheLocked(pcm);
        refs = pcache_ref_count(pcm);
        for (; i != refs; i++) {
            put_pcache(pcm);
        }
    } else {
        // write-protect
        pcache_wrprotect(pcm);
    }
    unlock_pcache(pcm);

    // reply back
    ack_result = 0;
    fit_ack_reply_callback_parameterized(fit_ctx, fit_imm, node_id, fit_offset, &ack_result, sizeof(int));

    goto unlock;

reply_page:
    task_id = payload->tgid;
    page_addr = payload->addr;

    task = find_task_by_pid(task_id);
    get_pmd_and_pte(task->mm, page_addr, &pmd, &pte);
    
    if ((!pte) || pte_none(*pte)) {
        ack_result = 0;
        fit_ack_reply_callback_parameterized(fit_ctx, fit_imm, node_id, fit_offset, &ack_result, sizeof(int));
    }
    
    // get kernel virtual address
    page_kva_pcm = pcache_meta_to_kva(pte_to_pcache_meta(*pte));

	if (payload->coherent) {
        pcm = pte_to_pcache_meta(*pte);
        lock_pcache(pcm);

        // only invalidate a page for a write in coherence
        if (payload->write && (payload->coherent == 1)) {
            // invalidate
            int i = 0;
            int refs = 0;
            pcache_try_to_unmap(pcm);
            __ClearPcacheReclaim(pcm);
            __ClearPcacheLocked(pcm);
            refs = pcache_ref_count(pcm);
            for (; i != refs; i++) {
                put_pcache(pcm);
            }
        } else {
            // make write protect
            pcache_wrprotect(pcm);
        }
        unlock_pcache(pcm);
    }

    memcpy(resp, page_kva_pcm, PCACHE_LINE_SIZE);
    smp_wmb();

    fit_ack_reply_callback_parameterized(fit_ctx, fit_imm, node_id, fit_offset, resp, PCACHE_LINE_SIZE);

    goto unlock;

ack_reply_bad:
    ack_result = -1;
    fit_ack_reply_callback_parameterized(fit_ctx, fit_imm, node_id, fit_offset, &ack_result, sizeof(int));

    goto unlock;


unlock:
    // unlock the page
    spin_unlock(&compute_pool_access_list[access_index].update_lock);

    return;

ack_reply_retry:
    ack_result = 1;
    fit_ack_reply_callback_parameterized(fit_ctx, fit_imm, node_id, fit_offset, &ack_result, sizeof(int));
}

/*
    The handler that processes pushdown completion message.
*/
static inline void teleport_completion_message_handler(void *fit_ctx, void *fit_imm,
        void *msg_payload, int rx_size, int node_id, int fit_offset) {
    int ack_result = 0;
    struct ongoing_teleport *curr;
    struct teleport_response *payload = (struct teleport_response *)msg_payload;

    // find the ongoing pushdown instance
    spin_lock(&teleport_reqs_lock);
    curr = teleport_ongoing_list;
    while(curr!=NULL && curr->pid != payload->pid) {
        curr = curr->next;
    }    
    spin_unlock(&teleport_reqs_lock);
    
    if(unlikely(curr == NULL)) {
        panic("TELEPORT: cannot find a matching instance\n");
    }

    if (unlikely(curr->expected_len != (rx_size - sizeof(struct common_header)))) {
        panic("TELEPORT: response error\n");
    }

    curr->response = msg_payload;

    complete(&curr->pushdown_done);

    wait_for_completion(&curr->response_done);

    // return to memory pool
    fit_ack_reply_callback_parameterized(fit_ctx, fit_imm, node_id, fit_offset, &ack_result, sizeof(int));
}

/*
    Process all messages that come to the compute pool in TELEPORT.
*/
void teleport_handle_messages(void *fit_ctx, void *fit_imm,
        void *rx, int rx_size, int node_id, int fit_offset) {
    void *msg;
    struct common_header *hdr;
    void *payload;

    msg = rx;
    hdr = to_common_header(msg);
    payload = to_payload(msg);

    switch (hdr->opcode)
    {
    case M2P_TELEPORT_PAGE_FAULT:
    case M2P_TELEPORT_INVALIDATE:
    {
        teleport_coherence_message_handler(fit_ctx, fit_imm, hdr, payload, node_id, fit_offset);
    }
        break;
    case M2P_TELEPORT_COMPLETE:
    {
        teleport_completion_message_handler(fit_ctx, fit_imm, payload, rx_size, node_id, fit_offset);
    }
        break;
    
    default:
        panic("TELEPORT: unknown message ID\n");
        break;
    }
}
