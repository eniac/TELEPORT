#include <lego/kernel.h>
#include <lego/slab.h>
#include <lego/fit_ibapi.h>
#include <lego/uaccess.h>
#include <lego/err.h>
#include <processor/processor.h>
#include <processor/pcache.h>
#include <processor/distvm.h>
#include <lego/syscalls.h>

#ifdef CONFIG_COMP_PROCESSOR
#define SYNC_FLAG_C2M 1
#define SYNC_FLAG_M2C 2

static inline void fetch_pte_range(pmd_t* pmd, unsigned long addr, unsigned long end) {
    pte_t *pte;
    unsigned long flags = FAULT_FLAG_KILLABLE | FAULT_FLAG_USER;

    struct pcache_meta* pcm;
    struct p2m_pcache_miss_msg msg;
    void *va_cache;
    int len, dst_nid;

    pte = pte_offset(pmd, addr);
    // pr_debug("Fetching to local (pte): %#Lx\n", addr);
    do {
        if(pte_none(*pte) || !(pte_present(*pte))) {
            // pr_debug("Fetch new: %#Lx\n", addr);
            // This page is not currently present. Fetch it from remote node and update page table.
            /*
            fault = pcache_handle_fault(current->mm, addr, flags);
            if (fault) {
                pr_debug("fetch_pte_range(): error happened when fetching: %#Lx\n", addr);
            }
            */
            continue;
        } else {
            // No need to update the page table.
            // pr_debug("Update old: %#Lx\n", addr);
            pcm = pte_to_pcache_meta(*pte);
            va_cache = pcache_meta_to_kva(pcm);

            dst_nid = get_memory_node(current, addr);

            fill_common_header(&msg, P2M_PCACHE_MISS);
            msg.has_flush_msg = 0;
            msg.pid = current->pid;
            msg.tgid = current->tgid;
            msg.flags = flags;
            msg.missing_vaddr = addr;
            len = ibapi_send_reply_timeout(dst_nid, &msg, sizeof(msg),
                va_cache, PCACHE_LINE_SIZE, false,
                DEF_NET_TIMEOUT);
            /*
            if (unlikely(len != (int)PCACHE_LINE_SIZE)) {
                pr_debug("fetch_pte_range(): error happened when updating: %#Lx\n", addr);
            }
            */
        }
    } while(pte++, addr += PAGE_SIZE, addr != end);
}

static inline void fetch_pmd_range(pud_t* pud, unsigned long addr, unsigned long end) {
    pmd_t *pmd;
    unsigned long next;

    pmd = pmd_offset(pud, addr);
    // pr_debug("Fetching to local (pmd): %#Lx\n", addr);
    do {
        next = pmd_addr_end(addr, end);
        // pr_debug("PMD: curr: %#Lx, end: %#Lx, next: %#Lx\n", addr, end, next);
        if (pmd_none_or_clear_bad(pmd))
            continue;
        fetch_pte_range(pmd, addr, next);
    } while(pmd++, addr = next, addr != end);
}

static inline void fetch_pud_range(pgd_t* pgd, unsigned long addr, unsigned long end) {
    pud_t *pud;
    unsigned long next;

    pud = pud_offset(pgd, addr);
    do {
        next = pud_addr_end(addr, end);
        if (pud_none_or_clear_bad(pud)) {
            continue;
	}
        fetch_pmd_range(pud, addr, next);
    } while(pud++, addr = next, addr != end);
}

static inline int fetch_pte_part(pgd_t* pgd, unsigned long addr, unsigned offset_head, unsigned offset_tail) {
    pud_t* pud;
    pmd_t* pmd;
    pte_t* pte;
    unsigned size;
    int len, dst_nid;
    void* va_cache;
    struct p2m_syncmem_m2p_msg msg;
    struct pcache_meta* pcm;
    unsigned long flags = FAULT_FLAG_KILLABLE | FAULT_FLAG_USER;

    pud = pud_offset(pgd, addr);
    if (pud_none_or_clear_bad(pud)) {
	    return -11;
    }
    pmd = pmd_offset(pud, addr);
    if (pmd_none_or_clear_bad(pmd)) return -6;
    pte = pte_offset(pmd, addr);
    if(pte_none(*pte) || !(pte_present(*pte))) return -1;

    size = PAGE_SIZE - offset_head - offset_tail;
    pcm = pte_to_pcache_meta(*pte);
    va_cache = pcache_meta_to_kva(pcm);
    dst_nid = get_memory_node(current, addr);

    fill_common_header(&msg, P2M_SYNCMEM);
    msg.pid = current->pid;
    msg.tgid = current->tgid;
    msg.flags = flags;
    msg.missing_vaddr = addr;
    msg.offset_head = offset_head;
    msg.size = size;
    
    dst_nid = get_memory_node(current, addr);
    len = ibapi_send_reply_timeout(dst_nid, &msg, sizeof(msg),
        (va_cache + offset_head), size, false,
        DEF_NET_TIMEOUT);

    // if (unlikely(len != size)) {
    //    pr_debug("fetch_pte_part(): error happened when updating: %#Lx\n", addr);
    // }
    return 0;
}

static void fetch_to_local(const char __user *addr, size_t sz) {
    unsigned long curr = (unsigned long)addr;
    unsigned long end = (unsigned long)addr + sz;
    unsigned long curr_pg, end_pg, next_pg;
    pgd_t* pgd;

    // align the address to page
    curr_pg = curr & PAGE_MASK;
    end_pg = end & PAGE_MASK;
    pgd = pgd_offset(current->mm, curr_pg);

    if (curr_pg == end_pg) {
        fetch_pte_part(pgd, curr_pg, (unsigned)(curr - curr_pg), (unsigned)(curr_pg + PAGE_SIZE - end));
	    return;
    } else {
        // fetch part page first
        fetch_pte_part(pgd, curr_pg, (unsigned)(curr - curr_pg), 0);
        curr_pg += PAGE_SIZE;
    }
    
    while (curr_pg != end_pg) {
        next_pg = pgd_addr_end(curr_pg, end_pg);
        if (!pgd_none_or_clear_bad(pgd)) // page fault to get the page
            fetch_pud_range(pgd, curr_pg, next_pg);
        curr_pg = next_pg;
        if (curr_pg == end_pg)
            break;
        pgd++;
    }

    if (end != end_pg){
        fetch_pte_part(pgd, end_pg, 0, (unsigned)(end_pg + PAGE_SIZE - end));
    }
}

static inline void flush_pte_range(pmd_t* pmd, unsigned long addr, unsigned long end) {
    pte_t *pte;
    struct pcache_meta* pcm;
    bool dirty;

    pte = pte_offset(pmd, addr);
    do {
        if(pte_none(*pte)) continue;
        if(!pte_present(*pte)) continue;

        // pr_debug("flushing pte with addr %#Lx\n", addr);
        pcm = pte_to_pcache_meta(*pte);
        // dirty = pcache_try_to_unmap_reserve_check_dirty(pcm);
        dirty = pte_dirty(*pte);
        if (likely(dirty)) {
            pcache_flush_one(pcm);
        }
        // pcache_free_reserved_rmap(pcm);
    } while(pte++, addr += PAGE_SIZE, addr != end);
}

static inline void flush_pmd_range(pud_t* pud, unsigned long addr, unsigned long end) {
    pmd_t *pmd;
    unsigned long next;

    pmd = pmd_offset(pud, addr);
    do {
        next = pmd_addr_end(addr, end);
        // pr_debug("PMD: curr: %#Lx, end: %#Lx, next: %#Lx\n", addr, end, next);
        if (pmd_none_or_clear_bad(pmd))
            continue;
        flush_pte_range(pmd, addr, next);
    } while(pmd++, addr = next, addr != end);
}

static inline void flush_pud_range(pgd_t* pgd, unsigned long addr, unsigned long end) {
    pud_t *pud;
    unsigned long next;

    pud = pud_offset(pgd, addr);
    do {
        next = pud_addr_end(addr, end);
        if (pud_none_or_clear_bad(pud)) {
    	    continue;
    	}
        flush_pmd_range(pud, addr, next);
    } while(pud++, addr = next, addr != end);
}

static void flush_to_remote(const char __user *addr, size_t sz) {
    unsigned long curr = (unsigned long)addr;
    unsigned long end = (unsigned long)addr + sz;
    unsigned long next;
    pgd_t* pgd;

    curr = curr & PAGE_MASK;
    if (end != (end & PAGE_MASK)) { // leftover
        end = end + PAGE_SIZE;
    }
    end = end & PAGE_MASK;
    pgd = pgd_offset(current->mm, curr);
    do {
        next = pgd_addr_end(curr, end);
        if (pgd_none_or_clear_bad(pgd))
            continue;
        flush_pud_range(pgd, curr, next);
    } while (pgd++, curr = next, curr != end);
}
#endif

asmlinkage long sys_syncmem(const char __user *addr, size_t sz, int flags) {
#ifdef CONFIG_COMP_PROCESSOR
    if (((0x1 << SYNC_FLAG_C2M) & flags) && ((0x1 << SYNC_FLAG_M2C) & flags)) {
        // only one direction is allowed
        return -1;
    }
    else if ((0x1 << SYNC_FLAG_C2M) & flags) {
        flush_to_remote(addr, sz);
    }
    else if ((0x1 << SYNC_FLAG_M2C) & flags) {
        fetch_to_local(addr, sz);
    }
    else {
        // one direction must be specified
        return -1;
    }
    return 0;
#else
    return -1;
#endif
}
