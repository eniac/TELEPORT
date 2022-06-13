#include <lego/kernel.h>
#include <lego/slab.h>
#include <lego/fit_ibapi.h>
#include <lego/uaccess.h>
#include <lego/err.h>
#include <processor/processor.h>
#include <processor/pcache.h>
#include <processor/distvm.h>
#include <lego/syscalls.h>
#include <lego/time.h>

#include <asm/tlbflush.h>

#include <teleport/pushdown.h>

#define PUSHDOWN_FLAG_SYNC_ALL 0
#define PUSHDOWN_FLAG_SYNC_DIRTY 1
#define PUSHDOWN_FLAG_SYNC_LAZY 2
#define PUSHDOWN_FLAG_COHERENCE 3
#define PUSHDOWN_FLAG_BLOCKING 4
#define PUSHDOWN_FLAG_COHERENCE_WEAK 5

#ifdef CONFIG_COMP_PROCESSOR
int teleport_online_pagefaults;
int teleport_reqs;
DEFINE_SPINLOCK(teleport_reqs_lock);
struct ongoing_teleport *teleport_ongoing_list;
#endif

/*
    Sync every page preemptively.
*/
static inline int sync_every_page(void) {
    struct pcache_meta *pcm;
    int nr = 0;
    int count = 0;

    pcache_for_each_way(pcm, nr) {
        pcache_flush_one(pcm);
        count++;
    }
    return count;
}

/*
    Sync back every page.
*/
static int __sync_back_pcm(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg) {
    int *nr_sync = arg;
    unsigned long vaddr = 0;
    void* va_cache;
    int dst_nid = 0;
    int len;
    struct p2m_pcache_miss_msg msg;

    if (rmap->owner_process->pid == current->tgid) {
        vaddr = rmap->address;
        va_cache = pcache_meta_to_kva(pcm);
        dst_nid = get_memory_node(current, vaddr);

        fill_common_header(&msg, P2M_PCACHE_MISS);
        msg.has_flush_msg = 0;
        msg.pid = current->pid;
        msg.tgid = current->tgid;
        msg.flags = FAULT_FLAG_KILLABLE | FAULT_FLAG_USER;
        msg.missing_vaddr = vaddr;
        len = ibapi_send_reply_timeout(dst_nid, &msg, sizeof(msg), va_cache, PCACHE_LINE_SIZE, false, DEF_NET_TIMEOUT);
    }
    (*nr_sync)++;
    return PCACHE_RMAP_AGAIN;
}

static inline int sync_back_every_page(void) {
    struct pcache_meta *pcm;
    int nr = 0;
    int nr_sync = 0;
    struct rmap_walk_control rwc = {
        .arg = &nr_sync,
        .rmap_one = __sync_back_pcm
    };

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }

    return nr_sync;
}

/*
    Sync back every page except dirty pages.
*/
static int __sync_back_clean_pcm(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg) {
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte) && (!pte_dirty(*pte))) {
            unsigned long vaddr = 0;
            int *nr_sync = arg;
            void *va_cache;
            int dst_nid = 0;
            int len;
            struct p2m_pcache_miss_msg msg;
            vaddr = rmap->address;
            va_cache = pcache_meta_to_kva(pcm);
            dst_nid = get_memory_node(current, vaddr);

            fill_common_header(&msg, P2M_PCACHE_MISS);
            msg.has_flush_msg = 0;
            msg.pid = current->pid;
            msg.tgid = current->tgid;
            msg.flags = FAULT_FLAG_KILLABLE | FAULT_FLAG_USER;
            msg.missing_vaddr = vaddr;
            len = ibapi_send_reply_timeout(dst_nid, &msg, sizeof(msg), va_cache, PCACHE_LINE_SIZE, false, DEF_NET_TIMEOUT);
    
            (*nr_sync)++;
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline int sync_back_clean_pages(void) {
    struct pcache_meta *pcm;
    int nr = 0;
    int nr_sync = 0;
    struct rmap_walk_control rwc = {
        .arg = &nr_sync,
        .rmap_one = __sync_back_clean_pcm
    };

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }

    return nr_sync;
}

static int __flush_only_if_dirty(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    int *nr_flushed = arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            if (likely(pte_dirty(*pte))) {
                (*nr_flushed)++;
                pcache_flush_one(pcm);

                lock_pcache(pcm);
                pcache_clean(pcm);
                unlock_pcache(pcm);
            }
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline int sync_dirty_pages_only(void) {
    struct pcache_meta *pcm;
    int nr = 0;
    int nr_flushed = 0;
    struct rmap_walk_control rwc = {
        .arg = &nr_flushed,
        .rmap_one = __flush_only_if_dirty,
    };
    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }

    return nr_flushed;
}

static int __count_dirty_pages_of_current_task(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    int *page_count = arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            if (pte_dirty(*pte)) {
                (*page_count)++;
            }
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline int count_dirty_pages(void) {
    struct pcache_meta *pcm;
    int nr = 0;
    int page_count = 0;
    struct rmap_walk_control rwc = {
        .arg = &page_count,
        .rmap_one = __count_dirty_pages_of_current_task,
    };
    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }
    return page_count;
}

static int __count_pages_of_current_task(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    int *page_count = arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            (*page_count)++;
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline int count_pages(void) {
    struct pcache_meta *pcm;
    int nr = 0;
    int page_count = 0;
    struct rmap_walk_control rwc = {
        .arg = &page_count,
        .rmap_one = __count_pages_of_current_task,
    };
    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }
    return page_count;
}

struct count_compression_struct {
    int *page_count;
    int *addr_count;
    unsigned long *last_addr;
    int *dirty_count;
    char *dirty;
};

static int __count_pages_of_current_task_compression(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct count_compression_struct *page_count = arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            char cur_dirty = !!pte_dirty(*pte);
            if (rmap->address != (*(page_count->last_addr) + PAGE_SIZE)) {
                (*(page_count->addr_count))++;
            }
            if (cur_dirty != (*(page_count->dirty))) {
                (*(page_count->dirty_count))++;
            }
            (*(page_count->last_addr)) = rmap->address;
            (*(page_count->dirty)) = cur_dirty;
            (*(page_count->page_count))++;
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline int count_pages_compression(int *addr_count, int *dirty_count) {
    struct count_compression_struct count_arg;
    struct pcache_meta *pcm;
    int nr = 0;
    int page_count = 0;
    unsigned long addr = 0;
    char dirty = -1;

    struct rmap_walk_control rwc = {
        .arg = &count_arg,
        .rmap_one = __count_pages_of_current_task_compression,
    };
    
    count_arg.page_count = &page_count;
    count_arg.addr_count = addr_count;
    count_arg.last_addr = &addr;
    count_arg.dirty_count = dirty_count;
    count_arg.dirty = &dirty;

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }

    return page_count;
}

struct count_compression_embedded_struct {
    int *page_count;
    int *count;
    unsigned long *last_addr;
    char *dirty;
    int *dirty_count;
};

static int __count_pages_of_current_task_compression_embedded(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct count_compression_embedded_struct *page_count = arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            char cur_dirty = !!pte_dirty(*pte);
            if (rmap->address != (*(page_count->last_addr) + PAGE_SIZE) || (cur_dirty != (*(page_count->dirty)))) {
                (*(page_count->count))++;
            }
            (*(page_count->last_addr)) = rmap->address;
            (*(page_count->dirty)) = cur_dirty;
            (*(page_count->page_count))++;
            if (cur_dirty) {
                (*(page_count->dirty_count))++;
            }
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline int count_pages_compression_embedded(int *count, int *dirty_count) {
    struct count_compression_embedded_struct count_arg;
    struct pcache_meta *pcm;
    int nr = 0;
    int page_count = 0;
    unsigned long addr = 0;
    char dirty = -1;

    struct rmap_walk_control rwc = {
        .arg = &count_arg,
        .rmap_one = __count_pages_of_current_task_compression_embedded,
    };
    
    count_arg.page_count = &page_count;
    count_arg.count = count;
    count_arg.last_addr = &addr;
    count_arg.dirty = &dirty;
    count_arg.dirty_count = dirty_count;

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }

    return page_count;
}

struct coherent_count_compression_struct {
    int *page_count;
    int *addr_count;
    unsigned long *last_addr;
    int *write_count;
    char *write;
};

static int __count_pages_of_current_task_compression_coherent(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct coherent_count_compression_struct *page_count = arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            char cur_write = !!pte_write(*pte);
            if (rmap->address != (*(page_count->last_addr) + PAGE_SIZE)) {
                (*(page_count->addr_count))++;
            }
            if (cur_write != (*(page_count->write))) {
                (*(page_count->write_count))++;
            }
            (*(page_count->last_addr)) = rmap->address;
            (*(page_count->write)) = cur_write;
            (*(page_count->page_count))++;
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline int count_pages_compression_coherent(int *addr_count, int *write_count) {
    struct coherent_count_compression_struct count_arg;
    struct pcache_meta *pcm;
    int nr = 0;
    int page_count = 0;
    unsigned long addr = 0;
    char write = -1;

    struct rmap_walk_control rwc = {
        .arg = &count_arg,
        .rmap_one = __count_pages_of_current_task_compression_coherent,
    };
    
    count_arg.page_count = &page_count;
    count_arg.addr_count = addr_count;
    count_arg.last_addr = &addr;
    count_arg.write_count = write_count;
    count_arg.write = &write;

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }

    return page_count;
}

struct coherent_count_compression_embedded_struct {
    int *page_count;
    int *count;
    unsigned long *last_addr;
    char *write;
    int *write_count;
};

static int __count_pages_of_current_task_compression_embedded_coherent(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct coherent_count_compression_embedded_struct *page_count = arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            char cur_write = !!pte_write(*pte);
            if (rmap->address != (*(page_count->last_addr) + PAGE_SIZE) || (cur_write != (*(page_count->write)))) {
                (*(page_count->count))++;
            }
            (*(page_count->last_addr)) = rmap->address;
            (*(page_count->write)) = cur_write;
            (*(page_count->page_count))++;
            if(cur_write) {
                (*(page_count->write_count))++;
            }
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline int count_pages_compression_embedded_coherent(int *count, int *write_count) {
    struct coherent_count_compression_embedded_struct count_arg;
    struct pcache_meta *pcm;
    int nr = 0;
    int page_count = 0;
    unsigned long addr = 0;
    char write = -1;

    struct rmap_walk_control rwc = {
        .arg = &count_arg,
        .rmap_one = __count_pages_of_current_task_compression_embedded_coherent,
    };
    
    count_arg.page_count = &page_count;
    count_arg.count = count;
    count_arg.last_addr = &addr;
    count_arg.write = &write;
    count_arg.write_count = write_count;

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }

    return page_count;
}

struct pgtable_sync_arg {
    int index;
    struct p2m_page_info_kv_pair* pg_list_addr;
};

static int __insert_page_info(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct p2m_pushdown_pageinfo **one_page = (struct p2m_pushdown_pageinfo**)arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            (*one_page)->addr = rmap->address;
            (*one_page)->is_dirty = !!pte_dirty(*pte);
            (*one_page)++;
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline void load_pages(struct p2m_pushdown_pageinfo* pageinfo_list) {
    struct pcache_meta *pcm;
    int nr = 0;
    struct rmap_walk_control rwc = {
        .arg = &pageinfo_list,
        .rmap_one = __insert_page_info,
    };
    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }
}

struct insert_compression_struct {
    struct p2m_pushdown_pageinfo_addr_compression *addr_list;
    struct p2m_pushdown_pageinfo_dirty_compression *dirty_list;
};

static int __insert_page_info_compression(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct insert_compression_struct *insert_arg = (struct insert_compression_struct*)arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            char cur_dirty = !!pte_dirty(*pte);
            if (rmap->address != insert_arg->addr_list->start_addr + PAGE_SIZE * insert_arg->addr_list->count) {
                if (insert_arg->addr_list->count != 0) {
                    (insert_arg->addr_list)++;
                }
                insert_arg->addr_list->start_addr = rmap->address;
                insert_arg->addr_list->count = 1;
            } else {
                insert_arg->addr_list->count++;
            }
            if (cur_dirty != insert_arg->dirty_list->is_dirty) {
                if (insert_arg->dirty_list->count != 0) {
                    (insert_arg->dirty_list)++;
                }
                insert_arg->dirty_list->is_dirty = cur_dirty;
                insert_arg->dirty_list->count = 1;
            } else {
                insert_arg->dirty_list->count++;
            }
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline void load_pages_compression(struct p2m_pushdown_pageinfo_addr_compression *pageinfo_addr_list,
    struct p2m_pushdown_pageinfo_dirty_compression *pageinfo_dirty_list) {
    struct insert_compression_struct arg_struct;
    struct pcache_meta *pcm;
    int nr = 0;
    struct rmap_walk_control rwc = {
        .arg = &arg_struct,
        .rmap_one = __insert_page_info_compression,
    };
    arg_struct.addr_list = pageinfo_addr_list;
    arg_struct.dirty_list = pageinfo_dirty_list;

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }
}

static int __insert_page_info_compression_embedded(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct p2m_pushdown_pageinfo_compression **insert_arg = (struct p2m_pushdown_pageinfo_compression**)arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            char cur_dirty = !!pte_dirty(*pte);
            if ((rmap->address != ((*insert_arg)->start_addr_dirty_embedded & PAGE_MASK) + PAGE_SIZE * (*insert_arg)->count) || 
                (cur_dirty != ((*insert_arg)->start_addr_dirty_embedded & 0x01))) {
                if ((*insert_arg)->count != 0) {
                    (*insert_arg)++;
                }
                (*insert_arg)->start_addr_dirty_embedded = rmap->address;
                (*insert_arg)->start_addr_dirty_embedded |= (unsigned long)cur_dirty;
                (*insert_arg)->count = 1;
            } else {
                (*insert_arg)->count++;
            }
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline void load_pages_compression_embedded(struct p2m_pushdown_pageinfo_compression *pageinfo_list) {
    struct pcache_meta *pcm;
    int nr = 0;
    struct rmap_walk_control rwc = {
        .arg = &pageinfo_list,
        .rmap_one = __insert_page_info_compression_embedded,
    };

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }
}

static int __insert_page_info_coherent(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct p2m_pushdown_pageinfo **one_page = (struct p2m_pushdown_pageinfo**)arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            (*one_page)->addr = rmap->address;
            (*one_page)->is_dirty = !!pte_write(*pte);
            (*one_page)++;
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline void load_pages_coherent(struct p2m_pushdown_pageinfo* pageinfo_list) {
    struct pcache_meta *pcm;
    int nr = 0;
    struct rmap_walk_control rwc = {
        .arg = &pageinfo_list,
        .rmap_one = __insert_page_info_coherent,
    };
    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }
}

static int __insert_page_info_compression_coherent(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct insert_compression_struct *insert_arg = (struct insert_compression_struct*)arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            char cur_write = !!pte_write(*pte);
            if (rmap->address != insert_arg->addr_list->start_addr + PAGE_SIZE * insert_arg->addr_list->count) {
                if (insert_arg->addr_list->count != 0) {
                    (insert_arg->addr_list)++;
                }
                insert_arg->addr_list->start_addr = rmap->address;
                insert_arg->addr_list->count = 1;
            } else {
                insert_arg->addr_list->count++;
            }
            if (cur_write != insert_arg->dirty_list->is_dirty) {
                if (insert_arg->dirty_list->count != 0) {
                    (insert_arg->dirty_list)++;
                }
                insert_arg->dirty_list->is_dirty = cur_write;
                insert_arg->dirty_list->count = 1;
            } else {
                insert_arg->dirty_list->count++;
            }
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline void load_pages_compression_coherent(struct p2m_pushdown_pageinfo_addr_compression *pageinfo_addr_list,
    struct p2m_pushdown_pageinfo_dirty_compression *pageinfo_dirty_list) {
    struct insert_compression_struct arg_struct;
    struct pcache_meta *pcm;
    int nr = 0;
    struct rmap_walk_control rwc = {
        .arg = &arg_struct,
        .rmap_one = __insert_page_info_compression_coherent,
    };
    arg_struct.addr_list = pageinfo_addr_list;
    arg_struct.dirty_list = pageinfo_dirty_list;

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }
}

static int __insert_page_info_compression_embedded_coherent(struct pcache_meta *pcm, struct pcache_rmap *rmap, void *arg)
{
    struct p2m_pushdown_pageinfo_compression **insert_arg = (struct p2m_pushdown_pageinfo_compression**)arg;
    pte_t *pte;

    if (rmap->owner_process->pid == current->tgid) {
        pte = rmap->page_table;
        if (!pte_none(*pte) && pte_present(*pte)) {
            char cur_write = !!pte_write(*pte);
            if ((rmap->address != ((*insert_arg)->start_addr_dirty_embedded & PAGE_MASK) + PAGE_SIZE * (*insert_arg)->count) || 
                (cur_write != ((*insert_arg)->start_addr_dirty_embedded & 0x01))) {
                if ((*insert_arg)->count != 0) {
                    (*insert_arg)++;
                }
                (*insert_arg)->start_addr_dirty_embedded = rmap->address;
                (*insert_arg)->start_addr_dirty_embedded |= (unsigned long)cur_write;
                (*insert_arg)->count = 1;
            } else {
                (*insert_arg)->count++;
            }
        }
    }
    return PCACHE_RMAP_AGAIN;
}

static inline void load_pages_compression_embedded_coherent(struct p2m_pushdown_pageinfo_compression *pageinfo_list) {
    struct pcache_meta *pcm;
    int nr = 0;
    struct rmap_walk_control rwc = {
        .arg = &pageinfo_list,
        .rmap_one = __insert_page_info_compression_embedded_coherent,
    };

    pcache_for_each_way(pcm, nr) {
        rmap_walk(pcm, &rwc);
    }
}

static int compare_pages_embedded(const void *lhs, const void *rhs) {
    struct p2m_pushdown_pageinfo_compression *lhs_page = (struct p2m_pushdown_pageinfo_compression *)lhs;
    struct p2m_pushdown_pageinfo_compression *rhs_page = (struct p2m_pushdown_pageinfo_compression *)rhs;

    if ((lhs_page->start_addr_dirty_embedded & PAGE_MASK) < (rhs_page->start_addr_dirty_embedded & PAGE_MASK)) return -1;
    if ((lhs_page->start_addr_dirty_embedded & PAGE_MASK) > (rhs_page->start_addr_dirty_embedded & PAGE_MASK)) return 1;
    return 0;
}

static inline void sort_pages_embedded(struct p2m_pushdown_pageinfo_compression *list, int count) {
    sort((void*)list, count, sizeof(struct p2m_pushdown_pageinfo_compression), compare_pages_embedded, NULL);
}

static inline int count_sorted_pages_embedded(struct p2m_pushdown_pageinfo_compression *list, int count) {
    int i;
    unsigned long prev_addr = list->start_addr_dirty_embedded;
    int prev_count = list->count;
    int total_count = 1;
    
    if (count <= 1) return count;

    for (i = 1; i != count; i++) {
        if (((list[i].start_addr_dirty_embedded & PAGE_MASK) == (prev_addr & PAGE_MASK) + prev_count * PAGE_SIZE) &&
            ((list[i].start_addr_dirty_embedded & 0x01) == (prev_addr & 0x01))) {
                prev_count += list[i].count;
        } else {
            prev_addr = list[i].start_addr_dirty_embedded;
            prev_count = list[i].count;
            total_count++;
        }
    }

    return total_count;
}

static inline void load_sorted_pages_embedded(struct p2m_pushdown_pageinfo_compression *origin_list, int origin_count,
    struct p2m_pushdown_pageinfo_compression *new_list) {
    int i;
    
    if (origin_count <= 1) return;

    new_list->start_addr_dirty_embedded = origin_list->start_addr_dirty_embedded;
    new_list->count = origin_list->count;

    for (i = 1; i != origin_count; i++) {
        if (((origin_list[i].start_addr_dirty_embedded & PAGE_MASK) == (new_list->start_addr_dirty_embedded & PAGE_MASK) + new_list->count * PAGE_SIZE) &&
            ((origin_list[i].start_addr_dirty_embedded & 0x01) == (new_list->start_addr_dirty_embedded & 0x01))) {
                new_list->count += origin_list[i].count;
        } else {
            new_list++;
            new_list->start_addr_dirty_embedded = origin_list[i].start_addr_dirty_embedded;
            new_list->count = origin_list[i].count;
        }
    }
}

static inline void lazy_sync_back(struct bloomfilter *page_filter,
    struct mm_struct *mm, struct p2m_pushdown_pageinfo *pages, int num_pages) {
    int i;
    unsigned long addr;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct pcache_meta* pcm;

    for (i = 0; i != num_pages; i++) {
        addr = pages[i].addr;
        if (bloom_check(page_filter, &addr, sizeof(unsigned long)) == 1) {
            int k = 0;
            int refs = 0;

            pgd = pgd_offset(mm, addr);
            pud = pud_offset(pgd, addr);
            pmd = pmd_offset(pud, addr);
            pte = pte_offset(pmd, addr);

            pcm = pte_to_pcache_meta(*pte);

            pcache_try_to_unmap(pcm);
            __ClearPcacheReclaim(pcm);
            __ClearPcacheLocked(pcm);
            refs = pcache_ref_count(pcm);
            for (; k != refs; k++) {
                put_pcache(pcm);
            }
        }
    }
}

static inline void lazy_sync_back_compression(struct bloomfilter *page_filter,
    struct mm_struct *mm, struct p2m_pushdown_pageinfo_addr_compression *pages, int num_addr) {
    int i;
    unsigned long addr;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct pcache_meta* pcm;

    for (i = 0; i != num_addr; i++) {
        int j;
        int count = pages[i].count;
        for (j = 0; j != count; j++) {
            addr = pages[i].start_addr + j * PAGE_SIZE;
            if (bloom_check(page_filter, &addr, sizeof(unsigned long)) == 1) {
                int k = 0;
                int refs = 0;

                pgd = pgd_offset(mm, addr);
                pud = pud_offset(pgd, addr);
                pmd = pmd_offset(pud, addr);
                pte = pte_offset(pmd, addr);

                pcm = pte_to_pcache_meta(*pte);

                pcache_try_to_unmap(pcm);
                __ClearPcacheReclaim(pcm);
                __ClearPcacheLocked(pcm);
                refs = pcache_ref_count(pcm);
                for (; k != refs; k++) {
                    put_pcache(pcm);
                }
            }
        }
    }
}

static inline void lazy_sync_back_compression_embedded(struct bloomfilter *page_filter,
    struct mm_struct *mm, struct p2m_pushdown_pageinfo_compression *pages, int num_embedded) {
    int i;
    unsigned long addr;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct pcache_meta* pcm;

    for (i = 0; i != num_embedded; i++) {
        int j;
        int count = pages[i].count;
        for (j = 0; j != count; j++) {
            addr = (pages[i].start_addr_dirty_embedded & PAGE_MASK) + j * PAGE_SIZE;
            if (bloom_check(page_filter, &addr, sizeof(unsigned long)) == 1) {
                int k = 0;
                int refs = 0;

                pgd = pgd_offset(mm, addr);
                pud = pud_offset(pgd, addr);
                pmd = pmd_offset(pud, addr);
                pte = pte_offset(pmd, addr);

                pcm = pte_to_pcache_meta(*pte);

                pcache_try_to_unmap(pcm);
                __ClearPcacheReclaim(pcm);
                __ClearPcacheLocked(pcm);
                refs = pcache_ref_count(pcm);
                for (; k != refs; k++) {
                    put_pcache(pcm);
                }
            }
        }
    }
}

struct profiling_times {
    s64 call_start_time; /* when the syscall is called (compute) */
    s64 sync_finish_time; /* when data sync is finished (compute) */
    s64 payload_finish_time; /* memory allocation (compute) */
    s64 req_recv_time; /* when the request is received (memory) */
    s64 t_context_time; /* when t_context() is called (memory) */
    s64 execution_start_time; /* when the pushdown function starts (memory) */
    s64 execution_end_time; /* when the pushdown function ends (memory) */
    s64 resp_recv_time; /* when the response is received (compute) */
    s64 call_end_time; /* when the syscall returns (compute) */
};

static inline void print_times(struct profiling_times *times) {
    printk("[TELEPORT TIME PROFILING]: \n \
            -> (C) call_start_time: %lld\n \
            -> (C) sync_finish_time: %lld (+%lld)\n \
            -> (C) payload_finish_time: %lld (+%lld)\n \
            -> (M) req_recv_time: %lld (+%lld)\n \
            -> (M) t_context_time: %lld (+%lld)\n \
            -> (M) execution_start_time: %lld (+%lld)\n \
            -> (M) execution_end_time: %lld (+%lld)\n \
            -> (C) resp_recv_time: %lld (+%lld)\n \
            -> (C) call_end_time: %lld (+%lld)\n", 
            times->call_start_time,
            times->sync_finish_time, times->sync_finish_time - times->call_start_time,
            times->payload_finish_time, times->payload_finish_time - times->sync_finish_time,
            times->req_recv_time, times->req_recv_time - times->payload_finish_time,
            times->t_context_time, times->t_context_time - times->req_recv_time,
            times->execution_start_time, times->execution_start_time - times->t_context_time,
            times->execution_end_time, times->execution_end_time - times->execution_start_time,
            times->resp_recv_time, times->resp_recv_time - times->execution_end_time,
            times->call_end_time, times->call_end_time - times->resp_recv_time);
}

static inline void print_data(int num_pre_pages,
    int num_online_pages_m2c,
    int num_online_pages_c2m,
    int num_post_pages,
    int num_pages,
    __u32 len_msg,
    __u32 len_retbuf,
    int filter_bytes) {
    printk("[TELEPORT DATA PROFILING]: \n \
            -> #pages in pre-pushdown sync: %d\n \
            -> #pages in online sync (M2C): %d\n \
            -> #pages in online sync (C2M): %d\n \
            -> #pages in post-pushdown sync: %d\n \
            -> #pages loaded in request: %d\n \
            -> #bytes in pushdown request: %u\n \
            -> #bytes in pushdown response: %u\n \
            -> #bytes in bloom filter: %d\n",
            num_pre_pages,
            num_online_pages_m2c,
            num_online_pages_c2m,
            num_post_pages,
            num_pages,
            len_msg,
            len_retbuf,
            filter_bytes);
}

static inline void print_data_compression(int num_pre_pages,
    int num_online_pages_m2c,
    int num_online_pages_c2m,
    int num_post_pages,
    int num_pages,
    int num_addr,
    int num_dirty,
    __u32 len_msg,
    __u32 len_retbuf,
    int filter_bytes) {
    printk("[TELEPORT DATA PROFILING]: \n \
            -> #pages in pre-pushdown sync: %d\n \
            -> #pages in online sync (M2C): %d\n \
            -> #pages in online sync (C2M): %d\n \
            -> #pages in post-pushdown sync: %d\n \
            -> #pages loaded in request: (%d + %d) / %d\n \
            -> #bytes in pushdown request: %u\n \
            -> #bytes in pushdown response: %u\n \
            -> #bytes in bloom filter: %d\n",
            num_pre_pages,
            num_online_pages_m2c,
            num_online_pages_c2m,
            num_post_pages,
            num_addr,
            num_dirty,
            num_pages,
            len_msg,
            len_retbuf,
            filter_bytes);
}

asmlinkage long sys_pushdown(const char __user *func, const char __user *arg, int flags) {
#ifdef CONFIG_COMP_PROCESSOR
    ssize_t retlen;
    __u32 len_retbuf, len_msg;
    int response_code;
    void *retbuf, *msg;
    struct teleport_response *resp;
    struct common_header *hdr;
    struct p2m_pushdown_payload *payload;
#ifdef TELEPORT_COMPRESSION
    struct p2m_pushdown_pageinfo_addr_compression *pageinfo_addr_list;
    struct p2m_pushdown_pageinfo_dirty_compression *pageinfo_dirty_list;

    int num_addr, num_dirty;
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
    struct p2m_pushdown_pageinfo_compression *pageinfo_list_original;
    struct p2m_pushdown_pageinfo_compression *pageinfo_list;

    int num_embedded_original, num_embedded;
#else
    struct p2m_pushdown_pageinfo *pageinfo_list;
#endif
    int num_pages;
    int num_total_pages_profile, num_dirty_pages_profile, num_sync_pages_profile;
    int mem_node;
    bool is_active_sync_all, is_active_sync_dirty, is_lazy_sync;
#ifdef TELEPORT_PRINTING
    // profiling_timespec is reused for populating time_records
    struct profiling_times time_records;
    struct timeval cur_time;
#endif
    struct bloomfilter tmp_filter;
    long syscall_ret = -1;

    int is_coherent = 0;
    int num_pages_removed_pre = 0;

    bool is_blocking = false;
    struct ongoing_teleport *me;
    bool do_i_sync = true;

#ifdef TELEPORT_PRINTING
    // call start time
    do_gettimeofday(&cur_time);
    time_records.call_start_time = timeval_to_ns(&cur_time);
#endif

    teleport_online_pagefaults = 0;

    is_active_sync_all = (1UL << PUSHDOWN_FLAG_SYNC_ALL ) & flags;
    is_active_sync_dirty = (1UL << PUSHDOWN_FLAG_SYNC_DIRTY) & flags;
    is_lazy_sync = (1UL << PUSHDOWN_FLAG_SYNC_LAZY ) & flags;
    is_coherent = (1UL << PUSHDOWN_FLAG_COHERENCE) & flags;
    is_blocking = (1UL << PUSHDOWN_FLAG_BLOCKING) & flags;

    is_active_sync_all = !!is_active_sync_all;
    is_active_sync_dirty = !!is_active_sync_dirty;
    is_lazy_sync = !!is_lazy_sync;
    is_coherent = !!is_coherent;
    if (is_coherent && ((1UL << PUSHDOWN_FLAG_COHERENCE_WEAK) & flags)) {
        is_coherent |= (1 << TELEPORT_COHERENCE_BIT_WEAK);
    }
    is_blocking = !!is_blocking;

#ifdef TELEPORT_COMPRESSION
    num_addr = 0;
    num_dirty = 0;
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
    num_embedded_original = num_embedded = 0;
#endif
    num_pages = 0;
    
    num_total_pages_profile = 0;
    num_dirty_pages_profile = 0;
    if (is_lazy_sync) {
#ifdef TELEPORT_COMPRESSION
        if (is_coherent) {
            num_pages = count_pages_compression_coherent(&num_addr, &num_dirty);
        } else {
            num_pages = count_pages_compression(&num_addr, &num_dirty);
        }
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
		if (is_coherent) {
        	num_pages = count_pages_compression_embedded_coherent(&num_embedded_original, &num_pages_removed_pre);
		} else {
        	num_pages = count_pages_compression_embedded(&num_embedded_original, &num_pages_removed_pre);
		}
        num_embedded = num_embedded_original;
#ifdef TELEPORT_PRINTING
        printk("TELEPORT: coherent=%d, dirty_count=%d\n", is_coherent, num_pages_removed_pre);
#endif
#else
        num_pages = count_pages();
#endif  
    } else if (is_active_sync_dirty) {
        spin_lock(&teleport_reqs_lock);
        num_dirty_pages_profile = sync_dirty_pages_only();
        spin_unlock(&teleport_reqs_lock);
    } else if (is_active_sync_all) {
        spin_lock(&teleport_reqs_lock);
        num_total_pages_profile = sync_every_page();
        spin_unlock(&teleport_reqs_lock);
    }

#ifdef TELEPORT_PRINTING
    // sync finish time
    do_gettimeofday(&cur_time);
    time_records.sync_finish_time = timeval_to_ns(&cur_time);
#endif

#ifdef TELEPORT_COMPRESSION
    len_msg = sizeof(struct common_header) + sizeof(struct p2m_pushdown_payload)
                    + sizeof(struct p2m_pushdown_pageinfo_addr_compression)*num_addr
                    + sizeof(struct p2m_pushdown_pageinfo_dirty_compression)*num_dirty;
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
    pageinfo_list_original = NULL;
    len_msg = sizeof(struct common_header) + sizeof(struct p2m_pushdown_payload)
                    + sizeof(struct p2m_pushdown_pageinfo_compression)*num_embedded;
    if (len_msg > 2097152) { // IMM_MAX_SIZE, 2MB
        int num_embedded_final = 0;
        pageinfo_list_original =
            (struct p2m_pushdown_pageinfo_compression*)kzalloc(sizeof(struct p2m_pushdown_pageinfo_compression)*num_embedded, GFP_KERNEL);
        if (!pageinfo_list_original) {
            return -ENOMEM;
        }
		pageinfo_list_original->start_addr_dirty_embedded = 0;
		pageinfo_list_original->count = 0;

		if (is_coherent) {
			load_pages_compression_embedded_coherent(pageinfo_list_original);
		} else {
        	load_pages_compression_embedded(pageinfo_list_original);
		}
        sort_pages_embedded(pageinfo_list_original, num_embedded);
        num_embedded_final = count_sorted_pages_embedded(pageinfo_list_original, num_embedded);

        num_embedded = num_embedded_final;
        len_msg = sizeof(struct common_header) + sizeof(struct p2m_pushdown_payload)
                        + sizeof(struct p2m_pushdown_pageinfo_compression)*num_embedded;
    }
#else
    len_msg = sizeof(struct common_header) + sizeof(struct p2m_pushdown_payload)
                    + sizeof(struct p2m_pushdown_pageinfo)*num_pages;
#endif
    msg = kzalloc(len_msg, GFP_KERNEL); // doesn't work for large memory
    if (!msg) {
        // msg for pushdown request is NULL
        return -ENOMEM;
    }

    hdr = msg;
    hdr->opcode = P2M_PUSHDOWN;
    hdr->src_nid = LEGO_LOCAL_NID;

    payload = msg + sizeof(*hdr);
    
    // copy strings and fill payload
    payload->pid = current->pid;
    payload->tgid = current->tgid;
    payload->parent_tgid = current->real_parent->tgid;
    payload->func = (__u64)func;
    payload->arg = (__u64)arg;
    
    payload->page_count = num_pages;
	payload->is_coherent = is_coherent;
#ifdef TELEPORT_COMPRESSION
    payload->addr_count = num_addr;
    payload->dirty_count = num_dirty;

    if (is_lazy_sync) {
        pageinfo_addr_list = msg + sizeof(struct common_header)
                        + sizeof(struct p2m_pushdown_payload);
        pageinfo_dirty_list = msg + sizeof(struct common_header)
                        + sizeof(struct p2m_pushdown_payload)
                        + sizeof(struct p2m_pushdown_pageinfo_addr_compression) * num_addr;
        pageinfo_addr_list->start_addr = 0;
        pageinfo_addr_list->count = 0;
        pageinfo_dirty_list->is_dirty = -1;
        pageinfo_dirty_list->count = 0;
        // load page info to the list
        if (is_coherent) {
            load_pages_compression_coherent(pageinfo_addr_list, pageinfo_dirty_list);
        } else {
        	load_pages_compression(pageinfo_addr_list, pageinfo_dirty_list);
		}
    }
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
    payload->embedded_count = num_embedded;

    if (is_lazy_sync) {
        pageinfo_list = msg + sizeof(struct common_header)
                            + sizeof(struct p2m_pushdown_payload);
        pageinfo_list->start_addr_dirty_embedded = 0;
        pageinfo_list->count = 0;

        if (pageinfo_list_original) {
            load_sorted_pages_embedded(pageinfo_list_original, num_embedded_original, pageinfo_list);
            kfree(pageinfo_list_original);
        } else {
			if (is_coherent) {
            	load_pages_compression_embedded_coherent(pageinfo_list);
			} else {
            	load_pages_compression_embedded(pageinfo_list);
			}
        }
    }
#else
    if (is_lazy_sync) {
        pageinfo_list = msg + sizeof(struct common_header) + sizeof(struct p2m_pushdown_payload);
        // load page info to the list
        if (is_coherent) {
            load_pages_coherent(pageinfo_list);
        } else {
            load_pages(pageinfo_list);
        }
    }
#endif

    len_retbuf = sizeof(struct teleport_response);
    if (is_lazy_sync && !is_coherent) {
        bloom_init(&tmp_filter, num_pages, NULL);
        len_retbuf += tmp_filter.bytes;
    }

    me = (struct ongoing_teleport *)kmalloc(sizeof(struct ongoing_teleport), GFP_KERNEL);
    me->pid = current->pid;
    me->tgid = current->tgid;
    me->expected_len = len_retbuf;
    init_completion(&me->pushdown_done);
    init_completion(&me->response_done);
    me->next = NULL;
    spin_lock(&teleport_reqs_lock);
    teleport_reqs++;
    if (teleport_ongoing_list == NULL) {
        teleport_ongoing_list = me;
    } else {
        struct ongoing_teleport *curr = teleport_ongoing_list;
        while(curr->next != NULL) {
            curr = curr->next;
        }
        curr->next = me;
    }
    spin_unlock(&teleport_reqs_lock);

    mem_node = current_pgcache_home_node();
    
#ifdef TELEPORT_PRINTING
    // payload construction finish time
    do_gettimeofday(&cur_time);
    time_records.payload_finish_time = timeval_to_ns(&cur_time);
#endif

    // set return buffer size
    payload->resp_length = len_retbuf;

    // send the request
    retlen = ibapi_send_reply_imm(mem_node, msg, len_msg,
            &response_code, sizeof(int), false);

    if (unlikely(retlen != sizeof(int))) {
        panic("TELEPORT: response code failure\n");
    }

    if (unlikely(response_code == -1)) {
        // pushdown request failed to execute
        goto out;
    }
    
    wait_for_completion(&me->pushdown_done);

    retbuf = me->response;

    resp = (struct teleport_response *)retbuf;
    resp->page_filter.bf = retbuf + sizeof(*resp);

#ifdef TELEPORT_PRINTING
    do_gettimeofday(&cur_time);
    time_records.resp_recv_time = timeval_to_ns(&cur_time);

    // resp recv time time
    time_records.req_recv_time = resp->time_profile.req_recv_time;
    time_records.t_context_time = resp->time_profile.t_context_time;
    time_records.execution_start_time = resp->time_profile.execution_start_time;
    time_records.execution_end_time = resp->time_profile.execution_end_time;
#endif

    spin_lock(&teleport_reqs_lock);
    teleport_reqs--;

    if (teleport_ongoing_list == me) {
        teleport_ongoing_list = me->next;
    } else {
        struct ongoing_teleport *prev, *curr;
        prev = teleport_ongoing_list;
        curr = teleport_ongoing_list->next;
        while (curr != me) {
            prev = curr;
            curr = curr->next;
        }
        prev->next = curr->next;
    }

    if (teleport_ongoing_list != NULL) {
        do_i_sync = false;
    }

    if (do_i_sync) {
        if (is_active_sync_all) {
            num_sync_pages_profile = sync_back_every_page();
        } else if (is_active_sync_dirty) {
            num_sync_pages_profile = sync_back_clean_pages();
        } else if (is_lazy_sync && !is_coherent) { // no need for post-pushdown sync with coherence
    #ifdef TELEPORT_COMPRESSION
            lazy_sync_back_compression(&(resp->page_filter), current->mm, pageinfo_addr_list, num_addr);
    #elif defined(TELEPORT_COMPRESSION_EMBEDDED)
            lazy_sync_back_compression_embedded(&(resp->page_filter), current->mm, pageinfo_list, num_embedded);
    #else
            lazy_sync_back(&(resp->page_filter), current->mm, pageinfo_list, num_pages);
    #endif
        }
    }

    spin_unlock(&teleport_reqs_lock);

#ifdef TELEPORT_PRINTING
    // call end time
    do_gettimeofday(&cur_time);
    time_records.call_end_time = timeval_to_ns(&cur_time);
#endif

#ifdef TELEPORT_PRINTING
    print_times(&time_records);
#ifdef TELEPORT_COMPRESSION
    print_data_compression(is_active_sync_all ? num_total_pages_profile : (is_active_sync_dirty ? num_dirty_pages_profile : 0), teleport_online_pagefaults, num_compute_invalidation_send, (is_active_sync_all || is_active_sync_dirty) ? num_sync_pages_profile : 0, num_pages, num_addr, num_dirty, len_msg, len_retbuf, resp->page_filter.bytes);
#else
    print_data(is_active_sync_all ? num_total_pages_profile : (is_active_sync_dirty ? num_dirty_pages_profile : 0), teleport_online_pagefaults, num_compute_invalidation_send, (is_active_sync_all || is_active_sync_dirty) ? num_sync_pages_profile : 0, num_pages, len_msg, len_retbuf, resp->page_filter.bytes);
#endif
#endif

    // complete the use of the response buffer
    complete(&me->response_done);

    kfree(me);

    if (is_blocking) {
        struct ongoing_teleport *curr;
        bool blocking = true;
        while (blocking) {
            spin_lock(&teleport_reqs_lock);
            for (curr = teleport_ongoing_list; curr != NULL; curr = curr->next) {
                if (curr == NULL || (curr->tgid == current->tgid)) {
                    break;
                }
            }
            spin_unlock(&teleport_reqs_lock);
            blocking = (curr != NULL);
        }
    }
    syscall_ret = resp->retval;
out:

    kfree(msg);
    return syscall_ret;
#else
    return -1;
#endif
}
