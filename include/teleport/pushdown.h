#ifndef _TELEPORT_PUSHDOWN_H_
#define _TELEPORT_PUSHDOWN_H_

#include <lego/completion.h>
#include <lego/comp_common.h>
#include <lego/err.h>
#include <lego/hashtable.h>
#include <lego/sched.h>
#include <teleport/bloomfilter.h>

#define TELEPORT_COHERENCE_BIT_DEFAULT 1
#define TELEPORT_COHERENCE_BIT_WEAK 2

#define T_CMD_PAGE_WRPROTECT ((__u8)0x01)
#define T_CMD_PAGE_INVALIDATE ((__u8)0x02)

struct pushdown_instantiate_info {
    __u32   src_nid;
    __u32   pid;
    __u32   tgid;
    __u32   parent_tgid;
    __u64   func; // function pointer
    __u64   arg; // argument pointer
    __u32   page_count;
    __u32   resp_length; // response size
    __u8    is_coherent;
#ifdef TELEPORT_COMPRESSION
    __u32   addr_count;
    __u32   dirty_count;
    struct p2m_pushdown_pageinfo_addr_compression* pageinfo_addr_list;
    struct p2m_pushdown_pageinfo_dirty_compression* pageinfo_dirty_list;
#elif defined(TELEPORT_COMPRESSION_EMBEDDED)
    __u32   embedded_count;
    struct p2m_pushdown_pageinfo_compression* pageinfo_list;
#else
    struct p2m_pushdown_pageinfo* pageinfo_list;
#endif
    long     result;

    s64 t_context_time;
    s64 execution_start_time;
    s64 execution_end_time;
  
    int bits_to_hash;
    struct pageinfo* hash_items;
    struct hlist_head* pageinfo_table;

    void * response_buffer;
    struct teleport_response* response;

    struct accessinfo* access_list;
    spinlock_t coherence_ready_lock;

    struct task_struct *task;
    int local_pid;

    struct completion   done;
    struct list_head    list;
};

struct profiling_ret_ty {
    s64 req_recv_time;
    s64 t_context_time;
    s64 execution_start_time;
    s64 execution_end_time;
};

struct pageinfo {
     __u64 addr;
     char is_dirty;
     struct hlist_node next;
};

struct accessinfo {
     __u64 addr;
     spinlock_t update_lock;
};

struct pfault_response {
    int code;
    char pcacheline[PCACHE_LINE_SIZE];
};

struct teleport_response {
    int pid;
    long retval;
    struct profiling_ret_ty time_profile;
    struct bloomfilter page_filter;
};

struct ongoing_teleport {
    int pid;
    int tgid;
    int expected_len;
    struct completion pushdown_done;
    struct completion response_done;
    void *response;
    struct ongoing_teleport* next;
};

int pushdown(void* unused);
extern struct task_struct* pushdown_task;
extern struct pushdown_instantiate_info* teleport_instances[TELEPORT_PARALLELISM];
extern spinlock_t teleport_instantiate_update_lock;
extern int teleport_online_pagefaults;
extern int teleport_reqs;
extern spinlock_t teleport_reqs_lock;
extern struct ongoing_teleport *teleport_ongoing_list;
extern spinlock_t teleport_pagefault_lock;
extern struct accessinfo *compute_pool_access_list;

#ifdef TELEPORT_PRINTING
extern unsigned long num_compute_invalidation_send;
extern unsigned long num_compute_invalidation_retry;
extern unsigned long num_compute_invalidation_success;
#endif

void pushdown_instantiate(struct pushdown_instantiate_info *inst);

int teleport_handle_fault(struct mm_struct *mm, int pid, int tgid, unsigned long address, __u32 flags, __u32 node_id, bool write, __u8 coherence_bits, struct pushdown_instantiate_info *teleport_instance);
int teleport_handle_fault_local(struct mm_struct *mm, int pid, int tgid, unsigned long address, __u32 flags, __u32 node_id);

void teleport_handle_messages(void *fit_ctx, void *fit_imm, void *rx, int rx_size, int node_id, int fit_offset);
void init_pfault_resp(void);

// FIT functions
void fit_ack_reply_callback_parameterized(void *ctx,
	void *metadata,
	int node_id, int offset, void *reply_data, int reply_size);

// hash table
#define hash_add_with_bits(hashtable, node, key, bits)						\
	hlist_add_head(node, &hashtable[hash_min(key, bits)])

#define hash_for_each_possible_with_bits(name, obj, member, key, bits)			\
	hlist_for_each_entry(obj, &name[hash_min(key, bits)], member)

#define hash_init_with_bits(hashtable, bits) __hash_init(hashtable, 1 << bits)

#endif /* _TELEPORT_PUSHDOWN_H_ */
