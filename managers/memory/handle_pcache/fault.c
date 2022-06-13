/*
 * Copyright (c) 2016-2018 Wuklab, Purdue University. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * This file describes routines for handling
 *	pcache line fetch.
 */

#include <lego/profile.h>
#include <lego/fit_ibapi.h>
#include <lego/ratelimit.h>
#include <lego/checksum.h>
#include <lego/profile.h>
#include <lego/comp_memory.h>
#include <lego/comp_storage.h>
#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/thread_pool.h>
#include <memory/teleport_syncmem.h>
#include <processor/pcache.h>

#include <teleport/teleport_config.h>
#include <teleport/pushdown.h>

#include <asm/tlbflush.h>

#include "internal.h"

#ifdef CONFIG_DEBUG_HANDLE_PCACHE_FILL
static DEFINE_RATELIMIT_STATE(handle_pcache_debug_rs,
	DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);

#define handle_pcache_debug(fmt, ...)					\
({									\
	if (__ratelimit(&handle_pcache_debug_rs))			\
		pr_debug("%s() cpu%2d " fmt "\n",			\
			__func__, smp_processor_id(), __VA_ARGS__);	\
})
#else
static inline void handle_pcache_debug(const char *fmt, ...) { }
#endif

#ifdef CONFIG_DEBUG_HANDLE_ZEROFILL
#define handle_zerofill_debug(fmt, ...)				\
	pr_debug("%s() cpu%2d " fmt "\n",			\
		__func__, smp_processor_id(), __VA_ARGS__)
#else
static inline void handle_zerofill_debug(const char *fmt, ...) { }
#endif

/*
 * Processor manager rely on the length of replied
 * message to know if us succeed or failed.
 */
static void pcache_miss_error(u32 retval, struct lego_task_struct *p,
			      u64 vaddr, struct thpool_buffer *tb)
{
	int *reply = thpool_buffer_tx(tb);

	*reply = retval;
	tb_set_tx_size(tb, sizeof(*reply));

	dump_lego_tasks();
	if (p) {
		pr_info("src_nid:%u,pid:%u,vaddr:%#Lx\n", p->node, p->pid, vaddr);
		dump_all_vmas_simple(p->mm);
	}
	WARN_ON_ONCE(1);
}

/*
 * A common shared routine to handle all pcache misses
 * - normal pcache miss
 * - zerofill request
 *
 * Both of them are valid page fault in traditional concept.
 * We need to establish mapping (e.g. page table) here in memory component.
 */
DEFINE_PROFILE_POINT(pcache_miss_find_vma)

int common_handle_p2m_miss(struct lego_task_struct *p,
				  u64 vaddr, u32 flags, unsigned long *new_page)
{
	struct vm_area_struct *vma;
	struct lego_mm_struct *mm = p->mm;
	int ret;
	PROFILE_POINT_TIME(pcache_miss_find_vma)

	down_read(&mm->mmap_sem);

	PROFILE_START(pcache_miss_find_vma);
	vma = find_vma(mm, vaddr);
	PROFILE_LEAVE(pcache_miss_find_vma);

	if (unlikely(!vma)) {
		pr_info("fail to find vma\n");
		ret = VM_FAULT_SIGSEGV;
		goto unlock;
	}

	/* VMAs except stack */
	if (likely(vma->vm_start <= vaddr))
		goto good_area;

	/* stack? */
	if (unlikely(!(vma->vm_flags & VM_GROWSDOWN))) {
		// pr_info("not a stack\n");
		ret = VM_FAULT_SIGSEGV;
		goto unlock;
	}

	if (unlikely(expand_stack(vma, vaddr))) {
		pr_info("fail to expand stack\n");
		ret = VM_FAULT_SIGSEGV;
		goto unlock;
	}

	/*
	 * Okay, now we have a good vma, which means this is a valid
	 * missing address. Now, calling back to underlying handler
	 * to establish mapping. The underlying hook can have its
	 * own choice of mapping: pgtable, segment etc.
	 */
good_area:
	ret = handle_lego_mm_fault(vma, vaddr, flags, new_page, NULL);
unlock:
	up_read(&mm->mmap_sem);
	return ret;
}

static void do_handle_p2m_zerofill_miss(struct lego_task_struct *p,
					u64 vaddr, u32 flags,
					struct thpool_buffer *tb)
{
	int *reply = thpool_buffer_tx(tb);
	int ret;

	ret = common_handle_p2m_miss(p, vaddr, flags, NULL);
	if (unlikely(ret & VM_FAULT_ERROR))
		*reply = -EFAULT;
	else
		*reply = 0;
	tb_set_tx_size(tb, sizeof(int));
}

static void do_handle_p2m_pcache_miss(struct lego_task_struct *p,
				      u64 vaddr, u32 flags,
				      struct thpool_buffer *tb, u8 teleport_cmd)
{
	int ret;
	unsigned long new_page;

	ret = common_handle_p2m_miss(p, vaddr, flags, &new_page);
	if (unlikely(ret & VM_FAULT_ERROR)) {
		if (ret & VM_FAULT_OOM)
			ret = RET_ENOMEM;
		else if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			ret = RET_ESIGSEGV;

		pcache_miss_error(ret, p, vaddr, tb);
		return;
	}

   if (teleport_cmd) {
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
		unsigned long addr;
		int i;

		addr = vaddr & PAGE_MASK;

		for (i = 0; i != TELEPORT_PARALLELISM; i++) {
			struct accessinfo *recent_access;
			struct pushdown_instantiate_info *teleport_instance = teleport_instances[i];
			if (!teleport_instance || (teleport_instance->tgid != p->pid) || !teleport_instance->is_coherent) {
				continue;
			}

			// rewrite the command based on the coherence protocol type
			if (teleport_instance->is_coherent & (1 << TELEPORT_COHERENCE_BIT_WEAK)) {
				teleport_cmd = T_CMD_PAGE_WRPROTECT;
			}

			// check the availability of the coherence protocol for this instance
			while (spin_is_locked(&teleport_instance->coherence_ready_lock)){}

			// check if the address if recently accessed
			recent_access = &teleport_instance->access_list[hash_min(addr, 64) % TELEPORT_ACCESS_TABLE_LENGTH];
			if (recent_access->addr == addr) {
				spin_lock(&recent_access->update_lock);
				recent_access->addr = 42;
				spin_unlock(&recent_access->update_lock);
			}

			lego_mm = p->mm;
			mm = teleport_instance->task->mm;

			lego_pgd = lego_pgd_offset(lego_mm, vaddr);	
			lego_pud = lego_pud_offset(lego_pgd, vaddr);
			lego_pmd = lego_pmd_offset(lego_pud, vaddr);
			lego_pte = lego_pte_offset(lego_pmd, vaddr);

			lego_ptl = lego_pte_lockptr(lego_mm, lego_pmd);
			spin_lock(lego_ptl);

			pgd = pgd_offset(mm, vaddr);
			pud = pud_offset(pgd, vaddr);
			if (unlikely(pud_none(*pud))) {
				goto unlock_protect;
			}
			pmd = pmd_offset(pud, vaddr);
			if (unlikely(pmd_none(*pmd))) {
				goto unlock_protect;
			}
			pte = pte_offset(pmd, vaddr);
			if (pte_none(*pte)) {
				goto unlock_protect;
			}

			switch (teleport_cmd)
			{
			// execute the TELEPORT operation
			case T_CMD_PAGE_WRPROTECT:
			{
				if (pte_present(*pte) && pte_write(*pte)) {
					pte_t entry;
					ptl = pte_lockptr(mm, pmd);
					if (ptl != lego_ptl) {
						spin_lock(ptl);
					}

					entry = ptep_get_and_clear(0, pte);
					entry = pte_wrprotect(entry);
					entry = pte_mkclean(entry);
					pte_set(pte, entry);

					flush_tlb_mm_range(mm, addr, addr + PAGE_SIZE - 1);

					if (ptl != lego_ptl) {
						spin_unlock(ptl);
					}
				}
				break;
			}
			case T_CMD_PAGE_INVALIDATE:
			{
				if (pte_present(*pte)) {
					ptl = pte_lockptr(mm, pmd);
					if (ptl != lego_ptl) {
						spin_lock(ptl);
					}

					pte_clear(pte);
					flush_tlb_mm_range(mm, addr, addr + PAGE_SIZE - 1);

					if (ptl != lego_ptl) {
						spin_unlock(ptl);
					}
				}
			}
			break;
			default:
			break;
			}
	unlock_protect:
			spin_unlock(lego_ptl);
		}
   }
   
	tb_set_private_tx(tb, (void *)new_page);
	tb_set_tx_size(tb, PCACHE_LINE_SIZE);
}

DEFINE_PROFILE_POINT(handle_flush)

void handle_p2m_flush_one(struct p2m_flush_msg *msg, struct thpool_buffer *tb)
{
	pid_t pid;
	unsigned long user_vaddr, dst_page;
	int reply, src_nid, ret;
	struct lego_task_struct *p;
	PROFILE_POINT_TIME(handle_flush)

	PROFILE_START(handle_flush);

	src_nid = to_common_header(msg)->src_nid;
	pid = msg->pid;
	user_vaddr = msg->user_va;

	p = find_lego_task_by_pid(src_nid, pid);
	if (unlikely(!p)) {
		reply = -ESRCH;
		goto out;
	}

	down_read(&p->mm->mmap_sem);
	ret = get_user_pages(p, msg->user_va, 1, 0, &dst_page, NULL);
	up_read(&p->mm->mmap_sem);
	if (likely(ret == 1)) {
		memcpy((void *)dst_page, msg->pcacheline, PCACHE_LINE_SIZE);
		reply = 0;
	} else
		reply = -EFAULT;

out:
	*(int *)thpool_buffer_tx(tb) = reply;
	tb_set_tx_size(tb, sizeof(int));
	PROFILE_LEAVE(handle_flush);
}

/*
 * Processor counterpart: __pcache_do_fill_page().
 * Check how we fill the information.
 */
static void do_piggyback_flush(void *_msg, unsigned int src_nid,
			       struct lego_task_struct *fault_task)
{
	struct p2m_pcache_miss_flush_combine_msg *pb_msg = _msg;
	struct p2m_flush_msg *flush_msg = &pb_msg->flush;
	struct lego_task_struct *flush_task;
	unsigned long dst_page;
	int ret;

	if (flush_msg->pid == fault_task->pid)
		flush_task = fault_task;
	else {
		flush_task = find_lego_task_by_pid(src_nid, flush_msg->pid);
		if (unlikely(!flush_task)) {
			WARN_ON_ONCE(1);
			return;
		}
	}

	down_read(&flush_task->mm->mmap_sem);
	ret = get_user_pages(flush_task, flush_msg->user_va, 1, 0, &dst_page, NULL);
	up_read(&flush_task->mm->mmap_sem);

	if (likely(ret == 1))
		memcpy((void *)dst_page, flush_msg->pcacheline, PCACHE_LINE_SIZE);
	else {
        printk("piggyback error for %#lx: ret = %d\n", flush_msg->user_va, ret);
		WARN_ON_ONCE(1);
    }
}

static int fault_in_kernel_space(unsigned long address)
{
	return address >= TASK_SIZE_MAX;
}

DEFINE_PROFILE_POINT(handle_miss)

void handle_p2m_pcache_miss(struct p2m_pcache_miss_msg *msg,
			    struct thpool_buffer *tb)
{
	u32 tgid, flags;
	u64 vaddr;
	unsigned int src_nid;
	struct lego_task_struct *p;
	PROFILE_POINT_TIME(handle_miss)

	src_nid = to_common_header(msg)->src_nid;
	tgid   = msg->tgid;
	flags  = msg->flags;
	vaddr  = msg->missing_vaddr;

	handle_pcache_debug("I nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);

	p = find_lego_task_by_pid(src_nid, tgid);
	if (unlikely(!p)) {
		pr_info("%s(): src_nid: %d tgid: %d\n", __func__, src_nid, tgid);
		pcache_miss_error(RET_ESRCH, p, vaddr, tb);
		return;
	}

	if (unlikely(fault_in_kernel_space(vaddr))) {
		pcache_miss_error(RET_EFAULT, p, vaddr, tb);
		return;
	}

	PROFILE_START(handle_miss);
	do_handle_p2m_pcache_miss(p, vaddr, flags, tb, msg->teleport_cmd);
	if (msg->has_flush_msg)
		do_piggyback_flush(msg, src_nid, p);
	PROFILE_LEAVE(handle_miss);

	handle_pcache_debug("O nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);
}

void handle_p2m_zerofill(struct p2m_zerofill_msg *msg,
			 struct thpool_buffer *tb)
{
	u32 tgid, flags;
	u64 vaddr;
	unsigned int src_nid;
	struct lego_task_struct *p;

	src_nid = to_common_header(msg)->src_nid;
	tgid   = msg->tgid;
	flags  = msg->flags;
	vaddr  = msg->missing_vaddr;

	handle_zerofill_debug("I nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);

	p = find_lego_task_by_pid(src_nid, tgid);
	if (unlikely(!p)) {
		pcache_miss_error(RET_ESRCH, p, vaddr, tb);
		return;
	}

	if (unlikely(fault_in_kernel_space(vaddr))) {
		pcache_miss_error(RET_EFAULT, p, vaddr, tb);
		return;
	}

	do_handle_p2m_zerofill_miss(p, vaddr, flags, tb);

	handle_zerofill_debug("O nid:%u pid:%u tgid:%u flags:%x vaddr:%#Lx",
		src_nid, msg->pid, tgid, flags, vaddr);
}
