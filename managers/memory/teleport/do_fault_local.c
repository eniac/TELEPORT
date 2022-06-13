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

static int __do_fault(struct lego_mm_struct *mm, struct vm_area_struct *vma,
        unsigned long address, pmd_t *pmd,
        pgoff_t pgoff, unsigned int flags, pte_t orig_pte,
        unsigned long *mapping_flags)
{
    struct vm_fault vmf;
    pte_t *page_table;
    pte_t entry;
    spinlock_t *ptl;
    int ret;

    vmf.virtual_address = address & PAGE_MASK;
    vmf.pgoff = pgoff;
    vmf.flags = flags;
    vmf.page = 0;

    ret = vma->vm_ops->fault(vma, &vmf);
    if (unlikely(ret & VM_FAULT_ERROR))
        return ret;

    page_table = lego_pte_offset_lock(mm, pmd, address, &ptl);

    if (likely(pte_same(*page_table, orig_pte))) {
        entry = lego_vfn_pte(((signed long)vmf.page >> PAGE_SHIFT),
                vma->vm_page_prot);
        if (flags & FAULT_FLAG_WRITE)
            entry = pte_mkwrite(pte_mkdirty(entry));
        pte_set(page_table, entry);
    }

    lego_pte_unlock(page_table, ptl);
    if (mapping_flags)
        *mapping_flags = PCACHE_MAPPING_FILE;
    return 0;
}

static int do_linear_fault(struct vm_area_struct *vma, unsigned long address,
        unsigned int flags, pte_t *page_table, pmd_t *pmd,
        pte_t orig_pte, unsigned long *mapping_flags)
{
    pgoff_t pgoff = (((address & PAGE_MASK)
                - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;

    return __do_fault(vma->vm_mm, vma, address, pmd, pgoff, flags, orig_pte, mapping_flags);
}

static int do_anonymous_page(struct vm_area_struct *vma, unsigned long address,
        unsigned int flags, pte_t *page_table, pmd_t *pmd,
        unsigned long *mapping_flags)
{
    pte_t entry;
    spinlock_t *ptl;
    unsigned long vaddr;
    struct lego_mm_struct *mm = vma->vm_mm;

    vaddr = __get_free_page(GFP_KERNEL | __GFP_ZERO);
    if (!vaddr)
        return VM_FAULT_OOM;

    entry = lego_vfn_pte(((signed long)vaddr >> PAGE_SHIFT),
            vma->vm_page_prot);
    if (vma->vm_flags & VM_WRITE)
        entry = pte_mkwrite(pte_mkdirty(entry));

    page_table = lego_pte_offset_lock(mm, pmd, address, &ptl);
    if (!pte_none(*page_table))
        goto unlock;

    pte_set(page_table, entry);
unlock:
    lego_pte_unlock(page_table, ptl);
    if (mapping_flags)
        *mapping_flags = PCACHE_MAPPING_ANON;
    return 0;
}

static int handle_pte_fault_local(struct vm_area_struct *vma, unsigned long address,
        unsigned int flags, pte_t *pte, pmd_t *pmd,
        unsigned long *mapping_flags)
{
    pte_t entry;
    spinlock_t *ptl;
    struct lego_mm_struct *mm = vma->vm_mm;
    int ret;

    entry = *pte;
    if (likely(!pte_present(entry))) {
        if (pte_none(entry)) {
            if (vma->vm_ops && vma->vm_ops->fault) {
                ret = do_linear_fault(vma, address, flags,
                        pte, pmd, entry, mapping_flags);
                return ret;
            } else {
                ret = do_anonymous_page(vma, address, flags,
                        pte, pmd, mapping_flags);
                return ret;
            }
        }

        dump_pte(pte, NULL);
        BUG();
    }

    ptl = lego_pte_lockptr(mm, pmd);
    spin_lock(ptl);

    if (unlikely(!pte_same(*pte, entry)))
        goto unlock;

    if (flags & FAULT_FLAG_WRITE) {
        if (likely(!pte_write(entry))) {
            spin_unlock(ptl);
            return 0;
        }
    }

unlock:
    lego_pte_unlock(pte, ptl);
    return 0;
}

int handle_fault_local(struct vm_area_struct *vma, unsigned long address,
        unsigned int flags, unsigned long *mapping_flags) {
    struct lego_mm_struct *mm = vma->vm_mm;
    int ret;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = lego_pgd_offset(mm, address);
    pud = lego_pud_alloc(mm, pgd, address);
    if (!pud)
        return VM_FAULT_OOM;
    pmd = lego_pmd_alloc(mm, pud, address);
    if (!pmd)
        return VM_FAULT_OOM;
    pte = lego_pte_alloc(mm, pmd, address);
    if (!pte)
        return VM_FAULT_OOM;

    ret = handle_pte_fault_local(vma, address, flags, pte, pmd, mapping_flags);
    if (unlikely(ret))
        return ret;

    return 0;
}

int common_handle_fault_local(struct lego_task_struct *p,
        u64 vaddr, u32 flags, struct vm_area_struct **vma)
{
    struct lego_mm_struct *mm = p->mm;
    int ret;

    down_read(&mm->mmap_sem);

    *vma = find_vma(mm, vaddr);

    if (unlikely(!(*vma))) {
        pr_info("fail to find vma\n");
        ret = VM_FAULT_SIGSEGV;
        goto unlock;
    }

    if (likely((*vma)->vm_start <= vaddr))
        goto good_area;

    if (unlikely(!((*vma)->vm_flags & VM_GROWSDOWN))) {
        ret = VM_FAULT_SIGSEGV;
        goto unlock;
    }

    if (unlikely(expand_stack(*vma, vaddr))) {
        pr_info("fail to expand stack\n");
        ret = VM_FAULT_SIGSEGV;
        goto unlock;
    }

good_area:
    ret = handle_fault_local(*vma, vaddr, flags, NULL);
unlock:
    up_read(&mm->mmap_sem);
    return ret;
}

int common_handle_fault_local_get_user_pages(struct lego_task_struct *p,
        u64 vaddr, u32 flags, struct vm_area_struct **vma)
{
    unsigned long dst_page;
	int ret = 0;

	down_read(&p->mm->mmap_sem);
    *vma = find_vma(p->mm, vaddr);
    up_read(&p->mm->mmap_sem);

    if (unlikely(!(*vma))) {
        printk("fail to find vma for %#lx\n", vaddr);
        ret = VM_FAULT_SIGSEGV;
    }

    down_read(&p->mm->mmap_sem);
	ret = get_user_pages(p, vaddr, 1, 0, &dst_page, NULL);
	up_read(&p->mm->mmap_sem);

    if (likely(ret == 1))
        memset((void *)dst_page, 0, PCACHE_LINE_SIZE);
    else {
        printk("handle local fault error: ret = %d\n", ret);
		WARN_ON_ONCE(1);
    }

    return ret == 1 ? 0 : -1;
}

int teleport_handle_fault_local(struct mm_struct *mm, int pid, int tgid,
        unsigned long fault_address, u32 flags, __u32 node_id)
{
    struct lego_task_struct *lego_tsk;
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
    unsigned long address = fault_address & PAGE_MASK;
    int res = 0;

    lego_tsk = find_lego_task_by_pid(node_id, tgid);

    if (unlikely(!lego_tsk)) {
        printk("%s(): src_nid: %d tgid: %d -- task not found!\n", __func__, node_id, tgid);
        return RET_ESRCH;
    }

    res = common_handle_fault_local(lego_tsk, address, flags, &vma);

    if (unlikely(res)) {
        printk("TELEPORT: failed to handle fault (%#lx)!\n", address);
        return res;
    }

    down_read(&lego_tsk->mm->mmap_sem);
    vma = find_vma(lego_tsk->mm, address);
    up_read(&lego_tsk->mm->mmap_sem);

    if (unlikely(!vma)) {
        pr_info("failed to find vma\n");
        return VM_FAULT_SIGSEGV;
    }

    pgd = pgd_offset(mm, address);	
    pud = pud_alloc(mm, pgd, address);
    if (!pud)
        return VM_FAULT_OOM;
    pmd = pmd_alloc(mm, pud, address);
    if (!pmd)
        return VM_FAULT_OOM;
    pte = pte_alloc(mm, pmd, address);
    if (!pte)
        return VM_FAULT_OOM;

    actual_mm = vma->vm_mm;

    lego_pgd = lego_pgd_offset(actual_mm, address);	
    lego_pud = lego_pud_offset(lego_pgd, address);
    lego_pmd = lego_pmd_offset(lego_pud, address);
    lego_pte = lego_pte_offset(lego_pmd, address);

    real_pte = *lego_pte;

    src_ptl = lego_pte_lockptr(actual_mm, lego_pmd);
    spin_lock(src_ptl);

    dst_ptl = pte_lockptr(mm, pmd);
    if (src_ptl != dst_ptl) {
        spin_lock(dst_ptl);
    }

    real_pte = pfn_pte(virt_to_pfn(lego_pte_to_virt(real_pte)), vma->vm_page_prot);
    real_pte = pte_mkold(real_pte);
    real_pte = pte_mkclean(real_pte);
    if (flags & FAULT_FLAG_WRITE) {
        real_pte = pte_mkwrite(real_pte);
    } else {
        real_pte = pte_wrprotect(real_pte);
    }
    pte_set(pte, real_pte);

    spin_unlock(src_ptl);
    if (src_ptl != dst_ptl)
        spin_unlock(dst_ptl);

    return res;
}
