#include <lego/mm.h>
#include <lego/rwsem.h>
#include <lego/slab.h>
#include <lego/rbtree.h>
#include <lego/sched.h>
#include <lego/kernel.h>
#include <lego/netmacro.h>
#include <lego/fit_ibapi.h>

#include <memory/vm.h>
#include <memory/pid.h>
#include <memory/vm-pgtable.h>
#include <memory/distvm.h>
#include <memory/file_types.h>

#include <memory/teleport_vm.h>

#define LEGO_PGALLOC_GFP     (GFP_KERNEL | __GFP_ZERO)

/*
    Recover the page table in mm (virtual to physical)
    from lego_mm (user virtual to kernel virtual).
*/
int recover_mm_from_lego_mm(struct mm_struct *dst,
        struct lego_mm_struct *src, struct task_struct *dst_tsk,
        struct lego_task_struct *src_tsk) {
    //
    struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
    struct rb_node **rb_link, *rb_parent;
    int ret = 0;

    for (mpnt = src->mmap; mpnt; mpnt = mpnt->vm_next) {
        ret = copy_mm_from_lego(dst, src, mpnt, dst_tsk);

        if (ret)
            goto out;
    }

    ret = 0;
out:
    return ret;
}

int recover_mm_from_lego_mm_with_table(struct mm_struct *dst,
        struct lego_mm_struct *src, struct task_struct *dst_tsk,
        struct lego_task_struct *src_tsk, struct hlist_head* pageinfo_table,
        int hash_bits, bool is_coherent) {
    //
    struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
    struct rb_node **rb_link, *rb_parent;
    int ret = 0;
    for (mpnt = src->mmap; mpnt; mpnt = mpnt->vm_next) {
        ret = copy_mm_from_lego_with_table(dst, src, mpnt, dst_tsk, pageinfo_table, hash_bits, is_coherent);

        if (ret)
            goto out;
    }

    ret = 0;
out:
    return ret;
}
