#ifndef _LEGO_MEMORY_DCR_SYNCMEM_H_
#define _LEGO_MEMORY_DCR_SYNCMEM_H_

#include <memory/task.h>

int common_handle_p2m_miss(struct lego_task_struct *p,
                          u64 vaddr, u32 flags, unsigned long *new_page);

#endif
