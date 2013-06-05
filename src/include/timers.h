#ifndef __CPT2_TIMERS_H__
#define __CPT2_TIMERS_H__

#include <stdbool.h>

#include "asm/int.h"

#include "cpt-image.h"
#include "context.h"
#include "ktime.h"
#include "task.h"
#include "list.h"

extern u16 image_HZ;

extern void free_timers(context_t *ctx);
extern int read_timers(context_t *ctx);
extern int write_timers(context_t *ctx, struct task_struct *t);

#endif /* __CPT2_TIMERS_H__ */
