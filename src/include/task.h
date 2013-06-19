#ifndef __CPT2_TASK_H__
#define __CPT2_TASK_H__

#include <stdbool.h>
#include <sys/types.h>

#include "task-states.h"
#include "cpt-image.h"
#include "context.h"
#include "list.h"
#include "bug.h"

/*
 * Offsets associated with task, they lays right
 * after task image, in the order we bullet below.
 */
struct task_aux_pos {
	/* CPT_OBJ_BITS/CPT_CONTENT_STACK */
	off_t			off_kstack;

	/* CPT_OBJ_X86_REGS or CPT_OBJ_X86_64_REGS */
	off_t			off_gpr;

	/* CPT_OBJ_BITS/(CPT_CONTENT_X86_XSAVE|FPUSTATE_OLD|FPUSTATE) */
	off_t			off_xsave;
	off_t			off_fsave;
	off_t			off_fxsave;

	/* CPT_OBJ_LASTSIGINFO/CPT_CONTENT_VOID */
	off_t			off_lastsiginfo;

	/* CPT_OBJ_SIGALTSTACK/CPT_CONTENT_VOID */
	off_t			off_sigaltstack;

	/* CPT_OBJ_TASK_AUX/CPT_CONTENT_VOID */
	off_t			off_futex;

	/* CPT_OBJ_SIGINFO/CPT_CONTENT_VOID */
	off_t			off_sig_priv_pending;

	/* CPT_OBJ_SIGNAL_STRUCT/CPT_CONTENT_ARRAY */
	off_t			off_signal;

	/* CPT_OBJ_SIGINFO/CPT_CONTENT_VOID */
	off_t			off_sig_share_pending;
};

struct task_struct {
	struct hlist_node	hash;
	struct task_struct	*parent;
	struct task_struct	*real_parent;

	struct list_head	flat;		/* flat view, read from image */

	struct list_head	tasks;		/* linkage for init_task */

	struct list_head	children;	/* list of my children */
	struct list_head	sibling;	/* linkage in my parent's children list */

	struct task_struct	*group_leader;
	struct list_head	thread_group;	/* list of my threads */

	unsigned int		nr_threads;	/* to speedup threads counting */

	struct task_aux_pos	aux_pos;

	struct cpt_task_image	ti;
};

extern struct task_struct *root_task;
extern struct task_struct init_task;

static inline struct task_struct *
next_thread(const struct task_struct *p)
{
	return list_entry(p->thread_group.next,
			  struct task_struct,
			  thread_group);
}

static inline struct task_struct *
next_task(const struct task_struct *p)
{
	return list_entry(p->tasks.next,
			  struct task_struct,
			  tasks);
}

#define for_each_process(p)				\
	for (p = &init_task;				\
	     (p = next_task(p)) != &init_task; )

/*
 * Careful: do_each_thread/while_each_thread is a double loop so
 *          'break' will not work as expected - use goto instead.
 */
#define do_each_thread(g, t)				\
	for (g = t = &init_task;			\
	     (g = t = next_task(g)) != &init_task; ) do

#define while_each_thread(g, t)				\
	while ((t = next_thread(t)) != g)

static inline int thread_group_empty(struct task_struct *p)
{
	return list_empty(&p->thread_group);
}

static inline bool thread_group_leader(struct task_struct *p)
{
	return p->ti.cpt_pid == p->ti.cpt_tgid;
}

static inline bool task_is_zombie(unsigned long state)
{
	return !!(state & (EXIT_ZOMBIE | EXIT_DEAD));
}

static inline bool task_is_stopped(unsigned long state)
{
	return !!(state & TASK_STOPPED);
}

static inline bool task_is_running(unsigned long state)
{
	return !!(state & TASK_NORMAL);
}

/*
 * Task states CRIU understands.
 */
#define CRIU_TASK_ALIVE		0x1
#define CRIU_TASK_DEAD		0x2
#define CRIU_TASK_STOPPED	0x3
#define CRIU_TASK_HELPER	0x4

static inline unsigned int encode_task_state(unsigned long state)
{
	BUG_ON(task_is_stopped(state));

	return task_is_zombie(state) ? CRIU_TASK_DEAD : CRIU_TASK_ALIVE;
}

extern int read_tasks(context_t *ctx);
extern int write_pstree(context_t *ctx);
extern int write_task_images(context_t *ctx);
extern void free_tasks(context_t *ctx);

#endif /* __CPT2_TASK_H__ */
