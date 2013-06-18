#ifndef __CPT2_TASK_H__
#define __CPT2_TASK_H__

#include <stdbool.h>
#include <sys/types.h>

#include "cpt-image.h"
#include "context.h"
#include "list.h"

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

	struct list_head	list;
	struct list_head	children;
	struct list_head	threads;
	unsigned int		n_threads;

	struct task_aux_pos	aux_pos;

	struct cpt_task_image	ti;
};

extern int read_tasks(context_t *ctx);
extern int write_pstree(context_t *ctx);
extern int write_task_images(context_t *ctx);
extern void free_tasks(context_t *ctx);

extern struct task_struct *root_task;

#endif /* __CPT2_TASK_H__ */
