#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <linux/futex.h>
#include <linux/sched.h>

#include "asm/fpu.h"

#include "syscall-codes.h"

#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "timers.h"
#include "image.h"
#include "files.h"
#include "read.h"
#include "task.h"
#include "log.h"
#include "obj.h"
#include "bug.h"
#include "net.h"
#include "sig.h"
#include "mm.h"
#include "ns.h"

#include "protobuf.h"
#include "protobuf/pstree.pb-c.h"
#include "protobuf/rlimit.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/sa.pb-c.h"

static unsigned int max_threads = 1;

/*
 * This init task is served only for linkage of the
 * process tree, thus never dump or convert it to some
 * CRIU image.
 */
struct task_struct init_task = {
	.parent			= &init_task,
	.real_parent		= &init_task,
	.tasks			= LIST_HEAD_INIT(init_task.tasks),
	.children		= LIST_HEAD_INIT(init_task.children),
	.sibling		= LIST_HEAD_INIT(init_task.sibling),
	.group_leader		= &init_task,
	.thread_group		= LIST_HEAD_INIT(init_task.thread_group),
	.nr_threads		= 1,
};

struct task_struct *root_task;

#define PID_HASH_BITS		10
static DEFINE_HASHTABLE(pids_hash, PID_HASH_BITS);

struct task_struct *task_lookup_pid(u32 pid)
{
	struct task_struct *task;

	hash_for_each_key(pids_hash, task, hash, pid) {
		if (task->ti.cpt_pid == pid)
			return task;
	}

	return NULL;
}

static int read_core_fpu(context_t *ctx, struct task_struct *t, CoreEntry *core)
{
	struct xsave_struct xsave;
	struct cpt_obj_bits bits;

#define __copy_fpu_state()								\
	do {										\
		core->thread_info->fpregs->cwd		= xsave.i387.cwd;		\
		core->thread_info->fpregs->swd		= xsave.i387.swd;		\
		core->thread_info->fpregs->twd		= xsave.i387.twd;		\
		core->thread_info->fpregs->fop		= xsave.i387.fop;		\
		core->thread_info->fpregs->rip		= xsave.i387.rip;		\
		core->thread_info->fpregs->rdp		= xsave.i387.rdp;		\
		core->thread_info->fpregs->mxcsr	= xsave.i387.mxcsr;		\
		core->thread_info->fpregs->mxcsr_mask	= xsave.i387.mxcsr_mask;	\
											\
		memcpy(core->thread_info->fpregs->st_space,				\
		       xsave.i387.st_space, sizeof(xsave.i387.st_space));		\
		memcpy(core->thread_info->fpregs->xmm_space,				\
		       xsave.i387.xmm_space, sizeof(xsave.i387.xmm_space));		\
	} while (0)

	if (t->aux_pos.off_fxsave) {
		if (read_obj_cpt(ctx->fd, CPT_OBJ_BITS, &bits, t->aux_pos.off_fxsave)) {
			pr_err("Can't read task fxsave at @%li\n", (long)t->aux_pos.off_fxsave);
			return -1;
		}

		if (bits.cpt_size != sizeof(xsave.i387)) {
			pr_err("Inconsistent fxsave frame size %d(%d) at @%li\n",
			       (int)bits.cpt_size, (int)sizeof(xsave.i387),
			       (long)t->aux_pos.off_fxsave);
			return -1;
		}

		if (read_data(ctx->fd, &xsave.i387, sizeof(xsave.i387), false)) {
			pr_err("Can't read bits at %li\n", (long)t->aux_pos.off_fxsave);
			return -1;
		}

		__copy_fpu_state();

		/*
		 * Don't forget to drop xsave frame, it can't be
		 * two frames in one pass.
		 */
		core->thread_info->fpregs->xsave = NULL;
	} else if (t->aux_pos.off_xsave) {
		if (read_obj_cpt(ctx->fd, CPT_OBJ_BITS, &bits, t->aux_pos.off_xsave)) {
			pr_err("Can't read task xsave at @%li\n", (long)t->aux_pos.off_xsave);
			return -1;
		}

		if (bits.cpt_size != sizeof(xsave)) {
			pr_err("Inconsistent xsave frame size %d(%d) at @%li\n",
			       (int)bits.cpt_size, (int)sizeof(xsave),
			       (long)t->aux_pos.off_xsave);
			return -1;
		}

		if (read_data(ctx->fd, &xsave, sizeof(xsave), false)) {
			pr_err("Can't read bits at @%li\n", (long)t->aux_pos.off_xsave);
			return -1;
		}

		__copy_fpu_state();

		core->thread_info->fpregs->xsave->xstate_bv = xsave.xsave_hdr.xstate_bv;

		memcpy(core->thread_info->fpregs->xsave->ymmh_space,
		       xsave.ymmh.ymmh_space, sizeof(xsave.ymmh.ymmh_space));
	} else
		BUG();

	return 0;
#undef __copy_fpu_state
}

static u32 decode_segment(u32 segno)
{
	if (segno == CPT_SEG_ZERO)
		return 0;

	if (segno <= CPT_SEG_TLS3)
		return ((GDT_ENTRY_TLS_MIN + segno - CPT_SEG_TLS1) << 3) + 3;

	if (segno >= CPT_SEG_LDT)
		return ((segno - CPT_SEG_LDT) << 3) | 7;

	if (segno == CPT_SEG_USER32_DS)
		return __USER32_DS;
	if (segno == CPT_SEG_USER32_CS)
		return __USER32_CS;
	if (segno == CPT_SEG_USER64_DS)
		return __USER_DS;
	if (segno == CPT_SEG_USER64_CS)
		return __USER_CS;

	pr_err("Invalid segment register %d\n", segno);
	return 0;
}

static void adjust_syscall_ret(UserX86RegsEntry *gpregs)
{
	if ((int)gpregs->orig_ax >= 0) {
		/* Restart the system call */
		switch ((int)gpregs->ax) {
		case -ERESTARTNOHAND:
		case -ERESTARTSYS:
		case -ERESTARTNOINTR:
			gpregs->ax = gpregs->orig_ax;
			gpregs->ip -= 2;
			break;
		case -ERESTART_RESTARTBLOCK:
			gpregs->ax = __NR_restart_syscall;
			gpregs->ip -= 2;
			break;
		}
	}

}

static int read_core_gpr(context_t *ctx, struct task_struct *t, CoreEntry *core)
{
	struct cpt_x86_64_regs regs;

	if (read_obj_cpt(ctx->fd, CPT_OBJ_X86_64_REGS, &regs, t->aux_pos.off_gpr)) {
		pr_err("Can't read task registers at @%li\n", (long)t->aux_pos.off_gpr);
		return -1;
	}

	core->thread_info->gpregs->r15		= regs.cpt_r15;
	core->thread_info->gpregs->r14		= regs.cpt_r14;
	core->thread_info->gpregs->r13		= regs.cpt_r13;
	core->thread_info->gpregs->r12		= regs.cpt_r12;
	core->thread_info->gpregs->bp		= regs.cpt_rbp;
	core->thread_info->gpregs->bx		= regs.cpt_rbx;
	core->thread_info->gpregs->r11		= regs.cpt_r11;
	core->thread_info->gpregs->r10		= regs.cpt_r10;
	core->thread_info->gpregs->r9		= regs.cpt_r9;
	core->thread_info->gpregs->r8		= regs.cpt_r8;
	core->thread_info->gpregs->ax		= regs.cpt_rax;
	core->thread_info->gpregs->cx		= regs.cpt_rcx;
	core->thread_info->gpregs->dx		= regs.cpt_rdx;
	core->thread_info->gpregs->si		= regs.cpt_rsi;
	core->thread_info->gpregs->di		= regs.cpt_rdi;
	core->thread_info->gpregs->orig_ax	= regs.cpt_orig_rax;
	core->thread_info->gpregs->ip		= regs.cpt_rip;
	core->thread_info->gpregs->cs		= decode_segment(regs.cpt_cs);
	core->thread_info->gpregs->flags	= regs.cpt_eflags;
	core->thread_info->gpregs->sp		= regs.cpt_rsp;
	core->thread_info->gpregs->ss		= decode_segment(regs.cpt_ss);
	core->thread_info->gpregs->fs_base	= regs.cpt_fsbase;
	core->thread_info->gpregs->gs_base	= regs.cpt_gsbase;
	core->thread_info->gpregs->ds		= decode_segment(regs.cpt_ds);
	core->thread_info->gpregs->es		= decode_segment(regs.cpt_es);
	core->thread_info->gpregs->fs		= decode_segment(regs.cpt_fsindex);
	core->thread_info->gpregs->gs		= decode_segment(regs.cpt_gsindex);

	adjust_syscall_ret(core->thread_info->gpregs);
	return 0;
}

static int read_core_data(context_t *ctx, struct task_struct *t, CoreEntry *core)
{
	if (read_core_gpr(ctx, t, core))
		return -1;

	if (read_core_fpu(ctx, t, core))
		return -1;

	/*
	 * Futexes are small one, read them right here.
	 */
	if (t->aux_pos.off_futex) {
		struct cpt_task_aux_image aux;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_TASK_AUX, &aux, t->aux_pos.off_futex)) {
			pr_err("Can't read task futexes at @%li\n", (long)t->aux_pos.off_futex);
			return -1;
		}

		/* See note at FUTEX_RLA_LEN definition */
		core->thread_core->futex_rla		= aux.cpt_robust_list;
		core->thread_core->futex_rla_len	= FUTEX_RLA_LEN;
	}

	/*
	 * FIXME Please make sure all t->aux_pos are covered
	 */

	return 0;
}

static int write_task_core(context_t *ctx, struct task_struct *t, bool is_thread)
{
	ThreadCoreEntry thread_core = THREAD_CORE_ENTRY__INIT;
	ThreadInfoX86 thread_info = THREAD_INFO_X86__INIT;
	TaskCoreEntry tc = TASK_CORE_ENTRY__INIT;
	CoreEntry core = CORE_ENTRY__INIT;

	UserX86RegsEntry gpregs = USER_X86_REGS_ENTRY__INIT;
	UserX86FpregsEntry fpregs = USER_X86_FPREGS_ENTRY__INIT;
	UserX86XsaveEntry xsave = USER_X86_XSAVE_ENTRY__INIT;

	struct xsave_struct x;

	int core_fd = -1, ret = -1;

	core_fd = open_image(ctx, CR_FD_CORE, O_DUMP, t->ti.cpt_pid);
	if (core_fd < 0)
		return -1;

	/*
	 * Bind core topology, the callee may maodify it so don't
	 * assume it's immutable.
	 */
	core.mtype			= CORE_ENTRY__MARCH__X86_64;
	core.thread_info		= &thread_info;
	core.tc				= &tc;

	core.thread_core		= &thread_core;

	thread_info.gpregs		= &gpregs;
	thread_info.fpregs		= &fpregs;

	BUILD_BUG_ON(sizeof(x.i387.st_space[0]) != sizeof(fpregs.st_space[0]));
	BUILD_BUG_ON(sizeof(x.i387.xmm_space[0]) != sizeof(fpregs.xmm_space[0]));
	BUILD_BUG_ON(sizeof(x.ymmh.ymmh_space[0]) != sizeof(xsave.ymmh_space[0]));

	xsave.n_ymmh_space		= ARRAY_SIZE(x.ymmh.ymmh_space);
	xsave.ymmh_space		= x.ymmh.ymmh_space;

	fpregs.xsave			= &xsave;

	fpregs.n_st_space		= ARRAY_SIZE(x.i387.st_space);
	fpregs.st_space			= x.i387.st_space;
	fpregs.n_xmm_space		= ARRAY_SIZE(x.i387.xmm_space);
	fpregs.xmm_space		= x.i387.xmm_space;

	if (read_core_data(ctx, t, &core)) {
		pr_err("Failed to read core data for task %d\n",
		       t->ti.cpt_pid);
			goto out;
	}

	tc.task_state			= encode_task_state(t->ti.cpt_state);
	tc.exit_code			= t->ti.cpt_exit_code;
	tc.personality			= t->ti.cpt_personality;
	tc.flags			= t->ti.cpt_flags;
	tc.blk_sigset			= t->ti.cpt_sigrblocked;
	tc.comm				= (char *)t->ti.cpt_comm;

	if (is_thread)
		core.tc = NULL;

	ret = pb_write_one(core_fd, &core, PB_CORE);

	/*
	 * FIXME Revisit sched entries.
	 */

#define MAX_USER_RT_PRIO	100
#define MAX_RT_PRIO		MAX_USER_RT_PRIO
#define PRIO_TO_NICE(prio)	((prio) - MAX_RT_PRIO - 20)

	thread_core.has_sched_nice	= true;
	thread_core.sched_nice		= 20 - PRIO_TO_NICE(t->ti.cpt_static_prio);

	thread_core.has_sched_policy	= true;
	thread_core.sched_policy	= t->ti.cpt_policy;

	thread_core.has_sched_prio	= true;
	thread_core.sched_prio		= t->ti.cpt_rt_priority;
out:
	close_safe(&core_fd);
	return ret;
}

static int write_task_kids(context_t *ctx, struct task_struct *t)
{
	TaskKobjIdsEntry kids = TASK_KOBJ_IDS_ENTRY__INIT;
	int fd, ret = -1;
	obj_t *obj;

	fd = open_image(ctx, CR_FD_IDS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	/*
	 * FIXME In crtools we use 32 bit kids, while
	 * openvz is using 64 bit ones.
	 */

	obj = obj_hash_lookup(CPT_OBJ_MM, t->ti.cpt_mm);
	if (!obj) {
		pr_err("Can't find mm at @%li\n", (long)t->ti.cpt_mm);
		goto out;
	}
	kids.vm_id	= t->ti.cpt_mm;

	obj = obj_hash_lookup(CPT_OBJ_FILES, t->ti.cpt_files);
	if (!obj) {
		pr_err("Can't find files at @%li\n", (long)t->ti.cpt_files);
		goto out;
	}
	kids.files_id		= t->ti.cpt_files;

	kids.fs_id		= t->ti.cpt_fs;
	kids.sighand_id		= t->ti.cpt_sighand;

	kids.has_pid_ns_id	= true;
	kids.has_net_ns_id	= true;
	kids.has_ipc_ns_id	= true;
	kids.has_uts_ns_id	= true;
	kids.has_mnt_ns_id	= true;

	/*
	 * FIXME See write_inventory() routine.
	 * There IDs are taken for debug purpose
	 * only!
	 */

	kids.pid_ns_id		= 1;
	kids.net_ns_id		= 1;
	kids.ipc_ns_id		= 2;
	kids.uts_ns_id		= 2;
	kids.mnt_ns_id		= t->ti.cpt_namespace;

	ret = pb_write_one(fd, &kids, PB_IDS);
out:
	close(fd);
	return ret;
}

static int write_task_creds(context_t *ctx, struct task_struct *t)
{
	CredsEntry ce = CREDS_ENTRY__INIT;
	int ret = 0, fd = -1;
	u64 bset = ~0;

	fd = open_image(ctx, CR_FD_CREDS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	ce.uid		= t->ti.cpt_uid;
	ce.gid		= t->ti.cpt_gid;
	ce.euid		= t->ti.cpt_euid;
	ce.egid		= t->ti.cpt_egid;
	ce.suid		= t->ti.cpt_suid;
	ce.sgid		= t->ti.cpt_sgid;
	ce.fsuid	= t->ti.cpt_fsuid;
	ce.fsgid	= t->ti.cpt_fsgid;

	ce.n_cap_inh	= sizeof(t->ti.cpt_icap) / sizeof(ce.cap_inh[0]);
	ce.cap_inh	= (u32 *)&t->ti.cpt_icap;

	ce.n_cap_prm	= sizeof(t->ti.cpt_pcap) / sizeof(ce.cap_prm[0]);
	ce.cap_prm	= (u32 *)&t->ti.cpt_pcap;

	ce.n_cap_eff	= sizeof(t->ti.cpt_ecap) / sizeof(ce.cap_eff[0]);
	ce.cap_eff	= (u32 *)&t->ti.cpt_ecap;

	/*
	 * FIXME bset is container wide, yet not found where.
	 */
	ce.n_cap_bnd	= sizeof(bset) / sizeof(ce.cap_bnd[0]);
	ce.cap_bnd	= (u32 *)&bset;

	ce.secbits	= t->ti.cpt_keepcap;

	ce.n_groups	= t->ti.cpt_ngids;
	ce.groups	= t->ti.cpt_gids;

	ret = pb_write_one(fd, &ce, PB_CREDS);

	close_safe(&fd);
	return ret;
}

static int write_task_utsns(context_t *ctx, struct task_struct *t)
{
	int ret = 0;
	int fd = -1;

	fd = open_image(ctx, CR_FD_UTSNS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;
	goto out;
out:
	close_safe(&fd);
	return ret;
}

static int write_task_ipc(context_t *ctx, struct task_struct *t)
{
	int ret = -1;
	int fd_ipc_var = -1, fd_ipc_shm = -1;
	int fd_ipc_msg = -1, fd_ipc_sem = -1;

	fd_ipc_var = open_image(ctx, CR_FD_IPCNS_VAR, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_var < 0)
		goto out;
	fd_ipc_shm = open_image(ctx, CR_FD_IPCNS_SHM, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_shm < 0)
		goto out;
	fd_ipc_msg = open_image(ctx, CR_FD_IPCNS_MSG, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_msg < 0)
		goto out;
	fd_ipc_sem = open_image(ctx, CR_FD_IPCNS_SEM, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_sem < 0)
		goto out;
	ret = 0;
out:
	close_safe(&fd_ipc_var);
	close_safe(&fd_ipc_shm);
	close_safe(&fd_ipc_msg);
	close_safe(&fd_ipc_sem);
	return ret;
}


static int write_task_rlimits(context_t *ctx, struct task_struct *t)
{
	int fd, i, ret;

	fd = open_image(ctx, CR_FD_RLIMIT, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	for (i = 0, ret = 0; i < CPT_RLIM_NLIMITS; i++) {
		RlimitEntry re = RLIMIT_ENTRY__INIT;

		re.cur = t->ti.cpt_rlim_cur[i];
		re.max = t->ti.cpt_rlim_max[i];

		ret |= pb_write_one(fd, &re, PB_RLIMIT);
	}

	close(fd);
	return ret;
}

static int __write_thread_images(context_t *ctx, struct task_struct *t)
{
	if (write_task_core(ctx, t, true)) {
		pr_err("Failed writing core for thread %d\n",
		       t->ti.cpt_pid);
		return -1;
	}

	if (write_signal_private_queue(ctx, t))
		return -1;

	return 0;
}

static int __write_task_images(context_t *ctx, struct task_struct *t)
{
	int ret;

	ret = write_task_core(ctx, t, false);
	if (ret) {
		pr_err("Failed writing core for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	/*
	 * Nothing else for zombie tasks.
	 */
	if (task_is_zombie(t->ti.cpt_state))
		return 0;

	ret = write_task_rlimits(ctx, t);
	if (ret) {
		pr_err("Failed writing rlimits for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_files(ctx, t);
	if (ret) {
		pr_err("Failed writing fdinfo for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_mm(ctx, t->ti.cpt_pid, t->ti.cpt_mm);
	if (ret) {
		pr_err("Failed writing mm for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_vmas(ctx, t->ti.cpt_pid, t->ti.cpt_mm);
	if (ret) {
		pr_err("Failed writing vmas for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_pages(ctx, t->ti.cpt_pid, t->ti.cpt_mm);
	if (ret) {
		pr_err("Failed writing vmas for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_kids(ctx, t);
	if (ret) {
		pr_err("Failed writing kernel-ids for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_sighandlers(ctx, t);
	if (ret) {
		pr_err("Failed writing sighandlers for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_signal_queues(ctx, t);
	if (ret) {
		pr_err("Failed writing signal queues for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_timers(ctx, t);
	if (ret) {
		pr_err("Failed writing timers for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_creds(ctx, t);
	if (ret) {
		pr_err("Failed writing creds for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_utsns(ctx, t);
	if (ret) {
		pr_err("Failed writing utsns for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_ipc(ctx, t);
	if (ret) {
		pr_err("Failed writing ipc for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	ret = write_task_fs(ctx, t);
	if (ret) {
		pr_err("Failed writing fs for task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

out:
	return ret;
}

int write_task_images(context_t *ctx)
{
	struct task_struct *p, *t;
	int ret = 0;

	for_each_process(p) {
		ret = __write_task_images(ctx, p);
		if (ret)
			break;

		t = p;
		while_each_thread(p, t) {
			ret = __write_thread_images(ctx, t);
			if (ret)
				break;
		}
	}

	return ret;
}

int write_pstree(context_t *ctx)
{
	PstreeEntry e = PSTREE_ENTRY__INIT;
	struct task_struct *p, *t;
	pid_t real_ppid;
	unsigned int i;
	int fd = -1;
	int ret = 0;
	void *tbuf;

	tbuf = xmalloc(sizeof(e.threads[0]) * (max_threads));
	if (!tbuf)
		return -1;

	e.threads = tbuf;

	fd = open_image(ctx, CR_FD_PSTREE, O_DUMP);
	if (fd < 0) {
		ret = -1;
		goto err;
	}

	for_each_process(p) {
		i = 0;

		/*
		 * CRIU has no idea about in-kernel relationships
		 * with real-parents and such. The parents are simply
		 * linked from @children list. Thus even if there was
		 * fork() called from thread and kernel's parent is the
		 * thread itself, we need to alternate data writen on
		 * disk and make a thread group leader to become a parent
		 * of the task instead.
		 */

		if (p->ti.cpt_rppid) {
			BUG_ON(!p->real_parent);
			BUG_ON(!p->real_parent->group_leader);

			if (!thread_group_leader(p->real_parent))
				real_ppid = p->real_parent->group_leader->ti.cpt_pid;
			else
				real_ppid = p->real_parent->ti.cpt_pid;
		} else
			real_ppid = 0;

		e.pid		= p->ti.cpt_pid;
		e.ppid		= real_ppid;
		e.pgid		= p->ti.cpt_pgrp;
		e.sid		= p->ti.cpt_session;
		e.n_threads	= p->nr_threads;
		e.threads[i++]	= p->ti.cpt_pid;

		t = p;
		while_each_thread(p, t) {
			if (unlikely(i >= max_threads)) {
				pr_err("Threads overflow in task %d thread %d (%d %d)\n",
				       p->ti.cpt_pid, t->ti.cpt_pid, i, max_threads);
				ret = -1;
				goto err;
			}
			e.threads[i++] = t->ti.cpt_pid;
		}

		ret = pb_write_one(fd, &e, PB_PSTREE);
		if (ret)
			break;
	}

err:
	close_safe(&fd);
	xfree(tbuf);
	return ret;
}

static void show_process_tree()
{
	struct task_struct *p, *t;

	if (wont_print(LOG_DEBUG))
		return;

	pr_debug("Built process tree\n");
	pr_debug("------------------------------\n");
	for_each_process(p) {
		pr_debug("\tpid %6d ppid %6d rppid %6d tgid %6d\n",
			 p->ti.cpt_pid, p->ti.cpt_ppid,
			 p->ti.cpt_rppid, p->ti.cpt_tgid);
		t = p;
		while_each_thread(p, t) {
			pr_debug("\t\tpid %6d ppid %6d rppid %6d tgid %6d\n",
				 t->ti.cpt_pid, t->ti.cpt_ppid,
				 p->ti.cpt_rppid, t->ti.cpt_tgid);
		}
	}
	pr_debug("------------------------------\n");
}

/*
 * In criu  the process tree is a flat file with all parents
 * children connected together with threads assigned where needed.
 * Thus we have to collect all tasks fisrt from the openvz image
 * file, build a tree and only then we will be able to write converted
 * results back. The bad news are that we've no guarantee that the data
 * we're obtaining from the image are valid (we do a minimal check here,
 * since criu will catch any additional problems by its own).
 *
 * FIXME How to handle cpt_rppid, do we consider CLONE_PARENT at all?
 */
static int build_process_tree(struct list_head *flat_head)
{
	struct task_struct *t, *p, *tmp;

	list_for_each_entry_safe(p, tmp, flat_head, flat) {

		/*
		 * Real parent won't escape us.
		 */
		if (likely(p->ti.cpt_rppid)) {
			t = task_lookup_pid(p->ti.cpt_rppid);
			if (!t) {
				pr_err("Stray task %d without real parent %d\n",
				       p->ti.cpt_pid, p->ti.cpt_rppid);
				return -1;
			}
			p->real_parent = t;
		}

		/*
		 * I'm someone's child, I hope :-)
		 */
		if (likely(p->ti.cpt_ppid)) {
			t = task_lookup_pid(p->ti.cpt_ppid);
			if (!t) {
				pr_err("Stray task %d without parent %d\n",
				       p->ti.cpt_pid, p->ti.cpt_ppid);
				return -1;
			}

			p->parent = t;
		}

		/*
		 * I'm someone's twin... wait, thread I mean... whatever...
		 */
		if (thread_group_leader(p)) {
			if (p->real_parent)
				list_add_tail(&p->sibling, &p->real_parent->children);
			else
				list_add_tail(&p->sibling, &init_task.children);

			list_add_tail(&p->tasks, &init_task.tasks);
		} else {
			t = task_lookup_pid(p->ti.cpt_tgid);
			if (!t) {
				pr_err("Stray task %d without thread group %d\n",
				       p->ti.cpt_pid, p->ti.cpt_tgid);
				return -1;
			}

			p->group_leader = t;
			t->nr_threads++;

			list_add_tail(&p->thread_group, &p->group_leader->thread_group);

			if (p->group_leader->nr_threads > max_threads)
				max_threads = p->group_leader->nr_threads;
		}
	}

	root_task = next_task(&init_task);

	show_process_tree();

	return 0;
}

void free_tasks(context_t *ctx)
{
	struct task_struct *task;

	while ((task = obj_pop_unhash_to(CPT_OBJ_TASK)))
		obj_free_to(task);
}

static const char * const task_state_array[] = {
	"R (running)",		/*   0 */
	"S (sleeping)",		/*   1 */
	"D (disk sleep)",	/*   2 */
	"T (stopped)",		/*   4 */
	"t (tracing stop)",	/*   8 */
	"Z (zombie)",		/*  16 */
	"X (dead)",		/*  32 */
	"x (dead)",		/*  64 */
	"K (wakekill)",		/* 128 */
	"W (waking)",		/* 256 */
	"P (parked)",		/* 512 */
};

static inline const char *get_task_state(struct task_struct *t)
{
	const char * const *p = &task_state_array[0];
	struct cpt_task_image *ti = &t->ti;
	unsigned int state;

	BUILD_BUG_ON(1 + ilog2(TASK_STATE_MAX) != ARRAY_SIZE(task_state_array));

	state = (ti->cpt_state & (TASK_REPORT | EXIT_ZOMBIE | EXIT_DEAD));

	while (state) {
		p++;
		state >>= 1;
	}

	return *p;
}

static void show_task_cont(context_t *ctx, struct task_struct *t)
{
	struct cpt_task_image *ti = &t->ti;

	pr_debug("\t@%-8li pid %6d tgid %6d ppid %6d rppid %6d pgrp %6d\n"
		 "\t\tcomm '%s' session %d leader %d 64bit %d\n"
		 "\t\tmm @%-8ld files @%-8ld fs @%-8ld signal @%-8ld\n"
		 "\t\tstate @%-8ld exit_code @%-8ld posix_timers @%-8ld\n"
		 "\t\t\t%s\n",
		 (long)obj_of(t)->o_pos, ti->cpt_pid, ti->cpt_tgid, ti->cpt_ppid,
		 ti->cpt_rppid, ti->cpt_pgrp, ti->cpt_comm, ti->cpt_session,
		 ti->cpt_leader,ti->cpt_64bit, (long)ti->cpt_mm,
		 (long)ti->cpt_files, (long)ti->cpt_fs, (long)ti->cpt_signal,
		 (long)ti->cpt_state, (long)ti->cpt_exit_code,
		 (long)ti->cpt_posix_timers, get_task_state(t));
}

static int task_read_aux_pos(context_t *ctx, struct task_struct *t)
{
	struct cpt_object_hdr h;
	off_t start;

	for (start = obj_of(t)->o_pos + t->ti.cpt_hdrlen;
	     start < obj_of(t)->o_pos + t->ti.cpt_next;
	     start += h.cpt_next) {

		if (read_obj_hdr(ctx->fd, &h, start)) {
			pr_err("Can't read task data header at %li\n", (long)start);
			return -1;
		}

		switch (h.cpt_object) {
		case CPT_OBJ_X86_64_REGS:
			t->aux_pos.off_gpr = start;
			break;
		case CPT_OBJ_BITS:
			switch (h.cpt_content) {
			case CPT_CONTENT_STACK:
				t->aux_pos.off_kstack = start;
				break;
			case CPT_CONTENT_X86_XSAVE:
				t->aux_pos.off_xsave = start;
				break;
			case CPT_CONTENT_X86_FPUSTATE:
				t->aux_pos.off_fxsave = start;
				break;
			case CPT_CONTENT_X86_FPUSTATE_OLD:
				t->aux_pos.off_fsave = start;
				break;
			default:
				goto unknown_obj;
			}
			break;
		case CPT_OBJ_LASTSIGINFO:
			t->aux_pos.off_lastsiginfo = start;
			break;
		case CPT_OBJ_SIGALTSTACK:
			t->aux_pos.off_sigaltstack = start;
			break;
		case CPT_OBJ_TASK_AUX:
			t->aux_pos.off_futex = start;
			break;
		case CPT_OBJ_SIGNAL_STRUCT:
			t->aux_pos.off_signal = start;
			break;
		case CPT_OBJ_SIGINFO:
			/*
			 * Siginfo reading problem: for some reason the
			 * kernel doesn't wrap siginfos into CPT_CONTENT_ARRAY,
			 * instead it comes as a series of CPT_OBJ_SIGINFO with
			 * CPT_CONTENT_VOID content, making reading of these
			 * objects position dependent.
			 *
			 * So what we do here is trying to make read procedure
			 * position context dependent. Usual structure is the
			 * following
			 *
			 *    <CPT_OBJ_SIGINFO ... CPT_OBJ_SIGINFO>
			 *    [ <CPT_OBJ_SIGNAL_STRUCT>
			 *      <CPT_OBJ_SIGINFO ...CPT_OBJ_SIGINFO> ]
			 *
			 * first set is obligatory and stands for private
			 * pending signals queue, in turn the second set
			 * is optional and set for shared pending signals queue.
			 */
			if (!t->aux_pos.off_sig_priv_pending)
				t->aux_pos.off_sig_priv_pending = start;
			else if (t->aux_pos.off_signal) {
				if (!t->aux_pos.off_sig_share_pending)
					t->aux_pos.off_sig_share_pending = start;
			}
			break;
		default:
			goto unknown_obj;
		}
	}

	pr_debug("\t\t\toffs: @%-8li @%-8li @%-8li @%-8li\n"
		 "\t\t\t      @%-8li @%-8li @%-8li @%-8li\n"
		 "\t\t\t      @%-8li @%-8li @%-8li\n",
		 (long)t->aux_pos.off_kstack, (long)t->aux_pos.off_gpr,
		 (long)t->aux_pos.off_xsave, (long)t->aux_pos.off_fsave,
		 (long)t->aux_pos.off_fxsave, (long)t->aux_pos.off_lastsiginfo,
		 (long)t->aux_pos.off_sigaltstack, (long)t->aux_pos.off_futex,
		 (long)t->aux_pos.off_sig_priv_pending, (long)t->aux_pos.off_signal,
		 (long)t->aux_pos.off_sig_share_pending);

	return 0;

unknown_obj:
	pr_err("Unexpected object %d/%d at @%li\n",
	       h.cpt_object, h.cpt_content, (long)start);
	return -1;
}

static int validate_task_early(context_t *ctx, struct task_struct *t)
{
	if (!t->ti.cpt_64bit) {
		pr_err("Unsupported IA32 task (pid %d comm %s) at @%li\n",
		       t->ti.cpt_pid, t->ti.cpt_comm,
		       (long)obj_of(t)->o_pos);
		return -1;
	}

	/*
	 * At least GPR and FPU must be present.
	 */
	if (!t->aux_pos.off_gpr || (!t->aux_pos.off_xsave && !t->aux_pos.off_fxsave)) {
		pr_err("Incomplete/corrupted data (%li %li %li) in task "
		       "(pid %d comm %s) at @%li\n",
		       t->aux_pos.off_gpr, t->aux_pos.off_xsave,
		       t->aux_pos.off_fxsave,
		       t->ti.cpt_pid, t->ti.cpt_comm,
		       (long)obj_of(t)->o_pos);
		return -1;
	}

	/*
	 * Make sure the task is in state we can deal with.
	 */
	if (task_is_stopped(t->ti.cpt_state)) {
		pr_err("Stopped tasks are not supported yet\n");
		return -1;
	} else if (!task_is_running(t->ti.cpt_state) &&
		   !task_is_zombie(t->ti.cpt_state)) {
		pr_err("Task is in unsupported state\n");
		return -1;
	}

	return 0;
}

static void task_struct_init(struct task_struct *t)
{
	INIT_LIST_HEAD(&t->flat);

	INIT_LIST_HEAD(&t->tasks);
	t->parent = t->real_parent = NULL;

	INIT_LIST_HEAD(&t->sibling);
	INIT_LIST_HEAD(&t->children);

	/*
	 * By default I'm thread group leader.
	 * Precise linkage will be done later.
	 */
	INIT_LIST_HEAD(&t->thread_group);
	t->group_leader = t;
	t->nr_threads = 1;

	memzero_p(&t->aux_pos);
}

int read_tasks(context_t *ctx)
{
	LIST_HEAD(flat_head);
	struct task_struct *task;
	off_t start, end;

	pr_read_start("tasks\n");
	get_section_bounds(ctx, CPT_SECT_TASKS, &start, &end);

	while (start < end) {
		task = obj_alloc_to(struct task_struct, ti);
		if (!task)
			return -1;
		task_struct_init(task);

		if (read_obj(ctx->fd, CPT_OBJ_TASK, &task->ti, sizeof(task->ti), start)) {
			obj_free_to(task);
			pr_err("Can't read task object at %li\n", (long)start);
			return -1;
		}

		obj_set_eos(task->ti.cpt_comm);

		hash_add(pids_hash, &task->hash, task->ti.cpt_pid);
		list_add_tail(&task->flat, &flat_head);
		obj_push_hash_to(task, CPT_OBJ_TASK, start);

		/*
		 * A task with minimal PID become a root one.
		 */
		if (likely(root_task)) {
			if (root_task->ti.cpt_pid > task->ti.cpt_pid)
				root_task = task;
		} else
			root_task = task;

		start += task->ti.cpt_next;
		show_task_cont(ctx, task);

		if (task_read_aux_pos(ctx, task) ||
		    validate_task_early(ctx, task))
			return -1;
	}
	pr_read_end();

	if (build_process_tree(&flat_head))
		return -1;

	return 0;
}
