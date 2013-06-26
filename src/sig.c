#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>

#include "cpt-image.h"
#include "xmalloc.h"
#include "image.h"
#include "read.h"
#include "log.h"
#include "obj.h"
#include "bug.h"
#include "sig.h"

#include "protobuf.h"
#include "protobuf/sa.pb-c.h"
#include "protobuf/siginfo.pb-c.h"

static void encode_siginfo(siginfo_t *d, struct cpt_siginfo_image *si)
{
	memzero(d, sizeof(*d));

	switch (si->cpt_code & __SI_MASK) {
	case __SI_TIMER:
		d->si_timerid	= si->cpt_pid;
		d->si_overrun	= si->cpt_uid;
		d->si_ptr	= (void *)(unsigned long)si->cpt_sigval;
		break;
	case __SI_POLL:
		d->si_band	= si->cpt_pid;
		d->si_fd	= si->cpt_uid;
		break;
	case __SI_FAULT:
		d->si_addr	= (void *)(unsigned long)si->cpt_sigval;
/*
 * Seems the kernel defines __ARCH_SI_TRAPNO for a few
 * archs but not for x86, thus leave this ifdef as is.
 */
#ifdef __ARCH_SI_TRAPNO
		d->si_trapno	= si->cpt_pid;
#endif
		break;
	case __SI_CHLD:
		d->si_pid	= si->cpt_pid;
		d->si_uid	= si->cpt_uid;
		d->si_status	= si->cpt_sigval;
		d->si_stime	= si->cpt_stime;
		d->si_utime	= si->cpt_utime;
		break;
	/*
	 * FIXME __SI_SYS ?
	 */
	case __SI_KILL:
	case __SI_RT:
	case __SI_MESGQ:
	default:
		d->si_pid	= si->cpt_pid;
		d->si_uid	= si->cpt_uid;
		d->si_ptr	= (void *)(unsigned long)si->cpt_sigval;
		break;
	}

	d->si_signo	= si->cpt_signo;
	d->si_errno	= si->cpt_errno;
	d->si_code	= si->cpt_code;
}

static int write_sigqueue(context_t *ctx, struct task_struct *t,
			  int fd, off_t start, char *queue)
{
	SiginfoEntry sie = SIGINFO_ENTRY__INIT;
	int ret = 0;

	while (start) {
		union {
			struct cpt_object_hdr		h;
			struct cpt_siginfo_image	si;
		} u;

		siginfo_t s;

		ret = read_obj_hdr(ctx->fd, &u.h, start);
		if (ret) {
			pr_err("Can't read %s sigqueue header at @%li\n",
			       queue, (long)start);
			goto err;
		}

		/* End reached */
		if (u.h.cpt_object != CPT_OBJ_SIGINFO ||
		    u.h.cpt_content != CPT_CONTENT_VOID)
			break;

		ret = read_obj_cont(ctx->fd, &u.si);
		if (ret) {
			pr_err("Can't read %s sigqueue object at @%li\n",
			       queue, (long)start);
			goto err;
		}

		encode_siginfo(&s, &u.si);
		sie.siginfo.len = sizeof(s);
		sie.siginfo.data = (void *)&s;

		ret = pb_write_one(fd, &sie, PB_SIGINFO);
		if (ret)
			goto err;

		start += u.h.cpt_next;
	}

err:
	return ret;
}

int write_signal_private_queue(context_t *ctx, struct task_struct *t)
{
	int fd = -1, ret;

	fd = open_image(ctx, CR_FD_PSIGNAL, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	ret = write_sigqueue(ctx, t, fd, t->aux_pos.off_sig_priv_pending, "private");
	close(fd);
	if (ret)
		return -1;

	return 0;
}

int write_signal_queues(context_t *ctx, struct task_struct *t)
{
	int fd = -1, ret;

	fd = open_image(ctx, CR_FD_SIGNAL, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	ret = write_sigqueue(ctx, t, fd, t->aux_pos.off_sig_share_pending, "shared");
	close(fd);
	if (ret)
		return -1;

	return write_signal_private_queue(ctx, t);
}

int write_sighandlers(context_t *ctx, struct task_struct *t)
{
	struct sighand_struct *s;
	int ret = -1, fd = -1;
	unsigned int sig;
	SaEntry e;

	s = obj_lookup_to(CPT_OBJ_SIGHAND_STRUCT, t->ti.cpt_sighand);
	if (!s) {
		pr_err("No sighandler found at @%li for task %d\n",
			(long)t->ti.cpt_sighand, t->ti.cpt_pid);
		goto err;
	}

	fd = open_image(ctx, CR_FD_SIGACT, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		goto err;

	/*
	 * Note the signal numbers coming from the OpenVZ
	 * image are started by 0 while in CRIU they are
	 * counted from 1.
	 */

	for (sig = 0; sig < ARRAY_SIZE(s->sig); sig++) {
		sa_entry__init(&e);

		/*
		 * These are always ignored from userspace.
		 */
		if (sig == (SIGKILL - 1) || sig == (SIGSTOP - 1))
			continue;

		e.sigaction	= s->sig[sig].cpt_handler;
		e.restorer	= s->sig[sig].cpt_restorer;
		e.flags		= s->sig[sig].cpt_flags;
		e.mask		= s->sig[sig].cpt_mask;

		if (pb_write_one(fd, &e, PB_SIGACT) < 0)
			goto err;
	}

	ret = 0;

err:
	close_safe(&fd);
	return ret;
}

void free_sighandlers(context_t *ctx)
{
	struct sighand_struct *s;

	while ((s = obj_pop_unhash_to(CPT_OBJ_SIGHAND_STRUCT)))
		obj_free_to(s);
}

static void show_sighand_cont(context_t *ctx, struct sighand_struct *s)
{
	unsigned int i;

	pr_debug("\t@%-8li nr-signals %d\n",
		(long)obj_of(s)->o_pos, s->nr_signals);

	for (i = 0; i < ARRAY_SIZE(s->sig); i++) {
		if (s->sig[i].cpt_handler != (u64)SIG_DFL || s->sig[i].cpt_flags) {
			pr_debug("\t\tkernel nr %3d: handler %#-16lx restorer "
				 "%#-16lx flags %#-16lx mask %#-16lx\n",
				 s->sig[i].cpt_signo,
				 (long)s->sig[i].cpt_handler,
				 (long)s->sig[i].cpt_restorer,
				 (long)s->sig[i].cpt_flags,
				 (long)s->sig[i].cpt_mask);
		}
	}
}

static int read_sighandlers(context_t *ctx, struct sighand_struct *s,
			    off_t start, off_t end)
{
	int ret = -1;

	while (start < end) {
		struct cpt_sighandler_image si;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_SIGHANDLER, &si, start)) {
			pr_err("Can't read sighandler struct at @%li\n", (long)start);
			goto err;
		}

		if (si.cpt_signo > SIGMAX) {
			pr_err("Unexpected signal number %d at @%li\n",
			       si.cpt_signo, (long)start);
			goto err;
		}

		s->sig[si.cpt_signo] = si;
		s->nr_signals++;

		start += si.cpt_next;
	}
	ret = 0;
err:
	return ret;
}

static void sighand_init(struct sighand_struct *s)
{
	BUILD_BUG_ON((void *)SIG_DFL != (void *)NULL);

	/*
	 * Init to zero means here two things:
	 *
	 * - it indeed zero all date thus we don't
	 *   have any heap trash in
	 *
	 * - zero entry means default signal handler,
	 *   note the handlers in image are optional
	 */
	memzero(s->sig, sizeof(s->sig));
	s->nr_signals = 0;
}

int read_sighand(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_read_start("signal handlers\n");
	get_section_bounds(ctx, CPT_SECT_SIGHAND_STRUCT, &start, &end);

	while (start < end) {
		struct sighand_struct *s;

		s = obj_alloc_to(struct sighand_struct, si);
		if (!s)
			goto err;
		sighand_init(s);

		if (read_obj_cpt(ctx->fd, CPT_OBJ_SIGHAND_STRUCT, &s->si, start)) {
			obj_free_to(s);
			pr_err("Can't read sighand struct at @%li\n", (long)start);
			goto err;
		}

		if (s->si.cpt_next > s->si.cpt_hdrlen) {
			if (read_sighandlers(ctx, s,
					     start + s->si.cpt_hdrlen,
					     start + s->si.cpt_next)) {
				obj_free_to(s);
				pr_err("Can't read sighandlers at @%li\n", (long)start);
				goto err;
			}
		}

		obj_push_hash_to(s, CPT_OBJ_SIGHAND_STRUCT, start);
		show_sighand_cont(ctx, s);
		start += s->si.cpt_next;
	}
	pr_read_end();

	ret = 0;
err:
	return ret;
}
