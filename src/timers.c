#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/time.h>

#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "timers.h"
#include "image.h"
#include "task.h"
#include "read.h"
#include "log.h"
#include "obj.h"
#include "bug.h"

#include "protobuf.h"
#include "protobuf/timer.pb-c.h"

u16 image_HZ;

static int write_posix_timers(context_t *ctx, struct task_struct *t)
{
	int fd, ret = -1;

	fd = open_image(ctx, CR_FD_POSIX_TIMERS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	if (t->ti.cpt_posix_timers != CPT_NULL) {
		union {
			struct cpt_object_hdr		h;
			struct cpt_posix_timer_image	v;
		} u;
		off_t start, end;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_POSIX_TIMER_LIST,
				 &u.h, t->ti.cpt_posix_timers)) {
			pr_err("Can't read posix timers list at @%li\n",
			       (long)t->ti.cpt_posix_timers);
			goto out;
		}

		start	= t->ti.cpt_posix_timers + u.h.cpt_hdrlen;
		end	= t->ti.cpt_posix_timers + u.h.cpt_next;

		while (start < end) {
			PosixTimerEntry pte = POSIX_TIMER_ENTRY__INIT;

			if (read_obj_cpt(ctx->fd, CPT_OBJ_POSIX_TIMER, &u.v, start)) {
				pr_err("Can't read posix timer at @%li\n", start);
				goto out;
			}

			pte.it_id		= u.v.cpt_timer_id;
			pte.clock_id		= u.v.cpt_timer_clock;
			pte.si_signo		= u.v.cpt_sigev_signo;
			pte.it_sigev_notify	= u.v.cpt_sigev_notify;
			pte.sival_ptr		= u.v.cpt_sigev_value;
			pte.overrun		= u.v.cpt_timer_overrun;
			pte.isec		= (u32)(u.v.cpt_timer_interval >> 32);
			pte.insec		= (u32)(u.v.cpt_timer_interval & 0xffffffff);
			pte.vsec		= (u32)(u.v.cpt_timer_value >> 32);
			pte.vnsec		= (u32)(u.v.cpt_timer_value & 0xffffffff);

			ret = pb_write_one(fd, &pte, PB_POSIX_TIMER);
			if (ret)
				goto out;

			start += u.v.cpt_next;
		}
	}
	ret = 0;

out:
	close(fd);
	return ret;
}

static int write_itimers(context_t *ctx, struct task_struct *t)
{
	int ret = -1, fd = -1;
	struct itimerval tv;
	ItimerEntry ie;

	fd = open_image(ctx, CR_FD_ITIMERS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	/* ITIMER_REAL */
	itimer_entry__init(&ie);

	tv.it_interval	= ns_to_timeval(t->ti.cpt_it_real_incr);
	tv.it_value	= ns_to_timeval(t->ti.cpt_it_real_value);

	ie.isec		= tv.it_interval.tv_sec;
	ie.iusec	= tv.it_interval.tv_usec;
	ie.vsec		= tv.it_value.tv_sec;
	ie.vusec	= tv.it_value.tv_usec;
	ret = pb_write_one(fd, &ie, PB_ITIMER);
	if (ret)
		goto err;

	/* ITIMER_VIRTUAL */
	itimer_entry__init(&ie);

	cputime_to_timeval(t->ti.cpt_it_virt_value, &tv.it_value);
	cputime_to_timeval(t->ti.cpt_it_virt_incr, &tv.it_interval);

	ie.isec		= tv.it_interval.tv_sec;
	ie.iusec	= tv.it_interval.tv_usec;
	ie.vsec		= tv.it_value.tv_sec;
	ie.vusec	= tv.it_value.tv_usec;
	ret = pb_write_one(fd, &ie, PB_ITIMER);
	if (ret)
		goto err;

	/* ITIMER_PROF */
	itimer_entry__init(&ie);

	cputime_to_timeval(t->ti.cpt_it_prof_value, &tv.it_value);
	cputime_to_timeval(t->ti.cpt_it_prof_incr, &tv.it_interval);

	ie.isec		= tv.it_interval.tv_sec;
	ie.iusec	= tv.it_interval.tv_usec;
	ie.vsec		= tv.it_value.tv_sec;
	ie.vusec	= tv.it_value.tv_usec;
	ret = pb_write_one(fd, &ie, PB_ITIMER);
	if (ret)
		goto err;
err:
	close_safe(&fd);
	return ret;
}

int write_timers(context_t *ctx, struct task_struct *t)
{
	return	write_itimers(ctx, t)	|
		write_posix_timers(ctx, t);
}
