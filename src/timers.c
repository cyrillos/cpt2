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
#include "protobuf/itimer.pb-c.h"

u16 image_HZ;


/*
 * FIXME The task image refers to cpt_posix_timer_image list
 *       which is not yet covered neither in cpt2 or criu itself.
 */

void free_timers(context_t *ctx)
{
	/* FIXME stub */
}

int read_timers(context_t *ctx)
{
	/* FIXME stub */
	return 0;
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
	ret = pb_write_one(fd, &ie, PB_ITIMERS);
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
	ret = pb_write_one(fd, &ie, PB_ITIMERS);
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
	ret = pb_write_one(fd, &ie, PB_ITIMERS);
	if (ret)
		goto err;
err:
	close_safe(&fd);
	return ret;
}

int write_timers(context_t *ctx, struct task_struct *t)
{
	int ret;

	ret = write_itimers(ctx, t);

	return ret;
}
