#ifndef __CPT2_SIG_H__
#define __CPT2_SIG_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compiler.h"
#include "context.h"
#include "task.h"
#include "obj.h"

#define SIGMAX 64

#define __SI_MASK	0xffff0000u
#define __SI_KILL	(0 << 16)
#define __SI_TIMER	(1 << 16)
#define __SI_POLL	(2 << 16)
#define __SI_FAULT	(3 << 16)
#define __SI_CHLD	(4 << 16)
#define __SI_RT		(5 << 16)
#define __SI_MESGQ	(6 << 16)
#define __SI_CODE(T,N)	((T) | ((N) & 0xffff))

struct sighand_struct {
	struct cpt_sighand_image	si;
	unsigned int			nr_signals;

	struct cpt_sighandler_image	sig[SIGMAX];
};

extern void free_sighandlers(context_t *ctx);
extern int read_sighand(context_t *ctx);
extern int write_sighandlers(context_t *ctx, struct task_struct *t);
extern int write_signal_queues(context_t *ctx, struct task_struct *t);
extern int write_signal_private_queue(context_t *ctx, struct task_struct *t);

#endif /* __CPT2_SIG_H__ */
