#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include "compiler.h"
#include "context.h"
#include "xmalloc.h"
#include "image.h"
#include "types.h"
#include "io.h"

int context_init_fdset_glob(context_t *ctx)
{
	struct fdset *fdset;

	fdset = fdset_alloc(_CR_FD_GLOB_FROM,
			    _CR_FD_GLOB_TO - _CR_FD_GLOB_FROM);
	if (!fdset) {
		pr_err("Can't allocate glob fdset\n");
		return -1;
	}
	ctx->fdset_glob = fdset;

	if (open_image_fdset(ctx, fdset, -1,
			     _CR_FD_GLOB_FROM,
			     _CR_FD_GLOB_TO, O_DUMP)) {
		pr_err("Failed to open glob fdset\n");
		return -1;
	}

	return 0;
}

int context_init_fdset_ns(context_t *ctx, pid_t pid)
{
	struct fdset *fdset;

	context_fini_fdset_ns(ctx);

	fdset = fdset_alloc(_CR_FD_NETNS_FROM,
			    _CR_FD_NETNS_TO - _CR_FD_NETNS_FROM);
	if (!fdset) {
		pr_err("Can't allocate ns fdset\n");
		return -1;
	}
	ctx->fdset_ns = fdset;

	if (open_image_fdset(ctx, fdset, pid,
			     _CR_FD_NETNS_FROM,
			     _CR_FD_NETNS_TO, O_DUMP)) {
		pr_err("Failed to open ns fdset\n");
		return -1;
	}

	return 0;
}

void context_fini_fdset_glob(context_t *ctx)
{
	fdset_free(&ctx->fdset_glob);
}

void context_fini_fdset_ns(context_t *ctx)
{
	fdset_free(&ctx->fdset_ns);
}

void context_init(context_t *ctx)
{
	memzero(ctx, sizeof(*ctx));
	ctx->fd = ctx->dfd = ctx->rootfd = -1;
}

void context_fini(context_t *ctx)
{
	close_safe(&ctx->fd);
	close_safe(&ctx->dfd);
	close_safe(&ctx->rootfd);
	context_fini_fdset_glob(ctx);
	context_fini_fdset_ns(ctx);
}
