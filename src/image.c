#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/limits.h>

#include "compiler.h"
#include "image.h"
#include "bug.h"
#include "io.h"

int open_image(context_t *ctx, int type, int flags, ...)
{
	char path[PATH_MAX];
	va_list args;
	int ret = -1;

	BUG_ON(type >= CR_FD_MAX);
	BUG_ON(flags == O_RDONLY);

	/*
	 * Just return some value which
	 * is not an error.
	 */
	if (io_read_only)
		return 0;

	va_start(args, flags);
	vsnprintf(path, PATH_MAX, fdset_template[type].fmt, args);
	va_end(args);

	if (flags & O_EXCL) {
		ret = unlinkat(ctx->dfd, path, 0);
		if (ret && errno != ENOENT) {
			pr_perror("Unable to unlink %s", path);
			return -1;
		}
	}

	ret = openat(ctx->dfd, path, flags, CR_FD_PERM);
	if (ret < 0) {
		pr_perror("Unable to open %s", path);
		goto err;
	}

	if (fdset_template[type].magic == RAW_IMAGE_MAGIC)
		goto skip_magic;

	if (write_img(ret, &fdset_template[type].magic))
		goto err;

skip_magic:
	return ret;
err:
	close_safe(&ret);
	return -1;
}

int open_image_fdset(context_t *ctx, struct fdset *fdset, pid_t pid,
		     unsigned int from, unsigned int to, int flags)
{
	unsigned int i;
	int ret;

	for (i = from + 1; i < to; i++) {
		ret = open_image(ctx, i, flags, pid);
		if (ret < 0) {
			if (!(flags & O_CREAT))
				/* caller should check himself */
				continue;
			goto err;
		}
		*fdset_fd_ptr(fdset, i) = ret;
	}

	return 0;

err:
	return -1;
}
