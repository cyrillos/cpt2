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

#include "cr-show.h"

#define GEN_SHOW_STUB(name)	void name(int fd) { }

void show_fown_cont(void *p) { }

GEN_SHOW_STUB(show_files);
GEN_SHOW_STUB(show_pagemap);
GEN_SHOW_STUB(show_reg_files);
GEN_SHOW_STUB(show_ns_files);
GEN_SHOW_STUB(show_core);
GEN_SHOW_STUB(show_ids);
GEN_SHOW_STUB(show_mm);
GEN_SHOW_STUB(show_vmas);
GEN_SHOW_STUB(show_pipes);
GEN_SHOW_STUB(show_pipes_data);
GEN_SHOW_STUB(show_fifo);
GEN_SHOW_STUB(show_fifo_data);
GEN_SHOW_STUB(show_pstree);
GEN_SHOW_STUB(show_sigacts);
GEN_SHOW_STUB(show_siginfo);
GEN_SHOW_STUB(show_itimers);
GEN_SHOW_STUB(show_creds);
GEN_SHOW_STUB(show_fs);
GEN_SHOW_STUB(show_remap_files);
GEN_SHOW_STUB(show_ghost_file);
GEN_SHOW_STUB(show_eventfds);
GEN_SHOW_STUB(show_tty);
GEN_SHOW_STUB(show_tty_info);
GEN_SHOW_STUB(show_file_locks);
GEN_SHOW_STUB(show_rlimit);
GEN_SHOW_STUB(show_inventory);
GEN_SHOW_STUB(show_raw_image);
GEN_SHOW_STUB(show_eventpoll);
GEN_SHOW_STUB(show_eventpoll_tfd);
GEN_SHOW_STUB(show_signalfd);
GEN_SHOW_STUB(show_inotify);
GEN_SHOW_STUB(show_inotify_wd);
GEN_SHOW_STUB(show_fanotify);
GEN_SHOW_STUB(show_fanotify_mark);
GEN_SHOW_STUB(show_unixsk);
GEN_SHOW_STUB(show_inetsk);
GEN_SHOW_STUB(show_packetsk);
GEN_SHOW_STUB(show_netlinksk);
GEN_SHOW_STUB(show_sk_queues);
GEN_SHOW_STUB(show_utsns);
GEN_SHOW_STUB(show_ipc_var);
GEN_SHOW_STUB(show_ipc_shm);
GEN_SHOW_STUB(show_ipc_msg);
GEN_SHOW_STUB(show_ipc_sem);
GEN_SHOW_STUB(show_tcp_stream);
GEN_SHOW_STUB(show_mountpoints);
GEN_SHOW_STUB(show_netdevices);
GEN_SHOW_STUB(show_stats);

int open_image(context_t *ctx, int type, int flags, ...)
{
	char path[PATH_MAX];
	va_list args;
	int ret = -1;

	BUG_ON(type >= CR_FD_MAX);
	BUG_ON(flags == O_RDONLY);

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
