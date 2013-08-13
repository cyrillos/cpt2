#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>

#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "files.h"
#include "image.h"
#include "epoll.h"
#include "read.h"
#include "log.h"
#include "obj.h"

#include "protobuf.h"
#include "protobuf/eventpoll.pb-c.h"

#define EPOLL_HASH_BITS		10
static DEFINE_HASHTABLE(epoll_hash, EPOLL_HASH_BITS);
static LIST_HEAD(epoll_list);

struct epoll_struct *epoll_lookup_file(u64 cpt_file)
{
	struct epoll_struct *epoll;

	hash_for_each_key(epoll_hash, epoll, hash, cpt_file) {
		if (epoll->ei.cpt_file == cpt_file)
			return epoll;
	}

	return NULL;
}

void free_epolls(context_t *ctx)
{
	struct epoll_struct *epoll, *t;

	list_for_each_entry_safe(epoll, t, &epoll_list, list) {
		obj_unhash_to(epoll);
		obj_free_to(epoll);
	}
}

static int write_epoll_tfds(context_t *ctx, struct file_struct *file, struct epoll_struct *epoll)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_EVENTPOLL_TFD);
	EventpollTfdEntry efd = EVENTPOLL_TFD_ENTRY__INIT;
	struct cpt_epoll_file_image efi;
	off_t start, end;
	int ret = -1;

	start	= obj_pos_of(epoll) + epoll->ei.cpt_hdrlen;
	end	= obj_pos_of(epoll) + epoll->ei.cpt_next;

	for (; start < end; start += efi.cpt_next) {
		if (read_obj_cpt(ctx->fd, CPT_OBJ_EPOLL_FILE, &efi, start)) {
			pr_err("Can't read epoll fd at @%li\n", (long)start);
			goto err;
		}

		efd.id		= obj_id_of(file);
		efd.tfd		= efi.cpt_fd;
		efd.events	= efi.cpt_events;
		efd.data	= efi.cpt_data;

		ret = pb_write_one(fd, &efd, PB_EVENTPOLL_TFD);
		if (ret)
			goto err;
	}
	ret = 0;
err:
	return ret;
}

int write_epoll(context_t *ctx, struct file_struct *file)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_EVENTPOLL);
	EventpollFileEntry e = EVENTPOLL_FILE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	struct epoll_struct *epoll;
	int ret = -1;

	if (file->dumped)
		return 0;

	epoll = epoll_lookup_file(obj_pos_of(file));
	BUG_ON(!epoll);

	fill_fown(&fown, file);

	e.id		= obj_id_of(file);
	e.flags		= file->fi.cpt_flags;
	e.fown		= (FownEntry *)&fown;

	ret = pb_write_one(fd, &e, PB_EVENTPOLL);
	if (!ret) {
		ret = write_epoll_tfds(ctx, file, epoll);
		file->dumped = 1;
	}

	return ret;
}

static void show_epoll_cont(context_t *ctx, struct epoll_struct *epoll)
{
	pr_debug("\t@%-10li file @%-10li\n",
		 obj_pos_of(epoll), (long)epoll->ei.cpt_file);
}

int read_epolls(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_read_start("epoll\n");
	get_section_bounds(ctx, CPT_SECT_EPOLL, &start, &end);

	while (start < end) {
		struct epoll_struct *epoll;

		epoll = obj_alloc_to(struct epoll_struct, ei);
		if (!epoll)
			goto out;

		INIT_HLIST_NODE(&epoll->hash);
		INIT_LIST_HEAD(&epoll->list);

		if (read_obj_cpt(ctx->fd, CPT_OBJ_EPOLL, &epoll->ei, start)) {
			obj_free_to(epoll);
			pr_err("Can't read epoll object at @%li\n", (long)start);
			goto out;
		}

		hash_add(epoll_hash, &epoll->hash, epoll->ei.cpt_file);
		list_add_tail(&epoll->list, &epoll_list);
		obj_hash_typed_to(epoll, CPT_OBJ_EPOLL, start);

		start += epoll->ei.cpt_next;
		show_epoll_cont(ctx, epoll);
	}
	pr_read_end();
	ret = 0;
out:
	return ret;
}
