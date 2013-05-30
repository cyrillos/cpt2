#ifndef __CPT2_EPOLL_H__
#define __CPT2_EPOLL_H__

#include <stdbool.h>

#include "cpt-image.h"
#include "context.h"
#include "types.h"
#include "files.h"
#include "list.h"

struct epoll_struct {
	struct list_head	list;
	struct hlist_node	hash;

	struct cpt_epoll_image	ei;
};

extern void free_epolls(context_t *ctx);
extern int read_epolls(context_t *ctx);
extern int write_epoll(context_t *ctx, struct file_struct *file);

#endif /* __CPT2_EPOLL_H__ */
