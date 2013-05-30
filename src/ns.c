#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "context.h"
#include "xmalloc.h"
#include "image.h"
#include "list.h"
#include "read.h"
#include "task.h"
#include "obj.h"
#include "ns.h"

#include "protobuf.h"
#include "../../../protobuf/mnt.pb-c.h"

struct ns_struct *root_ns;

void free_ns(context_t *ctx)
{
	struct ns_struct *ns;

	while ((ns = obj_pop_unhash_to(CPT_OBJ_NAMESPACE))) {
		struct vfsmnt_struct *v, *n;

		list_for_each_entry_safe(v, n, &ns->list, list) {
			xfree(v->mnt_type);
			xfree(v->mnt_point);
			xfree(v->mnt_dev);

			obj_unhash_to(v);
			obj_free_to(v);
		}
		obj_free_to(ns);
	}
}

static void show_vfsmnt_cont(context_t *ctx, struct vfsmnt_struct *v)
{
	pr_debug("\t@%-8li dev %-32s point %-32s type %-16s\n",
		(long)obj_of(v)->o_pos, v->mnt_dev, v->mnt_point, v->mnt_type);
}

static char *mnt_fstypes[] = {
	[FSTYPE__UNSUPPORTED]	= "unsupported",
	[FSTYPE__PROC]		= "proc",
	[FSTYPE__SYSFS]		= "sysfs",
	[FSTYPE__DEVTMPFS]	= "devtmpfs",
	[FSTYPE__BINFMT_MISC]	= "binfmt_misc",
	[FSTYPE__TMPFS]		= "tmpfs",
	[FSTYPE__DEVPTS]	= "devpts",
	[FSTYPE__SIMFS]		= "simfs",
};

static int setfstype(MntEntry *e, struct vfsmnt_struct *v)
{
	unsigned int i;

	BUILD_BUG_ON(FSTYPE__UNSUPPORTED != 0);

	if (v->mnt_type) {
		for (i = 1; i < ARRAY_SIZE(mnt_fstypes); i++) {
			if (strcmp(v->mnt_type, mnt_fstypes[i]) == 0) {
				e->fstype = i;
				return 0;
			}
		}
	}

	return -1;
}

int write_task_mountpoints(context_t *ctx, struct task_struct *t)
{
	struct vfsmnt_struct *v;
	struct ns_struct *ns;
	MntEntry e;

	int ret = 0;
	int fd = -1;

	fd = open_image(ctx, CR_FD_MOUNTPOINTS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	ns = obj_lookup_to(CPT_OBJ_NAMESPACE, t->ti.cpt_namespace);
	if (!ns) {
		pr_err("Can't find namespace at @%li\n",
		       (long)t->ti.cpt_namespace);
		return -1;
	}

	list_for_each_entry(v, &ns->list, list) {
		mnt_entry__init(&e);

		if (setfstype(&e, v)) {
			pr_err("Can't encode fs type %s\n", v->mnt_type);
			goto out;
		}

		e.mnt_id		= obj_id_of(v);
		e.root_dev		= v->s_dev;
		e.parent_mnt_id		= (v == ns->root) ? 1 : obj_id_of(ns->root);
		e.flags			= v->vfsmnt.cpt_flags;
		e.root			= "/";
		e.mountpoint		= v->mnt_point;
		e.source		= v->mnt_dev;
		e.options		= NULL;

		ret = pb_write_one(fd, &e, PB_MOUNTPOINTS);
		if (ret)
			goto out;
	}

out:
	close_safe(&fd);
	return ret;
}

int read_ns(context_t *ctx)
{
	struct cpt_object_hdr h;
	struct ns_struct *ns;

	off_t start, end;
	int ret = -1;

	pr_read_start("namespace\n");
	get_section_bounds(ctx, CPT_SECT_NAMESPACE, &start, &end);

	ns = obj_alloc_to(struct ns_struct, nsi);
	if (!ns)
		return -1;
	INIT_LIST_HEAD(&ns->list);

	if (read_obj_cpt(ctx->fd, CPT_OBJ_NAMESPACE, &ns->nsi, start))
		goto out;
	obj_push_hash_to(ns, CPT_OBJ_NAMESPACE, start);

	for (start += ns->nsi.cpt_hdrlen; start < end; start += h.cpt_next) {
		struct vfsmnt_struct *v;
		struct stat st;
		off_t pos, next;

		if (read_obj_hdr(ctx->fd, &h, start)) {
			pr_err("Can't read header in NS at %li\n", (long)start);
			goto out;
		}

		if (h.cpt_object != CPT_OBJ_VFSMOUNT)
			continue;

		v = obj_alloc_to(struct vfsmnt_struct, vfsmnt);
		if (!v)
			return -1;
		INIT_LIST_HEAD(&v->list);
		v->mnt_dev = v->mnt_point = v->mnt_type = NULL;
		memcpy(&v->vfsmnt, &h, sizeof(h));

		if (read_obj_cont(ctx->fd, &v->vfsmnt)) {
			pr_err("Can't read vfsmount payload at %li\n", (long)start);
			goto out;
		}

		pos = start + h.cpt_hdrlen;
		v->mnt_dev = read_name(ctx->fd, pos, &next);
		if (IS_ERR(v->mnt_dev)) {
			obj_free_to(v);
			goto out;
		}

		pos += next;
		v->mnt_point = read_name(ctx->fd, pos, &next);
		if (IS_ERR(v->mnt_point)) {
			xfree(v->mnt_dev);
			obj_free_to(v);
			goto out;
		}

		pos += next;
		v->mnt_type = read_name(ctx->fd, pos, &next);
		if (IS_ERR(v->mnt_type)) {
			xfree(v->mnt_dev);
			xfree(v->mnt_point);
			obj_free_to(v);
			goto out;
		}

		if (stat(v->mnt_point, &st)) {
			pr_perror("Can't get stat on mount %s",
				  v->mnt_point);
			xfree(v->mnt_dev);
			xfree(v->mnt_point);
			xfree(v->mnt_type);
			obj_free_to(v);
			goto out;
		}

		v->s_dev = st.st_dev;

		list_add_tail(&v->list, &ns->list);
		obj_hash_to(v, start);

		show_vfsmnt_cont(ctx, v);

		if (v->mnt_point[0] == '/' && v->mnt_point[1] == '\0') {
			root_ns = ns;
			ns->root = v;
		}
	}
	ret = 0;
	pr_read_end();
out:
	return ret;
}
