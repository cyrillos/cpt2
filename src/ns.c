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
#include "net.h"
#include "ns.h"

#include "protobuf.h"
#include "../../../protobuf/mnt.pb-c.h"

struct ns_struct *root_ns;
static int anon_dev_minor = 1;

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

static int getfstype(struct vfsmnt_struct *v)
{
	unsigned int i;

	BUILD_BUG_ON(FSTYPE__UNSUPPORTED != 0);

	if (v->mnt_type) {
		for (i = 1; i < ARRAY_SIZE(mnt_fstypes); i++) {
			if (strcmp(v->mnt_type, mnt_fstypes[i]) == 0) {
				return i;
			}
		}
	}

	return -1;
}

static int write_task_mountpoints(context_t *ctx, struct task_struct *t)
{
	int fd = fdset_fd(ctx->fdset_ns, CR_FD_MOUNTPOINTS);
	struct vfsmnt_struct *v;
	struct ns_struct *ns;
	MntEntry e;

	BUG_ON(t != root_task);

	ns = obj_lookup_to(CPT_OBJ_NAMESPACE, t->ti.cpt_namespace);
	if (!ns) {
		pr_err("Can't find namespace at @%li\n",
		       (long)t->ti.cpt_namespace);
		return -1;
	}

	list_for_each_entry(v, &ns->list, list) {
		mnt_entry__init(&e);

		e.fstype		= v->fstype;
		e.mnt_id		= obj_id_of(v);
		e.root_dev		= v->s_dev;
		e.parent_mnt_id		= (v == ns->root) ? 1 : obj_id_of(ns->root);
		e.flags			= v->vfsmnt.cpt_flags;
		e.root			= "/";
		e.mountpoint		= v->mnt_point;
		e.source		= v->mnt_dev;
		e.options		= NULL;

		if (pb_write_one(fd, &e, PB_MOUNTPOINTS))
			return -1;
	}

	return 0;
}

static int get_dev(struct vfsmnt_struct *v)
{
	struct stat st;

	/*
	 * FIXME
	 *
	 * We require only root file system being mounted
	 * at moment of conversion. If there are mount points
	 * referring to anonymous block device, such as sysfs,
	 * we need to calculate device numbers by hand.
	 */

	switch (v->fstype) {
	case FSTYPE__PROC:
	case FSTYPE__SYSFS:
	case FSTYPE__DEVTMPFS:
	case FSTYPE__TMPFS:
	case FSTYPE__SIMFS:
		BUG_ON(anon_dev_minor >= KDEV_MINORMASK);
		return MKKDEV(0, anon_dev_minor++);
	}

	if (stat(v->mnt_point, &st)) {
		pr_perror("Can't get stat on mount %s",
			  v->mnt_point);
		return -1;
	}

	return (int)st.st_dev;
}

int read_ns(context_t *ctx)
{
	struct vfsmnt_struct *v = NULL;
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
			goto free;
		}

		pos = start + h.cpt_hdrlen;
		v->mnt_dev = read_name(ctx->fd, pos, NULL, &next);
		if (IS_ERR(v->mnt_dev))
			goto free;

		pos += next;
		v->mnt_point = read_name(ctx->fd, pos, NULL, &next);
		if (IS_ERR(v->mnt_point))
			goto free;

		pos += next;
		v->mnt_type = read_name(ctx->fd, pos, NULL, &next);
		if (IS_ERR(v->mnt_type))
			goto free;

		v->fstype = getfstype(v);
		if (v->fstype < 0) {
			pr_err("Can't encode fs type %s\n", v->mnt_type);
			goto free;
		}

		v->s_dev = get_dev(v);
		if (v->s_dev < 0) {
			pr_err("Can't encode device %s\n", v->mnt_type);
			goto free;
		}

		list_add_tail(&v->list, &ns->list);
		obj_hash_to(v, start);

		show_vfsmnt_cont(ctx, v);

		if (v->mnt_point[0] == '/' && v->mnt_point[1] == '\0') {
			root_ns = ns;
			ns->root = v;
		}

		v = NULL;
	}
	ret = 0;
	pr_read_end();
out:
	return ret;

free:
	if (v) {
		if (!IS_ERR(v->mnt_dev))
			xfree(v->mnt_dev);
		if (!IS_ERR(v->mnt_point))
			xfree(v->mnt_point);
		if (!IS_ERR(v->mnt_type))
			xfree(v->mnt_type);
		obj_free_to(v);
	}
	goto out;
}

int convert_ns(context_t *ctx)
{
	int ret;

	ret = write_task_mountpoints(ctx, root_task);
	if (ret) {
		pr_err("Failed writing mountpoints for task %d\n",
		       root_task->ti.cpt_pid);
		goto out;
	}

	ret = write_netdevs(ctx);
	if (ret) {
		pr_err("Failed writing net devices for task %d\n",
		       root_task->ti.cpt_pid);
		goto out;
	}

	ret = write_ifaddr(ctx);
	if (ret) {
		pr_err("Failed writing interface addresses for task %d\n",
		       root_task->ti.cpt_pid);
		goto out;
	}

	ret = write_routes(ctx);
	if (ret) {
		pr_err("Failed writing routes for task %d\n",
		       root_task->ti.cpt_pid);
		goto out;
	}

out:
	return ret;
}
