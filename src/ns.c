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
#include "protobuf/mnt.pb-c.h"
#include "protobuf/utsns.pb-c.h"
#include "protobuf/ipc-var.pb-c.h"
#include "protobuf/ipc-shm.pb-c.h"
#include "protobuf/ipc-sem.pb-c.h"
#include "protobuf/ipc-msg.pb-c.h"

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
	pr_debug("\t@%-10li dev %-32s point %-32s type %-16s\n",
		obj_pos_of(v), v->mnt_dev, v->mnt_point, v->mnt_type);
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

static int write_ns_mountpoints(context_t *ctx, struct task_struct *t)
{
	int fd = fdset_fd(ctx->fdset_ns, CR_FD_MNTS);
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

		if (pb_write_one(fd, &e, PB_MNT))
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

static int write_ns_ipc_sem(context_t *ctx, struct task_struct *t)
{
	IpcDescEntry desc = IPC_DESC_ENTRY__INIT;
	IpcSemEntry sem = IPC_SEM_ENTRY__INIT;
	int ret = -1, fd = -1;
	off_t start, end;

	fd = open_image(ctx, CR_FD_IPCNS_SEM, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	sem.desc = &desc;

	/*
	 * FIXME In CRIU no CPT_SECT_SYSVSEM_UNDO implemented, must
	 * be addressed later.
	 */

	get_section_bounds(ctx, CPT_SECT_SYSV_SEM, &start, &end);
	while (start < end) {
		struct cpt_sysvsem_image v;
		struct sem_pair {
			u32	semval;
			u32	sempid;
		} s;
		u16 value;
		off_t at;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_SYSV_SEM, &v, start)) {
			pr_err("Can't read SysV semaphore at @%li\n", start);
			goto err;
		}

		at = start + v.cpt_hdrlen;
		sem.nsems = (v.cpt_next - v.cpt_hdrlen) / sizeof(s);

		/*
		 * FIXME Why @cpt_seq, @cpt_otime and @cpt_ctime
		 * are not present in CRIU?
		 *
		 * Sametime note the new kernel has no @sempid
		 * member but an array of values.
		 */
		desc.key	= v.cpt_key;
		desc.uid	= v.cpt_uid;
		desc.gid	= v.cpt_gid;
		desc.cuid	= v.cpt_cuid;
		desc.cgid	= v.cpt_cgid;
		desc.mode	= v.cpt_mode;
		desc.id		= v.cpt_id;

		if (pb_write_one(fd, &sem, PB_IPC_SEM)) {
			pr_err("Failed to write IPC semaphore descriptor at @%li\n", start);
			goto err;
		}

		start += v.cpt_next;

		/*
		 * Make sure the ctx->fd is at right position, don't
		 * insert new io operations here.
		 */

		while (at < start) {
			if (__read_ptr_at(ctx->fd, &s, at)) {
				pr_err("Failed to read IPC semaphore value at @%li\n", at);
				goto err;
			}
			value = s.semval;
			if (__write_ptr(fd, &value)) {
				pr_err("Failed to write IPC semaphore value from @%li\n", at);
				goto err;
			}

			at += sizeof(s);
		}

		if (sem.nsems) {
			u8 pad[sizeof(u64)] = { };
			size_t left;
			left  = round_up((sem.nsems * sizeof(value)), sizeof(u64));
			left -= (sem.nsems * sizeof(value));

			BUG_ON(left > sizeof(pad));

			if (__write(fd, pad, left)) {
				pr_err("Failed to write IPC semaphore value pad\n");
				goto err;
			}
		}
	}

	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int write_ns_ipc_var(context_t *ctx, struct task_struct *t)
{
	IpcVarEntry var = IPC_VAR_ENTRY__INIT;
	int ret = -1, fd = -1;
	off_t start, end;

	fd = open_image(ctx, CR_FD_IPC_VAR, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	get_section_bounds(ctx, CPT_SECT_VEINFO, &start, &end);
	while (start < end) {
		struct cpt_veinfo_image v;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_VEINFO, &v, start)) {
			pr_err("Can't read veinfo at @%li\n", start);
			goto err;
		}

		BUILD_BUG_ON(ARRAY_SIZE(v.sem_ctl_arr) != 4);

		/*
		 * FIXME There is no @auto_msgmni, @shm_rmid_forced,
		 * @mq_queues_max, @mq_msg_max, @mq_msgsize_max in the
		 * OpenVZ image.
		 */

		var.n_sem_ctls		= ARRAY_SIZE(v.sem_ctl_arr);
		var.sem_ctls		= v.sem_ctl_arr;
		var.msg_ctlmax		= v.msg_ctl_max;
		var.msg_ctlmnb		= v.msg_ctl_mnb;
		var.msg_ctlmni		= v.msg_ctl_mni;
		var.shm_ctlmax		= v.shm_ctl_max;
		var.shm_ctlall		= v.shm_ctl_all;
		var.shm_ctlmni		= v.shm_ctl_mni;

		ret = pb_write_one(fd, &var, PB_IPC_VAR);
		if (ret < 0) {
			pr_err("Failed to write IPC variables\n");
			goto err;
		}

		break;
	}
	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int write_ns_ipc_msg(context_t *ctx, struct task_struct *t)
{
	IpcDescEntry desc = IPC_DESC_ENTRY__INIT;
	IpcMsgEntry msg = IPC_MSG_ENTRY__INIT;
	int ret = -1, fd = -1;
	off_t start, end;
	size_t msg_qnum = 0;

	fd = open_image(ctx, CR_FD_IPCNS_MSG, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	msg.desc = &desc;

	get_section_bounds(ctx, CPT_SECT_SYSV_MSG, &start, &end);
	while (start < end) {
		struct cpt_sysvmsg_image v;
		off_t at;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_SYSVMSG, &v, start)) {
			pr_err("Can't read SysV message at @%li\n", start);
			goto err;
		}

		/*
		 * FIXME No @qnum in OpenVZ, just do seq increments.
		 */

		msg.qbytes = v.cpt_qbytes;
		msg.qnum = msg_qnum++;

		/*
		 * FIXME @cpt_stime, @cpt_rtime, @cpt_ctime,
		 * @cpt_last_sender, @cpt_last_receiver are
		 * not present in criu, why?
		 */

		desc.key	= v.cpt_key;
		desc.uid	= v.cpt_uid;
		desc.gid	= v.cpt_gid;
		desc.cuid	= v.cpt_cuid;
		desc.cgid	= v.cpt_cgid;
		desc.mode	= v.cpt_mode;
		desc.id		= v.cpt_id;

		if (pb_write_one(fd, &msg, PB_IPCNS_MSG_ENT))
			goto err;

		at = start + v.cpt_hdrlen;
		start += v.cpt_next;

		while (at < start) {
			struct cpt_sysvmsg_msg_image i;
			IpcMsg m = IPC_MSG__INIT;
			size_t size;

			if (read_obj_cpt(ctx->fd, CPT_OBJ_SYSVMSG_MSG, &i, at)) {
				pr_err("Can't read SysV message header at @%li\n", at);
				goto err;
			}

			size = i.cpt_next - i.cpt_hdrlen;
			m.msize = i.cpt_size;
			m.mtype = i.cpt_type;

			if (pb_write_one(fd, &m, PB_IPCNS_MSG))
				goto err;

			if (size) {
				u8 pad[sizeof(u64)] = { };
				size_t left = round_up(size, sizeof(u64)) - size;

				if (splice_data(ctx->fd, fd, size)) {
					pr_err("Can't splice SysV message data at @%li\n", at);
					goto err;
				}

				BUG_ON(left > sizeof(pad));
				if (__write(fd, pad, left)) {
					pr_err("Failed to write SysV message data pad\n");
					goto err;
				}
			}

			at += i.cpt_next;
		}
	}

	ret = 0;
err:
	close_safe(&fd);
	return ret;
}

static int write_ns_ipc(context_t *ctx, struct task_struct *t)
{
	int ret = -1;
	int fd_ipc_shm = -1;

	/*
	 * FIXME IPC conversion known to be buggy on OpenVZ behalf,
	 * need to revisit it.
	 */

	fd_ipc_shm = open_image(ctx, CR_FD_IPCNS_SHM, O_DUMP, t->ti.cpt_pid);
	if (fd_ipc_shm < 0)
		goto out;

	ret  = write_ns_ipc_sem(ctx, t);
	ret |= write_ns_ipc_var(ctx, t);
	ret |= write_ns_ipc_msg(ctx, t);
out:
	close_safe(&fd_ipc_shm);
	return ret;
}

static int write_ns_utsns(context_t *ctx, struct task_struct *t)
{
	UtsnsEntry ue = UTSNS_ENTRY__INIT;
	int ret = -1, fd = -1, pos = 0;
	off_t start, end, next;

	fd = open_image(ctx, CR_FD_UTSNS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	get_section_bounds(ctx, CPT_SECT_UTSNAME, &start, &end);
	while (start < end) {
		char *name;

		name = read_name(ctx->fd, start, NULL, &next);
		if (!name) {
			pr_err("Can't read UTS string at @%li\n", start);
			goto err;
		}

		switch (pos) {
		case 0:
			ue.nodename = name;
			break;
		case 1:
			ue.domainname = name;
			break;
		case 2:
			/* We don't care about release */
			goto out;
			break;
		}

		start += next;
		pos++;
	}
out:
	ret = pb_write_one(fd, &ue, PB_UTSNS);
	xfree(ue.nodename);
	xfree(ue.domainname);
err:
	close_safe(&fd);
	return ret;
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
			pr_err("Can't read header in NS at @%li\n", (long)start);
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
			pr_err("Can't read vfsmount payload at @%li\n", (long)start);
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

	ret = write_ns_mountpoints(ctx, root_task);
	if (ret) {
		pr_err("Failed writing mountpoints for task %d\n",
		       root_task->ti.cpt_pid);
		goto out;
	}

	ret = write_ns_utsns(ctx, root_task);
	if (ret) {
		pr_err("Failed writing utsns for task %d\n",
		       root_task->ti.cpt_pid);
		goto out;
	}

	ret = write_ns_ipc(ctx, root_task);
	if (ret) {
		pr_err("Failed writing ipc for task %d\n",
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
