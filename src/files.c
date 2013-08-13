#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <linux/major.h>

#include "cpt-image.h"
#include "fsnotify.h"
#include "signalfd.h"
#include "compiler.h"
#include "magicfs.h"
#include "xmalloc.h"
#include "socket.h"
#include "files.h"
#include "image.h"
#include "epoll.h"
#include "task.h"
#include "read.h"
#include "log.h"
#include "net.h"
#include "tty.h"
#include "obj.h"
#include "bug.h"

#include "protobuf.h"
#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/signalfd.pb-c.h"
#include "protobuf/file-lock.pb-c.h"
#include "protobuf/regfile.pb-c.h"
#include "protobuf/eventfd.pb-c.h"
#include "protobuf/pipe.pb-c.h"
#include "protobuf/fifo.pb-c.h"
#include "protobuf/pipe-data.pb-c.h"
#include "protobuf/fs.pb-c.h"
#include "protobuf/remap-file-path.pb-c.h"
#include "protobuf/ghost-file.pb-c.h"

/*
 * Here some notes on which kind of data inode payload may have
 *
 * - CPT_OBJ_SYSV_SHM in case of sysv shared mapping, then there
 *   go pages of memory
 * - CPT_OBJ_REF for char devices such as tty
 * - CPT_OBJ_BITS for pipe/fifo buffered data
 * - unlinked NFS is a separate case which I don't consider here
 * - ref to another file name (path), not considered here
 * - deleted regular files are a bit tricky
 *   - it can be a name to another file name, ie CPT_OBJ_NAME,
 *     I've not yet met situation where it is needed
 *   - deleted regular file without additional links to it,
 *     iow ghost file in terms of criu -- then inode payload
 *     is file content by pages
 *   - deleted regular file _with_ additional links to it, ie
 *     remapped in terms of criu, then there is CPT_OBJ_NAME
 *     for unlinked dentry (or harlink name and inode gets
 *     CPT_INODE_HARDLINKED o_flag) but no additional content
 *     present, iow it's remapped path in terms of criu
 */

#define __gen_lflag_entry(postfix)			\
	{						\
		.name	= __stringify_1(postfix),	\
		.flag	= CPT_DENTRY_ ##postfix,	\
	}

static struct {
	char	*name;
	int	flag;
} file_lflags_map[] = {
	__gen_lflag_entry(DELETED),
	__gen_lflag_entry(ROOT),
	__gen_lflag_entry(CLONING),
	__gen_lflag_entry(PROC),
	__gen_lflag_entry(EPOLL),
	__gen_lflag_entry(REPLACED),
	__gen_lflag_entry(INOTIFY),
	__gen_lflag_entry(FUTEX),
	__gen_lflag_entry(TUNTAP),
	__gen_lflag_entry(PROCPID_DEAD),
	__gen_lflag_entry(HARDLINKED),
	__gen_lflag_entry(SIGNALFD),
	__gen_lflag_entry(TIMERFD),
	__gen_lflag_entry(EVENTFD),
	__gen_lflag_entry(SILLYRENAME),
};

#undef __gen_lflag_entry

static int get_file_type(FdinfoEntry *e, struct file_struct *file)
{
	u32 lflags = file->fi.cpt_lflags;

	/*
	 * At first look at local flags.
	 */
	if (lflags & CPT_DENTRY_EPOLL) {
		e->type = FD_TYPES__EVENTPOLL;
		return 0;
	} else if (lflags & CPT_DENTRY_INOTIFY) {
		e->type = FD_TYPES__INOTIFY;
		return 0;
	} else if (lflags & CPT_DENTRY_SIGNALFD) {
		e->type = FD_TYPES__SIGNALFD;
		return 0;
	} else if (lflags & CPT_DENTRY_TIMERFD) {
		pr_err("Unsupported timerfd file\n");
		return -1;
	} else if (lflags & CPT_DENTRY_EVENTFD) {
		e->type = FD_TYPES__EVENTFD;
		return 0;
	}

	/*
	 * In most cases the upper code should handle all
	 * possible data, still if failed, lets deal with
	 * a name.
	 */

	if (!file->name)
		return -1;

	if (strcmp(file->name, "inotify") == 0) {
		e->type = FD_TYPES__INOTIFY;
		return 0;
	} else if (strncmp(file->name, "anon_inode:", 11) == 0) {
		if (strncmp(&file->name[11], "[fanotify]", 10) == 0) {
			e->type = FD_TYPES__FANOTIFY;
			return 0;
		} else if (strncmp(&file->name[11], "[eventpoll]", 11) == 0) {
			e->type = FD_TYPES__EVENTPOLL;
			return 0;
		} else if (strncmp(&file->name[11], "[eventfd]", 9) == 0) {
			e->type = FD_TYPES__EVENTFD;
			return 0;
		} else if (strncmp(&file->name[11], "[signalfd]", 10) == 0) {
			e->type = FD_TYPES__SIGNALFD;
			return 0;
		}
	} else if (S_ISREG(file->fi.cpt_i_mode)) {
		e->type = FD_TYPES__REG;
		return 0;
	}
	return -1;
}

static int set_fdinfo_type(FdinfoEntry *e, struct file_struct *file,
			   struct inode_struct *inode)
{

	/*
	 * Notifiers requires own lookup :(
	 */
	if (inotify_lookup_file(obj_pos_of(file))) {
		e->type = FD_TYPES__INOTIFY;
		return 0;
	}

	if (S_ISSOCK(file->fi.cpt_i_mode)) {
		struct sock_struct *sk;

		sk = sk_lookup_file(obj_pos_of(file));
		if (!sk) {
			pr_err("Can't find socket for @%li\n",
			       obj_pos_of(file));
			return -1;
		}
		switch (sk->si.cpt_family) {
		case PF_INET:
		case PF_INET6:
			e->type = FD_TYPES__INETSK;
			break;
		case PF_UNIX:
			e->type = FD_TYPES__UNIXSK;
			break;
		case PF_NETLINK:
			e->type = FD_TYPES__NETLINKSK;
			break;
		case PF_PACKET:
			e->type = FD_TYPES__PACKETSK;
			break;
		default:
			pr_err("File at @%li with unsupported sock family %d\n",
			       obj_pos_of(file), (int)sk->si.cpt_family);
			return -1;
		}
	} else if (S_ISCHR(file->fi.cpt_i_mode)) {
		if (!inode) {
			pr_err("Character file without inode at @%li\n",
			       obj_pos_of(file));
			return -1;
		}
		switch (kdev_major(inode->ii.cpt_rdev)) {
		case MEM_MAJOR:
			e->type = FD_TYPES__REG;
			break;
		case TTYAUX_MAJOR:
		case UNIX98_PTY_MASTER_MAJOR ... (UNIX98_PTY_MASTER_MAJOR + UNIX98_PTY_MAJOR_COUNT - 1):
		case UNIX98_PTY_SLAVE_MAJOR:
			e->type = FD_TYPES__TTY;
			break;
		default:
			pr_err("Character file with maj %d inode at @%li\n",
			       major(inode->ii.cpt_rdev), obj_pos_of(file));
			return -1;
		}
	} else if (S_ISDIR(file->fi.cpt_i_mode)) {
		e->type = FD_TYPES__REG;
	} else if (S_ISFIFO(file->fi.cpt_i_mode)) {
		if (!inode) {
			pr_err("Fifo file without inode at @%li\n",
			       obj_pos_of(file));
			return -1;
		}
		if (inode->ii.cpt_sb == PIPEFS_MAGIC)
			e->type = FD_TYPES__PIPE;
		else
			e->type = FD_TYPES__FIFO;
	} else {
		if (get_file_type(e, file) == 0)
			return 0;

		pr_err("File with unknown type at @%li\n", obj_pos_of(file));
		return -1;
	}

	return 0;
}

static int dump_remaped_file(context_t *ctx, struct file_struct *file,
			     struct inode_struct *inode)
{
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;

	bool hardlinked = !!(file->fi.cpt_lflags & CPT_DENTRY_HARDLINKED);
	int remap_fd = fdset_fd(ctx->fdset_glob, CR_FD_REMAP_FPATH);
	char namebuf[PATH_MAX], *_link = NULL;
	int ret = -1;

	if (!inode->u.dumped_remap) {
		RegFileEntry rfe = REG_FILE_ENTRY__INIT;
		FownEntry fown = FOWN_ENTRY__INIT;

		int regfile_fd = fdset_fd(ctx->fdset_glob, CR_FD_REG_FILES);
		off_t where = obj_pos_of(inode) + inode->ii.cpt_hdrlen;

		char *name = NULL;

		if (inode->ii.cpt_next <= inode->ii.cpt_hdrlen) {
			pr_err("Expected to find a name at @%li\n",
			       obj_pos_of(inode));
			return -1;
		}

		/*
		 * OpenVZ handles links in two ways
		 *  1 if a link name present in dcache, then we got it here as
		 *    a link name
		 *  2 if no name present in dcache we get a hardlink name
		 *
		 * It's more trickier as it sounds. For (1) we need to create
		 * own link to former link, because criu deletes link on restore
		 * if path remap found. But for hardlink in (2) we don't need to form
		 * a new link since it's generated by openvz kernel by itself.
		 */

		name = read_name(ctx->fd, where, NULL, NULL);
		if (!name) {
			pr_err("Failed to read a %s name at @%li\n",
			       hardlinked ? "hardlink" : "link",
			       obj_pos_of(inode));
			return -1;
		}

		if (!hardlinked) {
			/*
			 * We need to create own link here.
			 */
			snprintf(namebuf, sizeof(namebuf), "%s.link_remap.%d", name, obj_id_of(inode));
			if (linkat(ctx->rootfd, &name[1], ctx->rootfd, &namebuf[1], 0) < 0) {
				pr_perror("Can't link remap %s -> %s", name, namebuf);
				xfree(name);
				return -1;
			}

			_link = namebuf;
		}

		rfe.id		= obj_id_of(inode);
		rfe.fown	= &fown;
		rfe.name	= _link ? _link : name;

		ret = pb_write_one(regfile_fd, &rfe, PB_REG_FILES);
		xfree(name);

		if (ret)
			goto err;

		inode->u.dumped_remap = true;
	}

	rpe.orig_id	= obj_id_of(file);
	rpe.remap_id	= obj_id_of(inode);

	ret = pb_write_one(remap_fd, &rpe, PB_REMAP_FPATH);
err:
	return ret;
}

static int dump_ghost_file_content(context_t *ctx, int fd,
				   struct file_struct *file,
				   struct inode_struct *inode)
{
	union {
		struct cpt_object_hdr		h;
		struct cpt_page_block		pb;
	} u;

	unsigned long nr_pages, i;
	off_t start, end;
	int ret = -1;

	start	= obj_pos_of(inode) + inode->ii.cpt_hdrlen;
	end	= obj_pos_of(inode) + inode->ii.cpt_next;

	/*
	 * FIXME Somehow unify with write_page_block routine?
	 */
	for (; start < end; start += u.h.cpt_next) {
		if (read_obj_cpt(ctx->fd, OBJ_ANY, &u.h, start)) {
			pr_err("Can't read page header at @%li\n", (long)start);
			goto err;
		}

		switch (u.h.cpt_object) {
		case CPT_OBJ_PAGES:
			if (read_obj_cont(ctx->fd, &u.pb)) {
				pr_err("Can't read page at @%li\n", (long)start);
				goto err;
			}

			if (u.h.cpt_content != CPT_CONTENT_DATA) {
				pr_err("Unexpected object content %d at @%li\n",
				       u.h.cpt_content, (long)start);
				goto err;
			}
			break;
		default:
			pr_err("Unexpected object %d at @%li\n",
			       u.h.cpt_object, (long)start);
			goto err;
		}

		/*
		 * Nothing to write.
		 */
		if (u.h.cpt_hdrlen == u.h.cpt_next)
			continue;

		nr_pages = PAGES(u.h.cpt_next - u.h.cpt_hdrlen);
		i = PAGES(u.pb.cpt_end - u.pb.cpt_start);
		if (nr_pages != i) {
			pr_err("Broken pages count (%li/%li) at @%li\n",
			       nr_pages, i, (long)start);
			goto err;
		}

		/*
		 * Unlinke page blocks we use to carry page data
		 * from vmas area, here we write the size inode carries,
		 * otherwise fstat called on such files will return page
		 * granular size instead of real one.
		 */
		pr_debug("\tInode page block: %#lx %#lx pages: %li (size %lu)\n",
			 (long)u.pb.cpt_start,
			 (long)u.pb.cpt_start + nr_pages * PAGE_SIZE,
			 nr_pages, (unsigned long)inode->ii.cpt_size);

		if (splice_data(ctx->fd, fd, inode->ii.cpt_size)) {
			pr_perror("Can't splice on inode data\n");
			goto err;
		}
	}
	ret = 0;
err:
	return ret;
}

static int dump_ghost_file(context_t *ctx, struct file_struct *file,
			   struct inode_struct *inode)
{
	RemapFilePathEntry rpe = REMAP_FILE_PATH_ENTRY__INIT;
	GhostFileEntry gfe = GHOST_FILE_ENTRY__INIT;

	int remap_fd = fdset_fd(ctx->fdset_glob, CR_FD_REMAP_FPATH);
	int ghost_fd = -1;
	int ret = -1;

	BUG_ON(obj_id_of(inode) & REMAP_GHOST);

	if (!inode->u.dumped_ghost) {
		ghost_fd = open_image(ctx, CR_FD_GHOST_FILE, O_DUMP, obj_id_of(inode));
		if (ghost_fd < 0)
			return -1;

		gfe.uid		= inode->ii.cpt_uid;
		gfe.gid		= inode->ii.cpt_gid;
		gfe.mode	= inode->ii.cpt_mode;

		gfe.has_dev	= true;
		gfe.has_ino	= true;
		gfe.dev		= MKKDEV(MAJOR(inode->ii.cpt_dev),
					 MINOR(inode->ii.cpt_dev));
		gfe.ino		= inode->ii.cpt_ino;

		if (pb_write_one(ghost_fd, &gfe, PB_GHOST_FILE))
			goto err;

		if (S_ISREG(inode->ii.cpt_mode)) {
			if (dump_ghost_file_content(ctx, ghost_fd, file, inode))
				goto err;
		}

		inode->u.dumped_ghost = true;
	}

	rpe.orig_id	= obj_id_of(file);
	rpe.remap_id	= obj_id_of(inode) | REMAP_GHOST;

	ret = pb_write_one(remap_fd, &rpe, PB_REMAP_FPATH);
err:
	if (ghost_fd != -1)
		close(ghost_fd);
	return ret;
}

static int dump_deleted_file(context_t *ctx, struct file_struct *file,
			     struct inode_struct *inode)
{
	return inode->ii.cpt_nlink ?
		dump_remaped_file(ctx, file, inode) :
		dump_ghost_file(ctx, file, inode);
}

static int check_path_remap(context_t *ctx, struct file_struct *file)
{
	struct inode_struct *inode;

	if (file->fi.cpt_inode == -1)
		return 0;

	inode = obj_lookup_to(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("No inode @%li for file at @%li\n",
		       (long)file->fi.cpt_inode, obj_pos_of(file));
		return -1;
	}

	if (file->fi.cpt_lflags & CPT_DENTRY_DELETED)
		return dump_deleted_file(ctx, file, inode);

	return 0;
}

enum pid_type {
	PIDTYPE_PID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX
};

void fill_fown(FownEntry *e, struct file_struct *file)
{
	e->uid		= file->fi.cpt_fown_uid;
	e->euid		= file->fi.cpt_fown_euid;
	e->signum	= file->fi.cpt_fown_signo;

	/*
	 * FIXME
	 * No info about pid type in OpenVZ image, use
	 * type PID for a while.
	 */
	e->pid_type	= PIDTYPE_PID;
	e->pid		= file->fi.cpt_fown_pid;
}

static char *demangle_deleted(char *name)
{
	/*
	 * FIXME Do we always have one prefix here?
	 */
	if (strncmp(name, " (deleted)", 10) == 0)
		return &name[10];
	return name;
}

int write_reg_file_entry(context_t *ctx, struct file_struct *file)
{
	int rfd = fdset_fd(ctx->fdset_glob, CR_FD_REG_FILES);
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	int ret = -1;

	if (file->dumped)
		return 0;

	fill_fown(&fown, file);

	if (check_path_remap(ctx, file)) {
		pr_err("Failed to check remapping on file at @%li\n",
		       obj_pos_of(file));
		return -1;
	}

	rfe.id		= obj_id_of(file);
	rfe.flags	= file->fi.cpt_flags;
	rfe.pos		= file->fi.cpt_pos;
	rfe.fown	= &fown;
	rfe.name	= demangle_deleted(file->name);

	ret = pb_write_one(rfd, &rfe, PB_REG_FILES);
	if (!ret)
		file->dumped = true;

	return ret;
}

static int write_pipe_data(context_t *ctx, struct file_struct *file,
			   struct inode_struct *inode, bool is_pipe)
{
	int fd = fdset_fd(ctx->fdset_glob, is_pipe ? CR_FD_PIPES_DATA : CR_FD_FIFO_DATA);
	PipeDataEntry pde = PIPE_DATA_ENTRY__INIT;
	off_t start;

	union {
		struct cpt_object_hdr	h;
		struct cpt_obj_bits	bits;
	} u;

	/*
	 * Already there.
	 */
	if (inode->u.dumped_pipe)
		return 0;

	/*
	 * No underlied data.
	 */
	if (inode->ii.cpt_next == inode->ii.cpt_hdrlen)
		return 0;

	start = obj_pos_of(inode) + inode->ii.cpt_hdrlen;

	if (read_obj_hdr(ctx->fd, &u.h, start)) {
		pr_err("Failed to read object header at @%li\n",
		       (long)start);
		return -1;
	}

	if (u.h.cpt_object != CPT_OBJ_BITS &&
	    u.h.cpt_content != CPT_CONTENT_DATA) {
		pr_err("Wrong object %d:%d at @%li\n",
		       u.h.cpt_object, (int)u.h.cpt_content, (long)start);
		return -1;
	}

	if (read_obj_cont(ctx->fd, &u.bits)) {
		pr_err("Failed to read bits object at @%li\n",
		       (long)start);
		return -1;
	}

	/*
	 * NOTE OpenVZ image has no pipe size stored, so just ignore it.
	 */
	pde.pipe_id	= obj_id_of(inode);
	pde.bytes	= u.bits.cpt_size;
	pde.has_size	= false;

	if (pb_write_one(fd, &pde, PB_PIPES_DATA)) {
		pr_err("Can't write pde to image\n");
		return -1;
	}

	/*
	 * FIXME Should I check for u.bits.cpt_size being crossing
	 *	 objects bounds?
	 */
	if (splice_data(ctx->fd, fd, u.bits.cpt_size)) {
		pr_err("Failed splicing %li bytes of pipe/fifo data at @%li",
		       (long)u.bits.cpt_size, (long)start);
		return -1;
	}

	inode->u.dumped_pipe = true;
	return 0;
}

static int write_pipe_entry(context_t *ctx, struct file_struct *file)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_PIPES);
	PipeEntry pe = PIPE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	struct inode_struct *inode;
	int ret = -1;

	if (file->dumped)
		return 0;

	if (file->fi.cpt_flags & O_DIRECT) {
		pr_err("The packetized mode for pipes is not supported yet\n");
		return -1;
	}

	inode = obj_lookup_to(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("No inode for pipe on file @%li\n",
		       obj_pos_of(file));
		return -1;
	}

	fill_fown(&fown, file);

	pe.id		= obj_id_of(file);
	pe.pipe_id	= obj_id_of(inode);
	pe.flags	= file->fi.cpt_flags;
	pe.fown		= &fown;

	ret = pb_write_one(fd, &pe, PB_PIPES);
	if (!ret) {
		ret = write_pipe_data(ctx, file, inode, true);
		if (!ret)
			file->dumped = true;
	}

	return ret;
}

static int write_fifo_entry(context_t *ctx, struct file_struct *file)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_FIFO);
	FifoEntry fe = FIFO_ENTRY__INIT;
	struct inode_struct *inode;
	int ret = -1;

	if (file->dumped)
		return 0;

	/*
	 * FIFOs are named pipes, so we need to save a path
	 * associated with it. And there is a trick in CRIU:
	 * names are saved in regular files image.
	 */
	ret = write_reg_file_entry(ctx, file);
	if (ret) {
		pr_err("Failed wirtting fifo path at @%li\n",
		       obj_pos_of(file));
		return -1;
	}

	inode = obj_lookup_to(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("No inode for fifo on file @%li\n",
		       obj_pos_of(file));
		return -1;
	}

	fe.id		= obj_id_of(file);
	fe.pipe_id	= obj_id_of(inode);

	ret = pb_write_one(fd, &fe, PB_FIFO);
	if (!ret) {
		ret = write_pipe_data(ctx, file, inode, false);
		if (!ret)
			file->dumped = true;
	}

	return ret;
}

static int write_signalfd(context_t *ctx, struct file_struct *file)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_SIGNALFD);
	SignalfdEntry se = SIGNALFD_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	int ret = -1;

	if (file->dumped)
		return 0;

	fill_fown(&fown, file);

	se.id		= obj_id_of(file);
	se.flags	= file->fi.cpt_flags;
	se.fown		= &fown;
	se.sigmask	= file->fi.cpt_priv;

	ret = pb_write_one(fd, &se, PB_SIGNALFD);
	if (!ret)
		file->dumped = true;

	return ret;
}

static int write_eventfd(context_t *ctx, struct file_struct *file)
{
	int fd = fdset_fd(ctx->fdset_glob, CR_FD_EVENTFD);
	EventfdFileEntry e = EVENTFD_FILE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	int ret = -1;

	if (file->dumped)
		return 0;

	BUG_ON(!file->sprig);

	fill_fown(&fown, file);

	e.id		= obj_id_of(file);
	e.flags		= file->fi.cpt_flags;
	e.fown		= &fown;
	e.counter	= file->sprig->u.efi.cpt_count;

	ret = pb_write_one(fd, &e, PB_EVENTFD);
	if (!ret)
		file->dumped = true;

	return ret;
}

static int write_flock(context_t *ctx, struct file_struct *file,
		       struct fd_struct *fd, int image_fd)
{
	struct file_sprig_struct *sprig = file->sprig;
	FileLockEntry e = FILE_LOCK_ENTRY__INIT;

	if (file->dumped || !sprig)
		return 0;

	if (sprig->u.hdr.cpt_object != CPT_OBJ_FLOCK)
		return 0;

	/*
	 * FIXME What with @cpt_svid ?
	 */
	e.flag	= sprig->u.fli.cpt_flags;
	e.type	= sprig->u.fli.cpt_type;
	e.pid	= sprig->u.fli.cpt_pid;
	e.fd	= fd->fdi.cpt_fd;
	e.start	= sprig->u.fli.cpt_start;

#ifndef OFFSET_MAX
#define INT_LIMIT(x)	(~((x)1ull << (sizeof(x) * 8 - 1)))
#define OFFSET_MAX	INT_LIMIT(unsigned long long)
#endif

	if (sprig->u.fli.cpt_end == OFFSET_MAX)
		e.len = 0;
	else
		e.len = (sprig->u.fli.cpt_end + 1) - sprig->u.fli.cpt_start;

	return pb_write_one(image_fd, &e, PB_FILE_LOCK);
}

int write_task_files(context_t *ctx, struct task_struct *t)
{
	FdinfoEntry e = FDINFO_ENTRY__INIT;
	struct files_struct *files;
	struct fd_struct *fd;
	int image_flock = -1;
	int image_fd = -1;
	int ret = -1;

	/*
	 * If we share fdtable with parent then simply
	 * get out early.
	 */
	if (t->parent) {
		if (t->parent->ti.cpt_files == t->ti.cpt_files)
			return 0;
	}

	files = obj_lookup_to(CPT_OBJ_FILES, t->ti.cpt_files);
	if (!files) {
		pr_err("Can't find files associated with task %d\n",
		       t->ti.cpt_pid);
		goto out;
	}

	image_fd = open_image(ctx, CR_FD_FDINFO, O_DUMP, t->ti.cpt_pid);
	if (image_fd < 0)
		goto out;

	image_flock = open_image(ctx, CR_FD_FILE_LOCKS, O_DUMP, t->ti.cpt_pid);
	if (image_flock < 0)
		goto out;

	list_for_each_entry(fd, &files->fd_list, list) {
		struct inode_struct *inode;
		struct file_struct *file;

		file = obj_lookup_to(CPT_OBJ_FILE, fd->fdi.cpt_file);
		if (!file) {
			pr_err("Can't find file associated with fd %d\n",
			       fd->fdi.cpt_fd);
			goto out;
		}

		if (file->fi.cpt_inode != -1) {
			inode = obj_lookup_to(CPT_OBJ_INODE, file->fi.cpt_inode);
			if (!inode) {
				pr_err("No inode @%li for file at @%li\n",
				       (long)file->fi.cpt_inode, obj_pos_of(file));
				return -1;
			}
		} else
			inode = NULL;

		if (set_fdinfo_type(&e, file, inode)) {
			pr_err("Can't find file type for @%li\n",
			       (long)fd->fdi.cpt_file);
			goto out;
		}

		e.id	= obj_id_of(file);
		e.flags	= fd->fdi.cpt_flags;
		e.fd	= fd->fdi.cpt_fd;

		ret = pb_write_one(image_fd, &e, PB_FDINFO);
		if (ret)
			goto out;

		/*
		 * Associated file lock must be written earlier
		 * than anything else (we check for @dumped flag).
		 */
		ret = write_flock(ctx, file, fd, image_flock);
		if (ret)
			goto out;

		switch (e.type) {
		case FD_TYPES__REG:
			ret = write_reg_file_entry(ctx, file);
			break;
		case FD_TYPES__PIPE:
			ret = write_pipe_entry(ctx, file);
			break;
		case FD_TYPES__FIFO:
			ret = write_fifo_entry(ctx, file);
			break;
		case FD_TYPES__TTY:
			ret = write_tty_entry(ctx, file);
			break;
		case FD_TYPES__INETSK:
		case FD_TYPES__UNIXSK:
		case FD_TYPES__NETLINKSK:
			ret = write_socket(ctx, file);
			break;
		case FD_TYPES__INOTIFY:
			ret = write_inotify(ctx, file);
			break;
		case FD_TYPES__EVENTPOLL:
			ret = write_epoll(ctx, file);
			break;
		case FD_TYPES__SIGNALFD:
			ret = write_signalfd(ctx, file);
			break;
		case FD_TYPES__EVENTFD:
			ret = write_eventfd(ctx, file);
			break;
		default:
			pr_err("Unsupported file found (type = %d)\n", e.type);
			ret = -1;
			break;
		}

		if (ret)
			goto out;
	}
	ret = 0;
out:
	close_safe(&image_fd);
	close_safe(&image_flock);
	return ret;
}

void free_inodes(context_t *ctx)
{
	struct inode_struct *inode;

	while ((inode = obj_pop_unhash_to(CPT_OBJ_INODE)))
		obj_free_to(inode);
}

static void show_inode_cont(context_t *ctx, struct inode_struct *inode)
{
	pr_debug("\t@%-10li dev %10li ino %10li mode %6d nlink %6d "
		 "size %10li rdev %10li sb %10li vfsmount @%-10li (payload %li)\n",
		 obj_pos_of(inode), (long)inode->ii.cpt_dev,
		 (long)inode->ii.cpt_ino, inode->ii.cpt_mode, inode->ii.cpt_nlink,
		 (long)inode->ii.cpt_size, (long)inode->ii.cpt_rdev,
		 (long)inode->ii.cpt_sb, (long)inode->ii.cpt_vfsmount,
		 (long)inode->ii.cpt_next - (long)inode->ii.cpt_hdrlen);
}

int read_inodes(context_t *ctx)
{
	off_t start, end;

	pr_read_start("inodes\n");
	get_section_bounds(ctx, CPT_SECT_INODE, &start, &end);

	while (start < end) {
		struct inode_struct *inode;

		inode = obj_alloc_to(struct inode_struct, ii);
		if (!inode)
			return -1;

		inode->u.dumped_pipe = false;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_INODE, &inode->ii, start)) {
			obj_free_to(inode);
			pr_err("Can't read inode object at @%li\n", (long)start);
			return -1;
		}

		obj_push_hash_to(inode, CPT_OBJ_INODE, start);
		start += inode->ii.cpt_next;

		show_inode_cont(ctx, inode);
	}
	pr_read_end();

	return 0;
}

static void show_file_cont(context_t *ctx, struct file_struct *file)
{
	unsigned int i;

	pr_debug("\t@%-10li flags %8d mode %6d pos %16li\n"
		 "\t\ti_mode %6d lflags %6d inode @%-10li vfsmount @%-10li --> %s\n",
		obj_pos_of(file), file->fi.cpt_flags, file->fi.cpt_mode,
		(long)file->fi.cpt_pos, file->fi.cpt_i_mode,
		file->fi.cpt_lflags, (long)file->fi.cpt_inode,
		(long)file->fi.cpt_vfsmount, file->name);
	if (file->fi.cpt_lflags) {
		pr_debug("\t\t\t");
		for (i = 0; i < ARRAY_SIZE(file_lflags_map); i++) {
			if (file->fi.cpt_lflags & file_lflags_map[i].flag)
				pr_debug("%s ", file_lflags_map[i].name);
		}
		pr_debug("\n");
	}

	if (file->sprig) {
		switch (file->sprig->u.hdr.cpt_object) {
		case CPT_OBJ_TIMERFD:
			pr_debug("\t\t\t\t@%-10li timerfd"
				 "\t\t\t\t\tit_value %-8li it_interval %-8li\n"
				 "\t\t\t\t\tticks %-8li expired %-4i clockid %-4i\n",
				 obj_pos_of(file->sprig),
				 (long)file->sprig->u.tfi.cpt_it_value,
				 (long)file->sprig->u.tfi.cpt_it_interval,
				 (long)file->sprig->u.tfi.cpt_ticks,
				 file->sprig->u.tfi.cpt_expired,
				 file->sprig->u.tfi.cpt_clockid);
			break;
		case CPT_OBJ_EVENTFD:
			pr_debug("\t\t\t\t@%-10li eventfd"
				 "\t\t\t\t\tcount %-8li flags %-4i\n",
				 obj_pos_of(file->sprig),
				 (long)file->sprig->u.efi.cpt_count,
				 file->sprig->u.efi.cpt_flags);
			break;
		case CPT_OBJ_FLOCK:
			pr_debug("\t\t\t\t@%-10li flock"
				 "\t\t\t\t\towner %-4i pid %-4i\n"
				 "\t\t\t\t\tstart %-8li end %-8li flags %-4i\n"
				 "\t\t\t\t\ttype %-4i svid %-4i",
				 obj_pos_of(file->sprig),
				 file->sprig->u.fli.cpt_owner,
				 file->sprig->u.fli.cpt_pid,
				 (long)file->sprig->u.fli.cpt_start,
				 (long)file->sprig->u.fli.cpt_end,
				 file->sprig->u.fli.cpt_flags,
				 file->sprig->u.fli.cpt_type,
				 file->sprig->u.fli.cpt_svid);
			break;
		default:
			BUG();
		}
	}
}

static struct file_struct *read_file(context_t *ctx, off_t start, off_t *next)
{
	struct file_struct *file, *ret = NULL;

	file = obj_alloc_to(struct file_struct, fi);
	if (!file)
		return NULL;

	file->name = NULL;
	file->namelen = 0;
	file->dumped = false;
	file->sprig = NULL;

	if (read_obj_cpt(ctx->fd, CPT_OBJ_FILE, &file->fi, start))
		goto err;

	obj_push_hash_to(file, CPT_OBJ_FILE, start);
	*next = start + file->fi.cpt_next;

	if (file->fi.cpt_next > file->fi.cpt_hdrlen) {
		off_t from, end = 0;

		from = obj_pos_of(file) + file->fi.cpt_hdrlen;

		/*
		 * Some underlied data present, which might be one of
		 * CPT_OBJ_NAME (for non socket files) and then
		 * (CPT_OBJ_TIMERFD | CPT_OBJ_EVENTFD | CPT_OBJ_FLOCK)
		 */
		if (!S_ISSOCK(file->fi.cpt_i_mode)) {
			file->name = read_name(ctx->fd, from, &file->namelen, &end);
			if (IS_ERR(file->name))
				goto err;
		}
		from += end;

		if (from < *next) {
			struct file_sprig_struct *sprig;

			sprig = obj_alloc_to(struct file_sprig_struct, u);
			if (!sprig)
				goto err;

			if (read_obj_hdr(ctx->fd, &sprig->u.hdr, from)) {
				obj_free_to(sprig);
				pr_err("Failed to read undelied header\n");
				goto err;
			}

			switch (sprig->u.hdr.cpt_object) {
			case CPT_OBJ_TIMERFD:
				if (read_obj_cont(ctx->fd, &sprig->u.tfi)) {
					obj_free_to(sprig);
					pr_err("Failed to read timerfd\n");
					goto err;
				}
				break;
			case CPT_OBJ_EVENTFD:
				if (read_obj_cont(ctx->fd, &sprig->u.efi)) {
					obj_free_to(sprig);
					pr_err("Failed to read eventfd\n");
					goto err;
				}
				break;
			case CPT_OBJ_FLOCK:
				if (read_obj_cont(ctx->fd, &sprig->u.fli)) {
					obj_free_to(sprig);
					pr_err("Failed to read flock\n");
					goto err;
				}
				break;
			default:
				obj_free_to(sprig);
				pr_err("Unknown underlied object %d\n",
				       sprig->u.hdr.cpt_object);
				goto err;
			}

			obj_hash_typed_to(sprig, sprig->u.hdr.cpt_object, from);
			file->sprig = sprig;
		}
	}

	ret = file;
	file = NULL;
err:
	if (file)
		pr_err("Failed to read file at @%li\n", (long)start);
	return ret;
}

void free_files(context_t *ctx)
{
	struct files_struct *files;
	struct file_struct *file;
	struct fd_struct *fd, *n;

	while ((file = obj_pop_unhash_to(CPT_OBJ_FILE))) {
		if (likely(!IS_ERR(file->name)))
			xfree(file->name);
		if (file->sprig) {
			obj_unhash_to(file->sprig);
			obj_free_to(file->sprig);
		}
		obj_free_to(file);
	}

	while ((files = obj_pop_unhash_to(CPT_OBJ_FILES))) {
		list_for_each_entry_safe(fd, n, &files->fd_list, list) {
			obj_unhash_to(fd);
			obj_free_to(fd);
		}
		obj_free_to(files);
	}
}

static void show_fd_cont(context_t *ctx, struct fd_struct *fd)
{
	struct file_struct *file = obj_lookup_to(CPT_OBJ_FILE, fd->fdi.cpt_file);

	pr_debug("\t\t@%-10li fd %8d flags %6x file @%-10lu (name --> %s)\n",
		 obj_pos_of(fd), fd->fdi.cpt_fd, fd->fdi.cpt_flags,
		 (long)fd->fdi.cpt_file, file ? file->name : "");
}

static void show_files_cont(context_t *ctx, struct files_struct *files)
{
	pr_debug("\t@%-10li index %8d cpt_max_fds %6d cpt_next_fd %6d\n",
		 obj_pos_of(files), files->fsi.cpt_index,
		 files->fsi.cpt_max_fds, files->fsi.cpt_next_fd);
}

int read_files(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_read_start("files\n");
	get_section_bounds(ctx, CPT_SECT_FILES, &start, &end);

	while (start < end) {
		struct file_struct *file;

		file = read_file(ctx, start, &start);
		if (!file)
			goto out;

		show_file_cont(ctx, file);
	}
	pr_read_end();

	pr_read_start("file descriptors\n");
	get_section_bounds(ctx, CPT_SECT_FILES_STRUCT, &start, &end);

	while (start < end) {
		struct files_struct *files;
		struct fd_struct *fd;
		off_t from, to;

		files = obj_alloc_to(struct files_struct, fsi);
		if (!files)
			return -1;
		INIT_LIST_HEAD(&files->fd_list);

		if (read_obj_cpt(ctx->fd, CPT_OBJ_FILES, &files->fsi, start)) {
			obj_free_to(files);
			pr_err("Can't read files object at @%li\n", (long)start);
			return -1;
		}

		obj_push_hash_to(files, CPT_OBJ_FILES, start);
		start += files->fsi.cpt_next;

		show_files_cont(ctx, files);

		if (files->fsi.cpt_next <= files->fsi.cpt_hdrlen)
			continue;

		/*
		 * Read underlied file descriptors.
		 */
		for (from = obj_pos_of(files) + files->fsi.cpt_hdrlen,
		     to = obj_pos_of(files) + files->fsi.cpt_next;
		     from < to;
		     from += fd->fdi.cpt_next) {

			fd = obj_alloc_to(struct fd_struct, fdi);
			if (!fd)
				return -1;
			INIT_LIST_HEAD(&fd->list);

			if (read_obj_cpt(ctx->fd, CPT_OBJ_FILEDESC, &fd->fdi, from)) {
				obj_free_to(fd);
				pr_err("Can't read files object at @%li\n", (long)from);
				return -1;
			}

			obj_hash_to(fd, from);
			list_add_tail(&fd->list, &files->fd_list);

			show_fd_cont(ctx, fd);
		}
	}
	pr_read_end();
	ret = 0;
out:
	return ret;
}

void free_fs(context_t *ctx)
{
	struct fs_struct *fs;

	while ((fs = obj_pop_unhash_to(CPT_OBJ_FS)))
		obj_free_to(fs);
}

int write_task_fs(context_t *ctx, struct task_struct *t)
{
	FsEntry e = FS_ENTRY__INIT;
	int ret = -1, fd = -1;
	struct fs_struct *fs;

	fs = obj_lookup_to(CPT_OBJ_FS, t->ti.cpt_fs);
	if (!fs) {
		pr_err("No FS object found for task %d at @%li\n",
			t->ti.cpt_pid, (long)t->ti.cpt_fs);
		goto out;
	}

	fd = open_image(ctx, CR_FD_FS, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		goto out;

	e.has_umask	= true;
	e.umask		= fs->fsi.cpt_umask;
	e.root_id	= obj_id_of(fs->root);
	e.cwd_id	= obj_id_of(fs->cwd);

	if (write_reg_file_entry(ctx, fs->root)) {
		pr_err("Failed to write reg file for FS root\n");
		goto out;
	}

	if (write_reg_file_entry(ctx, fs->cwd)) {
		pr_err("Failed to write reg file for FS cwd\n");
		goto out;
	}

	ret = pb_write_one(fd, &e, PB_FS);
out:
	close_safe(&fd);

	return ret;
}

static void show_fs_cont(context_t *ctx, struct fs_struct *fs)
{
	pr_debug("\t@%-10li cpt_umask %#6x\n"
		 "\t\troot @%-10li (name --> %s)\n"
		 "\t\tcwd  @%-10li (name --> %s)\n",
		 obj_pos_of(fs), fs->fsi.cpt_umask,
		 obj_pos_of(fs->root), fs->root->name,
		 obj_pos_of(fs->cwd), fs->cwd->name);
}

int read_fs(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_read_start("fs\n");
	get_section_bounds(ctx, CPT_SECT_FS, &start, &end);

	while (start < end) {
		struct fs_struct *fs;
		off_t file_off;

		fs = obj_alloc_to(struct fs_struct, fsi);
		if (!fs)
			return -1;
		fs->root = fs->cwd = NULL;

		/* fs itself */
		if (read_obj_cpt(ctx->fd, CPT_OBJ_FS, &fs->fsi, start)) {
			obj_free_to(fs);
			pr_err("Can't read fs object at @%li\n", (long)start);
			return -1;
		}

		obj_push_hash_to(fs, CPT_OBJ_FS, start);

		if (fs->fsi.cpt_hdrlen >= fs->fsi.cpt_next) {
			pr_err("FS entry corrupted at @%li\n", (long)start);
			goto out;
		}

		file_off = start + fs->fsi.cpt_hdrlen;

		fs->root = read_file(ctx, file_off, &file_off);
		if (!fs->root) {
			pr_err("FS root entry corrupted at @%li\n", (long)file_off);
			goto out;
		}

		fs->cwd = read_file(ctx, file_off, &file_off);
		if (!fs->cwd) {
			pr_err("FS cwd entry corrupted at @%li\n", (long)file_off);
			goto out;
		}

		start += fs->fsi.cpt_next;
		show_fs_cont(ctx, fs);
	}
	pr_read_end();
	ret = 0;
out:
	return ret;
}
