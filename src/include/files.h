#ifndef __CPT2_FILES_H__
#define __CPT2_FILES_H__

#include <stdbool.h>

#include "cpt-image.h"
#include "context.h"
#include "types.h"
#include "list.h"
#include "obj.h"

#include "protobuf/fown.pb-c.h"
#include "protobuf/fdinfo.pb-c.h"

struct task_struct;

struct file_sprig_struct {
	union {
	  struct cpt_object_hdr		hdr;
	  struct cpt_timerfd_image	tfi;
	  struct cpt_eventfd_image	efi;
	  struct cpt_flock_image	fli;
	} u;
};

struct file_struct {
	bool				dumped;
	char				*name;

	struct cpt_file_image		fi;
	struct file_sprig_struct	*sprig;
};

struct files_struct {
	struct list_head		fd_list;

	struct cpt_files_struct_image	fsi;
};

struct fd_struct {
	struct list_head		list;

	struct cpt_fd_image		fdi;
};

struct fs_struct {
	struct file_struct		*root;
	struct file_struct		*cwd;

	struct cpt_fs_struct_image	fsi;
};

struct inode_struct {
	union {
		bool			dumped_pipe;
	} u;

	struct cpt_inode_image		ii;
};

extern int read_files(context_t *ctx);
extern int write_task_files(context_t *ctx, struct task_struct *t);
extern void free_files(context_t *ctx);

extern void fill_fown(FownEntry *e, struct file_struct *file);
extern int write_reg_file_entry(context_t *ctx, struct file_struct *file);

extern int read_inodes(context_t *ctx);
extern void free_inodes(context_t *ctx);

extern int read_fs(context_t *ctx);
extern void free_fs(context_t *ctx);
extern int write_task_fs(context_t *ctx, struct task_struct *t);

#endif /* __CPT2_FILES_H__ */
