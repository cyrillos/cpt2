#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "protobuf.h"
#include "context.h"
#include "convert.h"
#include "xmalloc.h"
#include "string.h"
#include "image.h"
#include "read.h"
#include "task.h"
#include "cpt2.h"
#include "log.h"
#include "net.h"
#include "mm.h"
#include "ns.h"

#include "protobuf/inventory.pb-c.h"

static int write_inventory(context_t *ctx)
{
	TaskKobjIdsEntry kids = TASK_KOBJ_IDS_ENTRY__INIT;
	InventoryEntry e = INVENTORY_ENTRY__INIT;
	int fd, ret;

	pr_info("Writing image inventory (version %u)\n", CRTOOLS_IMAGES_V1);

	fd = open_image(ctx, CR_FD_INVENTORY, O_DUMP);
	if (fd < 0)
		return -1;

	/*
	 * Inventory kIDs should be unique here. Since we know that
	 * offsets to cpt_ entries used are greater than 1, just
	 * use trivial numbers increment to obtain uniqueness.
	 */
	kids.vm_id		= root_task->ti.cpt_mm + 1;
	kids.files_id		= root_task->ti.cpt_files + 1;
	kids.fs_id		= root_task->ti.cpt_fs + 1;
	kids.sighand_id		= root_task->ti.cpt_sighand + 1;

	kids.has_pid_ns_id	= true;
	kids.has_net_ns_id	= true;
	kids.has_ipc_ns_id	= true;
	kids.has_uts_ns_id	= true;
	kids.has_mnt_ns_id	= true;

	/*
	 * FIXME
	 *
	 * These values here left for debug purpose,
	 * need some sane ones.
	 */
	kids.pid_ns_id		= 2;
	kids.net_ns_id		= 2;
	kids.ipc_ns_id		= 2;
	kids.uts_ns_id		= 2;
	kids.mnt_ns_id		= 2;

	e.img_version		= CRTOOLS_IMAGES_V1;
	e.fdinfo_per_id		= false;
	e.has_fdinfo_per_id	= false;
	e.root_ids		= &kids;

	ret = pb_write_one(fd, &e, PB_INVENTORY);
	close(fd);

	return ret;
}

static int write_stubs(context_t *ctx)
{
	int fd;

#define gen_stub(type)						\
	do {							\
		fd = open_image(ctx, CR_FD_##type, O_DUMP);	\
		if (fd < 0)					\
			return -1;				\
		close(fd);					\
	} while (0)

	gen_stub(FANOTIFY);
	gen_stub(FANOTIFY_MARK);
	gen_stub(PACKETSK);
	gen_stub(SK_QUEUES);
	gen_stub(REMAP_FPATH);
	gen_stub(RLIMIT);
	gen_stub(NS_FILES);
#undef gen_stub

	return 0;
}

int convert(void)
{
	context_t ctx;
	int ret = -1;

	context_init(&ctx);
	cr_pb_init();

	ctx.dfd = open(global_opts.criu_dirname, O_RDONLY);
	if (ctx.dfd < 0) {
		pr_perror("Can't open directory %s",
			  global_opts.criu_dirname);
		goto out;
	}

	ctx.fd = open(global_opts.cpt_filename, O_RDONLY);
	if (ctx.fd < 0) {
		pr_perror("Can't open checkpoint file %s",
			  global_opts.cpt_filename);
		goto out;
	}

	ctx.rootfd = open(global_opts.root_dirname, O_RDONLY);
	if (ctx.rootfd < 0) {
		pr_perror("Can't open container root %s",
			  global_opts.root_dirname);
		goto out;
	}

	if (fstat(ctx.rootfd, &ctx.stroot)) {
		pr_perror("Can't obtaine statistics on container root %s",
			  global_opts.root_dirname);
		goto out;

	}

	ctx.root_len = strlcpy(ctx.root, global_opts.root_dirname, sizeof(ctx.root));

	ret = context_init_fdset_glob(&ctx);
	if (ret)
		goto out;

	ret = read_dumpfile(&ctx);
	if (ret) {
		pr_err("Failed reading dumpfile %s\n",
		       global_opts.cpt_filename);
		goto out;
	}

	/*
	 * No nested namespace support in CRIU, thus
	 * just get pid from the root task.
	 */
	ret = context_init_fdset_ns(&ctx, root_task->ti.cpt_pid);
	if (ret)
		goto out;

	ret = write_task_images(&ctx);
	if (ret) {
		pr_err("Failed to write task images\n");
		goto out;
	}

	ret = write_pstree(&ctx);
	if (ret) {
		pr_err("Failed writting process tree\n");
		goto out;
	}

	ret = convert_ns(&ctx);
	if (ret) {
		pr_err("Failed writting ns related data\n");
		goto out;
	}

	ret = write_stubs(&ctx);
	if (ret) {
		pr_err("Failed writting stubs\n");
		goto out;
	}

	ret = write_shmem(&ctx);
	if (ret) {
		pr_err("Failed to write shmem\n");
		goto out;
	}

	ret = write_inventory(&ctx);
	if (ret) {
		pr_err("Failed to write inventory\n");
		goto out;
	}

	pr_warn("Conversion is not yet implemented and still in debug state\n");
out:
	read_fini(&ctx);
	context_fini(&ctx);
	return ret;
}
