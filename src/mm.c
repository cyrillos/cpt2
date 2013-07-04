#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/mman.h>

#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "image.h"
#include "files.h"
#include "read.h"
#include "vdso.h"
#include "log.h"
#include "obj.h"
#include "bug.h"
#include "mm.h"

#include "res/vdso-rhel.h"

#include "protobuf.h"
#include "protobuf/regfile.pb-c.h"
#include "protobuf/pagemap.pb-c.h"
#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/fown.pb-c.h"
#include "protobuf/vma.pb-c.h"
#include "protobuf/mm.pb-c.h"

static u32 pages_ids = 1;
static u8 zero_page[PAGE_SIZE];
static u8 page[PAGE_SIZE];

#define SHMEM_HASH_BITS	10
static DEFINE_HASHTABLE(shmem_hash, SHMEM_HASH_BITS);

static int write_page_block(context_t *ctx, int pagemap_fd, int page_fd,
			    off_t start, off_t end, bool all,
			    u64 addr_start, u64 addr_end);

static struct shmem_struct *shmem_lookup(u64 shmid)
{
	struct shmem_struct *shmem;

	hash_for_each_key(shmem_hash, shmem, hash, shmid) {
		if (shmem->shmid == shmid)
			return shmem;
	}

	return NULL;
}

static int shmem_add(struct vma_struct *vma, u64 shmid, pid_t pid)
{
	struct shmem_struct *shmem;
	unsigned long size;

	BUG_ON(!vma->file || !(vma_is(vma, VMA_ANON_SHARED)));

	size  = (vma->vmai.cpt_pgoff << PAGE_SHIFT);
	size += (vma->vmai.cpt_end - vma->vmai.cpt_start);

	shmem = shmem_lookup(shmid);
	if (shmem) {
		if (shmem->size < size) {
			shmem->size = size;
			return 0;
		}
	}

	shmem = xmalloc(sizeof(*shmem));
	if (!shmem) {
		pr_err("Failed handling shmem\n");
		return -1;
	}

	INIT_HLIST_NODE(&shmem->hash);
	shmem->shmid	= shmid;
	shmem->vma	= vma;
	shmem->pid	= pid;

	hash_add(shmem_hash, &shmem->hash, shmem->shmid);
	return 0;
}

void free_mm(context_t *ctx)
{
	struct shmem_struct *shmem;
	struct hlist_node *n;
	unsigned long bucket;
	struct mm_struct *mm;

	hash_for_each_safe(shmem_hash, bucket, n, shmem, hash)
		xfree(shmem);

	while ((mm = obj_pop_unhash_to(CPT_OBJ_MM))) {
		struct vma_struct *vma, *n;

		list_for_each_entry_safe(vma, n, &mm->vma_list, list) {
			obj_unhash_to(vma);
			obj_free_to(vma);
		}
		obj_free_to(mm);
	}


}

static void show_mmi_cont(context_t *ctx, struct mm_struct *mm)
{
	struct cpt_mm_image *mmi = &mm->mmi;

	pr_debug("\t@%-10li start_code 0x%-16lx end_code  0x%-16lx "
		 "start_data 0x%-16lx  end_data 0x%-16lx mm_flags 0x%-16lx\n",
		 obj_pos_of(mm),
		 (long)mmi->cpt_start_code, (long)mmi->cpt_end_code,
		 (long)mmi->cpt_start_data, (long)mmi->cpt_end_data,
		 (long)mmi->cpt_mm_flags);
}

static u32 vma_flags_to_prot(u64 flags)
{
	return	_calc_vm_trans(flags, VM_READ,		PROT_READ)	|
		_calc_vm_trans(flags, VM_WRITE,		PROT_WRITE)	|
		_calc_vm_trans(flags, VM_EXEC,		PROT_EXEC)	|
		_calc_vm_trans(flags, VM_EXECUTABLE,	PROT_EXEC);
}

static bool is_dev_zero(struct file_struct *file)
{
	if (!file->name)
		return false;

	return (strcmp(file->name, "/dev/zero (deleted)") == 0 ||
		strcmp(file->name, " (deleted)/dev/zero") == 0 ||
		strcmp(file->name, "/dev/zero") == 0);
}

static bool vma_has_direct_payload(struct vma_struct *vma)
{
	return vma->vmai.cpt_hdrlen < vma->vmai.cpt_next;
}

static bool should_dump_vma(struct vma_struct *vma)
{
	/* Special areas are not dumped */
	if (!vma_is(vma, VMA_AREA_REGULAR))
		return false;

	/* No dumps for file-shared mappings */
	if (vma_is(vma, VMA_FILE_SHARED))
		return false;

	/* Always dump vDSO */
	if (vma_is(vma, VMA_AREA_VDSO))
		return true;

	/* No dumps for SYSV IPC mappings */
	if (vma_is(vma, VMA_AREA_SYSVIPC))
		return false;

	/* Anon shared is dumped separately */
	if (vma_is(vma, VMA_ANON_SHARED))
		return false;

	if (!vma_is(vma, VMA_ANON_PRIVATE | VMA_FILE_PRIVATE)) {
		pr_warn("Unexpected VMA area found (@%li %#x)\n",
			obj_pos_of(vma), vma->status);
		return false;
	}

	if (vma->vmai.cpt_end > TASK_SIZE)
		return false;

	return true;
}

static int write_vdso_pages(context_t *ctx, int pagemap_fd, int page_fd,
			    struct vma_struct *vma)
{
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;
	unsigned long aligned, size, end;
	int ret = -1;
	void *src;

	if (ctx->h.cpt_image_version < CPT_VERSION_32 ||
	    vma->vmai.cpt_type == CPT_VMA_VDSO_OLD) {
		src	= (void *)vdso_blob_rhel5;
		size	= sizeof(vdso_blob_rhel5);
	} else {
		src	= (void *)vdso_blob_rhel6;
		size	= sizeof(vdso_blob_rhel6);
	}

	aligned		= ALIGN(size, PAGE_SIZE);
	end		= (long)vma->vmai.cpt_start + aligned;

	if (end != vma->vmai.cpt_end) {
		pr_err("Misaligned vDSO area %lx %lx\n",
		       (long)vma->vmai.cpt_end, end);
		goto err;
	}

	pr_debug("\tvDSO pages: %#lx %#lx pages: %li (%li %li)\n",
		 (long)vma->vmai.cpt_start, (long)vma->vmai.cpt_end,
		 (long)PAGES(aligned), (long)size, (long)aligned);

	pe.vaddr	= vma->vmai.cpt_start;
	pe.nr_pages	= PAGES(aligned);

	if (pb_write_one(pagemap_fd, &pe, PB_PAGEMAP) < 0)
		goto err;

	if (__write(page_fd, src, size)) {
		pr_err("Can't write vDSO pages at @%li\n",
		       obj_pos_of(vma));
		goto err;
	}

	if (__write(page_fd, zero_page, aligned - size)) {
		pr_err("Can't write vDSO zero pages at @%li\n",
		       obj_pos_of(vma));
		goto err;
	}

	ret = 0;
err:
	return ret;
}

static int write_copy_pages(context_t *ctx, int pagemap_fd, int page_fd,
			    struct cpt_copypage_block *cpb)
{
	struct vma_struct *vma;
	struct mm_struct *mm;
	int ret = -1;

	mm = obj_lookup_to(CPT_OBJ_MM, cpb->cpt_source);
	if (!mm)
		goto err;

	/*
	 * It's assumed that VMA's are sorted in image and
	 * copy page block is granular and doesn't jump out
	 * of VMA bounds. Thus just find which VMA our page
	 * page belongs and write it where needed.
	 */
	list_for_each_entry(vma, &mm->vma_list, list) {
		if (vma->vmai.cpt_end <= cpb->cpt_start)
			continue;
		else if (vma->vmai.cpt_start >= cpb->cpt_end)
			break;
		pr_debug("\tCopy page block %#lx %#lx  %#lx %#lx (nr-pages: %li)\n",
			 (long)vma->vmai.cpt_start,
			 (long)vma->vmai.cpt_end,
			 (long)cpb->cpt_start,
			 (long)cpb->cpt_end,
			 (long)PAGES(cpb->cpt_end - cpb->cpt_start));

		/*
		 * We've got VMA the page block belongs to just
		 * need to read them and write into image.
		 */
		if (write_page_block(ctx, pagemap_fd, page_fd,
				     obj_of(vma)->o_pos + vma->vmai.cpt_hdrlen,
				     obj_of(vma)->o_pos + vma->vmai.cpt_next,
				     false, cpb->cpt_start, cpb->cpt_end))
			goto err;
		break;
	}
	ret = 0;

err:
	return ret;
}

static int write_page_block(context_t *ctx, int pagemap_fd, int page_fd,
			    off_t start, off_t end, bool all,
			    u64 addr_start, u64 addr_end)
{
	union {
		struct cpt_object_hdr		h;
		struct cpt_page_block		pb;
		struct cpt_copypage_block	cpb;
	} u;

	unsigned long nr_pages, i;
	PagemapEntry pe;
	int ret = -1;

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
		case CPT_OBJ_COPYPAGES:
			if (read_obj_cont(ctx->fd, &u.cpb)) {
				pr_err("Can't read page at @%li\n", (long)start);
				goto err;
			}

			if (u.h.cpt_content != CPT_CONTENT_VOID) {
				pr_err("Unexpected object content %d at @%li\n",
				       u.h.cpt_content, (long)start);
				goto err;
			}

			ret = write_copy_pages(ctx, pagemap_fd, page_fd, &u.cpb);
			if (ret)
				goto err;
			break;
		case CPT_OBJ_REMAPPAGES:
		case CPT_OBJ_LAZYPAGES:
		case CPT_OBJ_ITERPAGES:
		case CPT_OBJ_ITERYOUNGPAGES:
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

		pr_debug("\tPage block: %#lx %#lx pages: %li\n",
			 (long)u.pb.cpt_start,
			 (long)u.pb.cpt_start + nr_pages * PAGE_SIZE,
			 nr_pages);

		pagemap_entry__init(&pe);
		pe.vaddr	= u.pb.cpt_start;
		pe.nr_pages	= nr_pages;

		if (all) {
			if (pb_write_one(pagemap_fd, &pe, PB_PAGEMAP) < 0)
				goto err;
			for (i = 0; i < nr_pages; i++) {
				if (__read(ctx->fd, page, sizeof(page))) {
					pr_err("Can't read page at @%li\n",
					       (long)start);
					goto err;
				} else if (__write(page_fd, page, sizeof(page))) {
					pr_err("Can't write page at @%li\n",
					       (long)start);
					goto err;
				}
			}
		} else {
			/*
			 * Scroll until address needed is reached.
			 */
			while (addr_start > pe.vaddr &&
			       addr_start < addr_end &&
			       pe.nr_pages) {

				pe.vaddr += PAGE_SIZE;
				pe.nr_pages--;

				if (lseek(ctx->fd, PAGE_SIZE, SEEK_CUR) == (off_t)-1) {
					pr_perror("Failed to lookup on page at @%li",
						  (long)start);
					goto err;
				}
			}

			if (!pe.nr_pages)
				continue;

			for (i = 0;
			     i < pe.nr_pages && addr_start < addr_end;
			     i++, addr_start += PAGE_SIZE) {
				if (__read(ctx->fd, page, sizeof(page))) {
					pr_err("Can't read page at @%li\n",
					       (long)start);
					goto err;
				} else if (__write(page_fd, page, sizeof(page))) {
					pr_err("Can't write page at @%li\n",
					       (long)start);
					goto err;
				}

				if (addr_start >= addr_end) {
					ret = 0;
					goto err;
				}
			}

			pe.nr_pages = i;

			if (pb_write_one(pagemap_fd, &pe, PB_PAGEMAP) < 0)
				goto err;
		}
	}
	ret = 0;
err:
	return ret;
}

static int write_vma_pages(context_t *ctx, int pagemap_fd, int page_fd,
			   struct vma_struct *vma)
{
	if (unlikely(vma_is(vma, VMA_AREA_VDSO)))
		return write_vdso_pages(ctx, pagemap_fd, page_fd, vma);

	return write_page_block(ctx, pagemap_fd, page_fd,
				obj_of(vma)->o_pos + vma->vmai.cpt_hdrlen,
				obj_of(vma)->o_pos + vma->vmai.cpt_next,
				true, 0, 0);
}

int write_shmem(context_t *ctx)
{
	int pagemap_fd = -1, page_fd = -1;
	struct shmem_struct *shmem;
	unsigned long bucket;
	int ret = -1;

	hash_for_each(shmem_hash, bucket, shmem, hash) {
		struct inode_struct *inode;
		unsigned long payload;

		PagemapHead h = PAGEMAP_HEAD__INIT;

		pagemap_fd = open_image(ctx, CR_FD_SHMEM_PAGEMAP, O_DUMP, shmem->shmid);
		if (pagemap_fd < 0)
			return -1;

		h.pages_id = shmem->shmid;

		page_fd = open_image(ctx, CR_FD_PAGES, O_DUMP, h.pages_id);
		if (page_fd < 0)
			goto err;

		if (pb_write_one(pagemap_fd, &h, PB_PAGEMAP_HEAD) < 0)
			goto err;

		/*
		 * For anonymous shared memory pages are pinned to inode.
		 */
		inode = obj_lookup_to(CPT_OBJ_INODE, shmem->vma->file->fi.cpt_inode);
		if (!inode) {
			pr_err("No inode @%li for vma @%li\n",
			       (long)shmem->vma->file->fi.cpt_inode,
			       obj_pos_of(shmem->vma));
			goto err;
		}

		payload  = (unsigned long)inode->ii.cpt_next;
		payload -= (unsigned long)inode->ii.cpt_hdrlen;

		if (payload) {

			pr_debug("\tAnonymous shared memory block %#lx %#lx @%li\n",
				 (long)shmem->vma->vmai.cpt_start,
				 (long)shmem->vma->vmai.cpt_end,
				 obj_pos_of(shmem->vma));

			ret = write_page_block(ctx, pagemap_fd, page_fd,
					       (off_t)obj_pos_of(inode) + inode->ii.cpt_hdrlen,
					       (off_t)obj_pos_of(inode) + inode->ii.cpt_next,
					       true, 0, 0);
			if (ret) {
				pr_err("Can't write page block of @%li\n",
				       obj_pos_of(shmem->vma));
				goto err;
			}
		}

		close_safe(&pagemap_fd);
		close_safe(&page_fd);
	}
	ret = 0;

err:
	close_safe(&pagemap_fd);
	close_safe(&page_fd);
	return ret;
}

int write_pages(context_t *ctx, pid_t pid, off_t cpt_mm)
{
	PagemapHead h = PAGEMAP_HEAD__INIT;
	struct vma_struct *vma;
	struct mm_struct *mm;

	int pagemap_fd = -1;
	int page_fd = -1;
	int ret = -1;

	mm = obj_lookup_to(CPT_OBJ_MM, cpt_mm);
	if (!mm)
		return -1;

	pagemap_fd = open_image(ctx, CR_FD_PAGEMAP, O_DUMP, pid);
	if (pagemap_fd < 0)
		goto err;

	h.pages_id = pages_ids++;

	page_fd = open_image(ctx, CR_FD_PAGES, O_DUMP, h.pages_id);
	if (page_fd < 0)
		goto err;

	if (pb_write_one(pagemap_fd, &h, PB_PAGEMAP_HEAD) < 0)
		goto err;

	list_for_each_entry(vma, &mm->vma_list, list) {
		if (!should_dump_vma(vma))
			continue;

		/*
		 * For vDSO we need to provide own content even
		 * if it's not provided in image.
		 */
		if (!vma_has_direct_payload(vma) && !vma_is(vma, VMA_AREA_VDSO))
			continue;

		ret = write_vma_pages(ctx, pagemap_fd, page_fd, vma);
		if (ret) {
			pr_err("Can't write pages header at @%li\n", obj_pos_of(vma));
			goto err;
		}
	}
	ret = 0;
err:
	close_safe(&pagemap_fd);
	close_safe(&page_fd);
	return ret;
}

static int write_file_map(context_t *ctx, pid_t pid, struct vma_struct *vma)
{
	int rfd = fdset_fd(ctx->fdset_glob, CR_FD_REG_FILES);
	RegFileEntry rfe = REG_FILE_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;
	int ret;

	if (vma->file->dumped)
		return 0;

	fill_fown(&fown, vma->file);

	rfe.id		= obj_id_of(vma->file);
	rfe.pos		= vma->file->fi.cpt_pos;
	rfe.fown	= &fown;
	rfe.name	= vma->file->name;

	if (vmai_is(vma, VM_WRITE) && vma_is(vma, VMA_FILE_SHARED))
		rfe.flags = O_RDWR;
	else
		rfe.flags = O_RDONLY;

	ret = pb_write_one(rfd, &rfe, PB_REG_FILES);
	if (!ret)
		vma->file->dumped = 1;

	return ret;
}

int write_vmas(context_t *ctx, pid_t pid, off_t cpt_mm)
{
	VmaEntry e = VMA_ENTRY__INIT;
	int fd_vmas = -1, ret = -1;
	struct vma_struct *vma;
	struct mm_struct *mm;

	mm = obj_lookup_to(CPT_OBJ_MM, cpt_mm);
	if (!mm)
		return -1;

	fd_vmas = open_image(ctx, CR_FD_VMAS, O_DUMP, pid);
	if (fd_vmas < 0)
		return -1;

	list_for_each_entry(vma, &mm->vma_list, list) {

		if (!vma_is(vma, VMA_AREA_REGULAR))
			continue;

		e.start		= vma->vmai.cpt_start;
		e.end		= vma->vmai.cpt_end;
		e.pgoff		= vma->vmai.cpt_pgoff << PAGE_SHIFT;
		e.prot		= vma_flags_to_prot(vma->vmai.cpt_flags);
		e.status	= vma->status;
		e.fd		= -1;

		if (vma_is_shared(vma))
			e.flags = MAP_SHARED;
		else
			e.flags = MAP_PRIVATE;

		if (vma_is(vma, VMA_ANON_SHARED | VMA_ANON_PRIVATE))
			e.flags |= MAP_ANONYMOUS;

		if (vmai_is(vma, VM_GROWSDOWN))
			e.flags |= MAP_GROWSDOWN;

		if (vmai_is(vma, VM_DENYWRITE))
			e.flags |= MAP_DENYWRITE;

		if (vmai_is(vma, VM_ACCOUNT))
			e.flags |= MAP_NORESERVE;

		if (vma_is(vma, VMA_FILE_SHARED | VMA_FILE_PRIVATE)) {
			e.shmid = obj_id_of(vma->file);
			if (write_file_map(ctx, pid, vma))
				goto err;
		} else if (vma_is(vma, VMA_ANON_SHARED)) {
			e.shmid = vma->file ? obj_id_of(vma->file) : -1;
			if (shmem_add(vma, e.shmid, pid))
				goto err;
		} else if (vma_is(vma, VMA_AREA_SOCKET)) {
			pr_err("Sockets are not yet supported\n");
			goto err;
		}

		if (pb_write_one(fd_vmas, &e, PB_VMAS)) {
			pr_err("Can't write VMA at @%li\n", obj_pos_of(vma));
			goto err;
		}
	}
	ret = 0;

out:
	close_safe(&fd_vmas);
	return ret;

err:
	pr_err("Error while handling VMA %lx-%lx\n",
	       (long)vma->vmai.cpt_start, (long)vma->vmai.cpt_end);
	goto out;
}

int write_mm(context_t *ctx, pid_t pid, off_t cpt_mm)
{
	MmEntry e = MM_ENTRY__INIT;
	struct mm_struct *mm;
	int fd, ret = -1;

	mm = obj_lookup_to(CPT_OBJ_MM, cpt_mm);
	if (!mm)
		return -1;

	fd = open_image(ctx, CR_FD_MM, O_DUMP, pid);
	if (fd < 0)
		return -1;

	e.mm_start_code		= mm->mmi.cpt_start_code;
	e.mm_end_code		= mm->mmi.cpt_end_code;
	e.mm_start_data		= mm->mmi.cpt_start_data;
	e.mm_end_data		= mm->mmi.cpt_end_data;
	e.mm_start_stack	= mm->mmi.cpt_start_stack;
	e.mm_start_brk		= mm->mmi.cpt_start_brk;
	e.mm_brk		= mm->mmi.cpt_brk;
	e.mm_arg_start		= mm->mmi.cpt_start_arg;
	e.mm_arg_end		= mm->mmi.cpt_end_arg;
	e.mm_env_start		= mm->mmi.cpt_start_env;
	e.mm_env_end		= mm->mmi.cpt_end_env;

	e.exe_file_id		= obj_id_of(mm->exec_vma->file);
	e.n_mm_saved_auxv	= mm->auxv.nwords;
	e.mm_saved_auxv		= (void *)mm->auxv.vector;

	if (write_reg_file_entry(ctx, mm->exec_vma->file)) {
		pr_err("Can't add exe_file_id link\n");
		goto out;
	}

	ret = pb_write_one(fd, &e, PB_MM);
out:
	close(fd);
	return ret;
}

static void show_auxv_cont(context_t *ctx, struct mm_struct *mm)
{
	unsigned int i;

	pr_debug("\t\tauxv @%-10li\n", (long)mm->auxv.start);

	pr_debug("\t\t\t");
	for (i = 0; i < mm->auxv.nwords; i++) {
		pr_debug("%#016lx ", mm->auxv.vector[i]);
		if (i && (i % 4) == 0)
			pr_debug("\n\t\t\t");
	}
	pr_debug("\n");
}

static int read_mm_auxv(context_t *ctx, struct mm_struct *mm, off_t start, off_t end)
{
	if (read_obj_hdr(ctx->fd, &mm->auxv.hdr, start)) {
		pr_err("Can't read AUXV header at @%li\n", (long)start);
		return -1;
	}

	mm->auxv.nwords  = (mm->auxv.hdr.cpt_next - mm->auxv.hdr.cpt_hdrlen);
	mm->auxv.nwords /= sizeof(mm->auxv.vector[0]);

	if (mm->auxv.nwords > AT_VECTOR_SIZE - 2) {
		pr_err("Too many words in AUXV %d\n", mm->auxv.nwords);
		return -1;
	}

	if (__read(ctx->fd, mm->auxv.vector,
		   (mm->auxv.hdr.cpt_next - mm->auxv.hdr.cpt_hdrlen))) {
		pr_err("Failed reading AUXV at @%li\n", (long)start);
		return -1;
	}

	mm->auxv.vector[mm->auxv.nwords + 0] = 0;
	mm->auxv.vector[mm->auxv.nwords + 1] = 0;

	mm->auxv.start = start;
	show_auxv_cont(ctx, mm);

	return 0;
}

static char *vma_name(struct vma_struct *vma)
{
	if (vma_is(vma, VMA_AREA_STACK))
		return "stack";
	else if (vma_is(vma, VMA_AREA_VSYSCALL))
		return "vsyscall";
	else if (vma_is(vma, VMA_AREA_VDSO))
		return "vdso";
	else if (vma_is(vma, VMA_AREA_HEAP))
		return "heap";
	else if (vma_is(vma, VMA_AREA_SYSVIPC))
		return "sysvipc";
	else if (vma_is(vma, VMA_AREA_SOCKET))
		return "socket";
	else if (vma_is(vma, VMA_FILE_PRIVATE))
		return "file private mmap";
	else if (vma_is(vma, VMA_FILE_SHARED))
		return "file shared mmap";
	else if (vma_is(vma, VMA_ANON_SHARED))
		return "anon shared mmap";
	else if (vma_is(vma, VMA_ANON_PRIVATE))
		return "anon private mmap";

	return "unknown";
}

static void show_vma_cont(context_t *ctx, struct vma_struct *vma)
{
	pr_debug("\t\tvma @%-10li file @%-10li type %2d start %#16lx end %#16lx\n"
		 "\t\t\tflags %#8lx pgprot %#16lx pgoff %#10lx\n"
		 "\t\t\tanonvma %#8x anonvmaid %#8lx\n"
		 "\t\t\t(%c%c%c) (%c) (%#x -> [%s])\n"
		 "\t\t\t(%li direct payload bytes)\n",
		 obj_pos_of(vma), (long)vma->vmai.cpt_file,
		 vma->vmai.cpt_type, (long)vma->vmai.cpt_start,
		 (long)vma->vmai.cpt_end, (long)vma->vmai.cpt_flags,
		 (long)vma->vmai.cpt_pgprot, (long)vma->vmai.cpt_pgoff,
		 vma->vmai.cpt_anonvma, (long)vma->vmai.cpt_anonvmaid,

		 vmai_is(vma, VM_READ) ? 'r' : '-',
		 vmai_is(vma, VM_WRITE) ? 'w' : '-',

		 vmai_is(vma, VM_EXEC | VM_EXECUTABLE) ? 'x' : '-',
		 vmai_is_shared(vma) ? 's' : 'p',

		 vma->status, vma_name(vma),
		 (long)(vma->vmai.cpt_next - vma->vmai.cpt_hdrlen));
}

static int vma_parse(context_t *ctx, struct mm_struct *mm,
		     struct vma_struct *vma)
{
	struct inode_struct *inode = NULL;
	struct file_struct *file = NULL;

	if (vma->vmai.cpt_file != -1) {
		file = obj_lookup_to(CPT_OBJ_FILE, vma->vmai.cpt_file);
		if (!file)
			goto err;

		if (file->fi.cpt_inode != -1) {
			inode = obj_lookup_to(CPT_OBJ_INODE, file->fi.cpt_inode);
			if (!inode)
				goto err;
		}

		vma->file = file;
	}

	vma->status = VMA_AREA_REGULAR;

	switch (vma->vmai.cpt_type) {
	case CPT_VMA_TYPE_0:
		if (file) {
			if (is_dev_zero(file)) {
				if (!vmai_is_shared(vma)) {
					pr_err("Private mapping on share entry\n");
					goto err;
				}
				vma->status |= VMA_ANON_SHARED;
			} else {
				if (vmai_is_shared(vma))
					vma->status |= VMA_FILE_SHARED;
				else
					vma->status |= VMA_FILE_PRIVATE;
			}
		} else {
			/*
			 * No file associated -- anonymous private
			 */
			if (vmai_is_shared(vma)) {
				pr_err("No file associated on shared memory\n");
				goto err;
			}
			vma->status |= VMA_ANON_PRIVATE;
		}
		break;
	case CPT_VMA_TYPE_SHM:
		if (!file) {
			pr_err("SysV shmem area without file found\n");
			goto err;
		}
		vma->status |= VMA_ANON_SHARED | VMA_AREA_SYSVIPC;
		break;
	case CPT_VMA_VDSO:
	case CPT_VMA_VDSO_OLD:
		if (file) {
			pr_err("VDSO area with file found\n");
			goto err;
		}
		vma->status |= VMA_ANON_PRIVATE | VMA_AREA_VDSO;
		break;
	}

	if (vma->vmai.cpt_start <= mm->mmi.cpt_start_brk &&
	    vma->vmai.cpt_end >= mm->mmi.cpt_brk) {
		vma->status |= VMA_AREA_HEAP;
	} else if (vma->vmai.cpt_start <= mm->mmi.cpt_start_stack
		   && vma->vmai.cpt_end >= mm->mmi.cpt_start_stack) {
		vma->status |= VMA_AREA_STACK;
	} else if (vma->vmai.cpt_start >= VSYSCALL_START &&
		 vma->vmai.cpt_end <= VSYSCALL_END) {
		/*
		 * cpt image do not tell us if vma is
		 * vsyscall area so we need to figure it
		 * out by self
		 *
		 * FIXME It's valid for x86-64 only
		 */
		vma->status &= ~VMA_AREA_REGULAR;
		vma->status |= VMA_AREA_VSYSCALL;
	}

	return 0;

err:
	pr_err("Error while parsing VMA %lx-%lx\n",
	       (long)vma->vmai.cpt_start, (long)vma->vmai.cpt_end);
	return -1;
}

static int read_mm_vma(context_t *ctx, struct mm_struct *mm, off_t start, off_t end)
{
	struct vma_struct *vma;

	vma = obj_alloc_to(struct vma_struct, vmai);
	if (!vma)
		return -1;

	INIT_LIST_HEAD(&vma->list);
	vma->status = 0;
	vma->file = NULL;

	if (read_obj_cpt(ctx->fd, CPT_OBJ_VMA, &vma->vmai, start)) {
		pr_err("Can't read VMA at @%li\n", (long)start);
		obj_free_to(vma);
		return -1;
	}

	list_add_tail(&vma->list, &mm->vma_list);
	obj_hash_typed_to(vma, CPT_OBJ_VMA, start);

	if (vma->vmai.cpt_file != -1 && (vma->vmai.cpt_flags & VM_EXECUTABLE))
		mm->exec_vma = vma;

	if (vma_parse(ctx, mm, vma)) {
		pr_err("Can't parse VMA at @%li\n", (long)start);
		return -1;
	}

	show_vma_cont(ctx, vma);
	return 0;
}

static int read_mm_payload(context_t *ctx, struct mm_struct *mm,
			   off_t start, off_t end)
{
	struct cpt_object_hdr h;

	for (; start < end; start += h.cpt_next) {
		if (read_obj_hdr(ctx->fd, &h, start)) {
			pr_err("Can't read MM payload header at @%li\n", (long)start);
			return -1;
		}

		switch (h.cpt_object) {
		case CPT_OBJ_VMA:
			if (read_mm_vma(ctx, mm, start, end))
				return -1;
			break;
		case CPT_OBJ_MM_AUXV:
			if (read_mm_auxv(ctx, mm, start, end))
				return -1;
			break;
		default:
			pr_debug("\t\tobject %s skipped\n", obj_name(h.cpt_object));
			break;
		}
	}

	return 0;
}

int read_mm(context_t *ctx)
{
	off_t start, end;
	int ret = -1;

	pr_read_start("mm\n");
	get_section_bounds(ctx, CPT_SECT_MM, &start, &end);

	while (start < end) {
		struct mm_struct *mm = obj_alloc_to(struct mm_struct, mmi);
		if (!mm)
			return -1;
		INIT_LIST_HEAD(&mm->vma_list);
		mm->exec_vma = NULL;
		memzero(&mm->auxv, sizeof(mm->auxv));

		if (read_obj_cpt(ctx->fd, CPT_OBJ_MM, &mm->mmi, start)) {
			obj_free_to(mm);
			pr_err("Can't read task mm at @%li\n", (long)start);
			return -1;
		}

		obj_push_hash_to(mm, CPT_OBJ_MM, start);
		show_mmi_cont(ctx, mm);

		if (read_mm_payload(ctx, mm, start + mm->mmi.cpt_hdrlen, start + mm->mmi.cpt_next))
			goto out;

		if (!mm->exec_vma) {
			pr_err("No self-exe vma found for MM at @%li\n", obj_pos_of(mm));
			goto out;
		} else if (!mm->auxv.nwords) {
			pr_err("No auxv found for MM at @%li\n", obj_pos_of(mm));
			goto out;
		}

		start += mm->mmi.cpt_next;
	}

	pr_read_end();
	ret = 0;
out:
	return ret;
}
