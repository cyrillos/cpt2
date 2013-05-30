#ifndef __CPT2_IMAGE_H__
#define __CPT2_IMAGE_H__

#include <sys/stat.h>
#include <fcntl.h>

#include "magic.h"
#include "image-desc.h"

#include "context.h"
#include "fdset.h"
#include "types.h"
#include "io.h"

#define read_img(fd, ptr)	__read_ptr(fd, ptr)
#define write_img(fd, ptr)	__write_ptr(fd, ptr)

#define CR_FD_PERM	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)

#define O_DUMP		(O_RDWR | O_CREAT | O_EXCL)

extern int open_image(context_t *ctx, int type, int flags, ...);
extern int open_image_fdset(context_t *ctx, struct fdset *fdset, pid_t pid,
			    unsigned int from, unsigned int to, int flags);

#endif /* __CPT2_IMAGE_H__ */
