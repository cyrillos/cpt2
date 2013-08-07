#ifndef __CPT2_IO_H__
#define __CPT2_IO_H__

#include <unistd.h>
#include <stdbool.h>

#include "log.h"

extern int splice_data(int from, int to, size_t size);

extern int read_data(int fd, void *ptr, size_t size, bool eof);
extern int read_data_at(int fd, void *ptr, size_t size, off_t pos, bool eof);

#define __read(fd, ptr, size)			read_data(fd, ptr, size, false)
#define __read_eof(fd, ptr, size)		read_data(fd, ptr, size, true)

#define __read_ptr(fd, ptr)			__read(fd, ptr, sizeof(*ptr))
#define __read_ptr_eof(fd, ptr)			__read_eof(fd, ptr, sizeof(*ptr))

#define __read_at(fd, ptr, size, pos)		read_data_at(fd, ptr, size, pos, false)
#define __read_eof_at(fd, ptr, size, pos)	read_data_at(fd, ptr, size, pos, true)

#define __read_ptr_at(fd, ptr, pos)		__read_at(fd, ptr, sizeof(*ptr), pos)
#define __read_ptr_eof_at(fd, ptr, pos)		__read_eof_at(fd, ptr, sizeof(*ptr), pos)

extern int write_data(int fd, void *ptr, size_t size);
extern int write_data_at(int fd, void *ptr, size_t size, off_t pos);

#define __write(fd, ptr, size)			write_data(fd, ptr, size)
#define __write_ptr(fd, ptr)			__write(fd, ptr, sizeof(*ptr))
#define __write_at(fd, ptr, size, pos)		write_data_at(fd, ptr, size, pos)
#define __write_ptr_at(fd, ptr, pos)		__write_at(fd, ptr, sizeof(*ptr), pos)

extern bool io_read_only;

static inline int close_safe(int *fd)
{
	int ret = 0;
	if (*fd > -1) {
		if (!io_read_only)
			ret = close(*fd);
		if (!ret)
			*fd = -1;
		else
			pr_perror("Unable to close fd %d", *fd);
	}

	return ret;
}

static inline int lseek_safe(int fd, off_t offset, int whence)
{
	off_t new;

	new = lseek(fd, offset, whence);
	if (new == (off_t)-1) {
		pr_perror("Failed to seek %li as %d\n",
			  (long)offset, whence);
		return -1;
	}

	return 0;
}

#endif /* __CPT2_IO_H__ */
