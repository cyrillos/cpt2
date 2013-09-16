#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>

#include "io.h"
#include "log.h"

#undef LOG_PREFIX
#define LOG_PREFIX "io: "

bool io_read_only = false;

int __splice_data(int from, int to, size_t size)
{
	int attempts = 16; /* Default number of buffers in pipe */
	ssize_t ret_in, ret_out;
	int p[2];

	if (pipe(p)) {
		pr_perror("Can't create transport for splicing data");
		return -1;
	}

	while (size) {
		ret_in = splice(from, NULL, p[1], NULL, size, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (ret_in == -1) {
			pr_perror("Can't read %li bytes", (long)size);
			goto err;
		}

		ret_out = splice(p[0], NULL, to, NULL, size, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (ret_out == -1) {
			pr_perror("Can't write %li bytes", (long)size);
			goto err;
		}

		if (ret_in != ret_out) {
			pr_err("Error on pipe level %li:%li\n", (long)ret_in, (long)ret_out);
			goto err;
		}

		size -= ret_out;
		if (attempts-- < 0) {
			pr_err("Too many attempts to flush pipe data\n");
			goto err;
		}
	}

	return 0;
err:
	return -1;
}

int splice_data(int from, int to, size_t size)
{
	if (io_read_only)
		return 0;

	return __splice_data(from, to, size);
}

int read_data(int fd, void *ptr, size_t size, bool eof)
{
	ssize_t ret;

	ret = read(fd, ptr, size);
	if (ret == size)
		return 0;
	if (ret == 0) {
		if (eof)
			return 0;
		else
			return 1;
	}

	if (ret < 0)
		pr_perror("Can't read record from the file");
	else
		pr_err("Record trimmed %d/%d\n", (int)ret, (int)size);

	return -1;
}

int read_data_at(int fd, void *ptr, size_t size, off_t pos, bool eof)
{
	off_t cur = lseek(fd, pos, SEEK_SET);
	if (cur < 0) {
		pr_perror("Can't move file position\n");
		return -1;
	}

	return read_data(fd, ptr, size, eof);
}

int write_data(int fd, void *ptr, size_t size)
{
	ssize_t ret;

	if (io_read_only)
		return 0;

	ret = write(fd, ptr, size);
	if (ret == size)
		return 0;

	if (ret < 0)
		pr_perror("Can't write data to a file");
	else
		pr_err("Record has been trimmed %d/%d\n", (int)ret, (int)size);

	return -1;
}

/*
 * We don't use pwrite here simply because we can reuse error
 * messages from write_data() helper.
 */
int write_data_at(int fd, void *ptr, size_t size, off_t pos)
{
	off_t cur;

	if (io_read_only)
		return 0;

	cur = lseek(fd, pos, SEEK_SET);
	if (cur < 0) {
		pr_perror("Can't move file position\n");
		return -1;
	}

	return write_data(fd, ptr, size);
}

