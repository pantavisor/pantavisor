/*
 * Copyright (c) 2021 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <signal.h>
#include "fops.h"
#include "tsh.h"

int pv_fops_set_file_xattr(const char *filename, char *attr, char *value)
{
	int val_len = getxattr(filename, attr, NULL, 0);
	int set_flag = XATTR_REPLACE;
	int ret = 0;

	if (val_len < 0 && errno == ENODATA)
		set_flag = XATTR_CREATE;
	ret = setxattr(filename, attr, value, strlen(value), set_flag);
	return ret < 0 ? -errno : ret;
}


int pv_fops_get_file_xattr(const char *filename, char *attr, char **dst, int(*alloc)(char**, int))
{
	int val_len = -1;

	val_len = getxattr(filename, attr, NULL, 0);
	if (val_len > 0) {
		int ret = 0;

		if (alloc)
			ret = alloc(dst, val_len + 1);
		if (!ret)
			val_len = getxattr(filename, attr, *dst, val_len);
	}
	return val_len < 0 ? -errno : val_len;
}

ssize_t pv_fops_write_nointr(int fd, char *buf, ssize_t len)
{
	ssize_t written = 0;

	while (written != len) {
		int __written = write(fd, buf + written, len - written);

		if (__written < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		written += __written;
	}
	return written;
}

ssize_t pv_fops_read_nointr(int fd, char *buf, ssize_t len)
{
	ssize_t nr_read = 0;

	while (nr_read != len) {
		int __read = read(fd, buf + nr_read, len - nr_read);

		if (__read < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (__read == 0)
			break;
		nr_read += __read;
	}
	return nr_read;
}

int pv_fops_lock_file(int fd)
{
	struct flock flock;
	int ret = 0;

	flock.l_whence = SEEK_SET;
	/*Lock the whole file*/
	flock.l_len = 0;
	flock.l_start = 0;
	flock.l_type = F_WRLCK;

	while ( (ret = fcntl(fd, F_SETLK, &flock)) < 0 && errno == EINTR)
		;
	return ret;
}

/*
 * Returns the open file descriptor, if successful.
 * */
int pv_fops_open_and_lock_file(const char *fname, int flags, mode_t mode)
{
	int fd = -1;
	int ret = -1;

	fd = open(fname, flags, mode);
	if (fd >= 0)
		ret = pv_fops_lock_file(fd);
	if (ret) {
		close(fd);
		fd = -1;
	}
	return fd;
}

int pv_fops_unlock_file(int fd)
{
	struct flock flock;
	int ret = 0;

	flock.l_whence = SEEK_SET;
	/*Lock the whole file*/
	flock.l_len = 0;
	flock.l_start = 0;
	flock.l_type = F_UNLCK;

	while ( (ret = fcntl(fd, F_SETLK, &flock)) < 0 && errno == EINTR)
		;
	return ret;
}

int pv_fops_gzip_file(const char *filename, const char *target_name)
{
	int __outfile[] = {-1, -1};
	char cmd[PATH_MAX + 32];

	snprintf(cmd, sizeof(cmd), "gzip %s", filename);
	__outfile[1] = open(target_name, O_RDWR | O_APPEND | O_CREAT);
	if (__outfile[1] >= 0) {
		tsh_run_io(cmd, 1, NULL, NULL, __outfile, NULL);
		close(__outfile[1]);
		return 0;
	}
	return -1;
}

int pv_fops_check_and_open_file(const char *fname, int flags, mode_t mode)
{
	struct stat st;
	int fd = -1;

	if (!fname)
		goto out;
	if (stat(fname, &st))
		goto out;
	fd = open(fname, flags, mode);
out:
	return fd;
}

int pv_fops_copy_and_close(int s_fd, int d_fd)
{
	int bytes_r = 0, bytes_w = 0;
	char buf[4096];

	lseek(s_fd, 0, SEEK_SET);
	lseek(d_fd, 0, SEEK_SET);

	while (bytes_r = read(s_fd, buf, sizeof(buf)), bytes_r > 0)
		bytes_w += write(d_fd, buf, bytes_r);

	close(s_fd);

	return bytes_r;
}
