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

#include "file.h"
#include "fs.h"
#include "tsh.h"

#define TMP_PATH "%s.tmp"

char* pv_file_load(const char *path, const unsigned int max_size)
{
	struct stat st;
	unsigned int size;
	int fd, res;
	char *content = NULL;

	res = stat(path, &st);
	if (res < 0)
		goto out;
	size = st.st_size;

	if (max_size && (size > max_size)) {
		errno = EFBIG;
		goto out;
	}

	content = calloc(1, size+1);
	if (!content)
		goto out;

	fd = open(path, O_RDONLY, 0644);
	if (fd < 0)
		goto out;

	res = read(fd, content, size);
	if (res < 0)
		goto out;

	close(fd);
out:
	return content;
}

int pv_file_save(const char *path, const char *content, mode_t mode)
{
	int ret = -1, len, fd;
	char tmp_path[PATH_MAX];

	len = strlen(path) + strlen(TMP_PATH);
	if (len > PATH_MAX) {
		errno = ENOENT;
		goto out;
	}

	snprintf(tmp_path, len, TMP_PATH, path);
	fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC | O_SYNC, mode);
	if (fd < 0)
		goto out;

	ret = write(fd, content, strlen(content));
	if (ret < 0)
		goto out;

	close(fd);

	ret = rename(tmp_path, path);
	if (ret < 0)
		goto out;

	syncdir(path);

	ret = 0;

out:
	remove(tmp_path);
	syncdir(tmp_path);

	return ret;
}

int pv_file_copy(const char *src_path, const char *dst_path, mode_t mode)
{
	int ret = -1, len, s_fd, d_fd;
	int bytes_r = 0, bytes_w = 0;
	char buf[4096], tmp_path[PATH_MAX];

	s_fd = open(src_path, O_RDONLY, 0);
	if (s_fd < 0)
		goto out;

	len = strlen(dst_path) + strlen(TMP_PATH);
	if (len > PATH_MAX) {
		errno = ENOENT;
		goto out;
	}

	snprintf(tmp_path, len, TMP_PATH, dst_path);
	d_fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, mode);
	if (d_fd < 0)
		goto out;

	lseek(s_fd, 0, SEEK_SET);
	lseek(d_fd, 0, SEEK_SET);

	while (bytes_r = read(s_fd, buf, sizeof(buf)), bytes_r > 0)
		bytes_w += write(d_fd, buf, bytes_r);

	ret = bytes_r;

	close(d_fd);

	ret = rename(tmp_path, dst_path);
	if (ret < 0)
		goto out;

	syncdir(dst_path);

	ret = 0;

out:
	close(s_fd);
	remove(tmp_path);
	syncdir(tmp_path);
	syncdir(dst_path);

	return ret;
}

int pv_file_rename(const char *src_path, const char *dst_path)
{
	int ret = -1;

	syncdir(src_path);

	ret = rename(src_path, dst_path);
	if (ret < 0)
		goto out;

	syncdir(dst_path);

	ret = 0;

out:
	return ret;
}

int pv_file_remove(const char *path)
{
	int ret = -1;

	ret = remove(path);
	if (ret < 0)
		goto out;

	syncdir(path);

out:
	return ret;
}

size_t pv_file_get_size(const char *path)
{
	struct stat st;

	stat(path, &st);
	return st.st_size;
}

int pv_file_set_file_xattr(const char *filename, char *attr, char *value)
{
	int val_len = getxattr(filename, attr, NULL, 0);
	int set_flag = XATTR_REPLACE;
	int ret = 0;

	if (val_len < 0 && errno == ENODATA)
		set_flag = XATTR_CREATE;
	ret = setxattr(filename, attr, value, strlen(value), set_flag);
	return ret < 0 ? -errno : ret;
}


int pv_file_get_file_xattr(const char *filename, char *attr, char **dst, int(*alloc)(char**, int))
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

ssize_t pv_file_write_nointr(int fd, char *buf, ssize_t len)
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

ssize_t pv_file_read_nointr(int fd, char *buf, ssize_t len)
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

int pv_file_lock_file(int fd)
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
int pv_file_open_and_lock_file(const char *fname, int flags, mode_t mode)
{
	int fd = -1;
	int ret = -1;

	fd = open(fname, flags, mode);
	if (fd >= 0)
		ret = pv_file_lock_file(fd);
	if (ret) {
		close(fd);
		fd = -1;
	}
	return fd;
}

int pv_file_unlock_file(int fd)
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

int pv_file_gzip_file(const char *filename, const char *target_name)
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

int pv_file_check_and_open_file(const char *fname, int flags, mode_t mode)
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

int pv_file_copy_and_close(int s_fd, int d_fd)
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
