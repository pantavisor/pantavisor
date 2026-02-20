/*
 * Copyright (c) 2021-2025 Pantacor Ltd.
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

#include "fs.h"
#include "tsh.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define PV_FS_BUF_SIZE (512)

static void close_fd(int *fd)
{
	if (!fd || *fd < 0)
		return;

	close(*fd);
	*fd = -1;
}

bool pv_fs_path_exist(const char *path)
{
	return access(path, F_OK) == 0;
}

bool pv_fs_path_exist_timeout(const char *path, unsigned int timeout)
{
	unsigned int i;
	for (i = 0; i < timeout; i++) {
		if (pv_fs_path_exist(path))
			return true;
		sleep(1);
	}
	return false;
}

bool pv_fs_path_is_directory(const char *path)
{
	DIR *tmp = opendir(path);
	if (tmp) {
		closedir(tmp);
		return true;
	}

	return false;
}

void pv_fs_path_sync(const char *path)
{
	char dir[PATH_MAX] = { 0 };
	if (!path)
		return;

	int fd = open(path, O_RDONLY);
	if (fd > -1) {
		fsync(fd);
		close(fd);
	}

	strncpy(dir, path, strnlen(path, PATH_MAX));
	char *sync_dir = dirname(dir);

	fd = open(sync_dir, O_RDONLY);
	if (fd > -1) {
		fsync(fd);
		close(fd);
	}
}

int pv_fs_mkdir_p(const char *path, mode_t mode)
{
	if (!path)
		return -1;

	if (pv_fs_path_exist(path))
		return 0;

	char cur_path[PATH_MAX] = { 0 };

	errno = 0;
	int i = -1;

	do {
		++i;
		if (i > 0 && (path[i] == '/' || path[i] == '\0')) {
			memcpy(cur_path, path, i);
			cur_path[i] = '\0';
			if (mkdir(cur_path, mode) != 0 && errno != EEXIST)
				return -1;
		}
	} while (path[i]);

	return 0;
}

int pv_fs_mkbasedir_p(const char *path, mode_t mode)
{
	int ret = -1;
	char *c, *tmp;
	tmp = strdup(path);
	c = strrchr(tmp, '/');

	if (c) {
		*c = '\0';
		ret = pv_fs_mkdir_p(tmp, mode);
	}

	free(tmp);
	return ret;
}

void pv_fs_path_concat(char *buf, int size, ...)
{
	char fmt[PATH_MAX] = { 0 };

	for (int i = 0; i < size; ++i) {
		fmt[i * 3 + 0] = '%';
		fmt[i * 3 + 1] = 's';
		fmt[i * 3 + 2] = '/';
	}

	va_list list;
	va_start(list, size);

	vsnprintf(buf, PATH_MAX, fmt, list);
	buf[strnlen(buf, PATH_MAX) - 1] = '\0';

	va_end(list);
}

int pv_fs_path_remove(const char *path, bool recursive)
{
	if (!recursive) {
		int ret = remove(path);
		pv_fs_path_sync(path);
		return ret;
	}

	struct dirent **arr = NULL;
	int n = scandir(path, &arr, NULL, alphasort);

	for (int i = 0; i < n; ++i) {
		char new_path[PATH_MAX] = { 0 };
		// discard . and .. from scandir
		if (!strcmp(arr[i]->d_name, ".") ||
		    !strcmp(arr[i]->d_name, ".."))
			goto free_dir;

		pv_fs_path_concat(new_path, 2, path, arr[i]->d_name);

		if (arr[i]->d_type == DT_DIR)
			pv_fs_path_remove(new_path, true);
		else
			pv_fs_path_remove(new_path, false);

	free_dir:
		free(arr[i]);
	}
	int ret = remove(path);
	free(arr);
	pv_fs_path_sync(path);

	return ret;
}

int pv_fs_path_rename(const char *src_path, const char *dst_path)
{
	pv_fs_path_sync(src_path);

	int ret = rename(src_path, dst_path);
	if (ret < 0)
		return ret;

	pv_fs_path_sync(dst_path);
	return 0;
}

int pv_fs_path_tmpdir(const char *fname, char *tmp)
{
	if (!fname)
		return -1;

	memset(tmp, 0, PATH_MAX);
	snprintf(tmp, PATH_MAX, "%s.tmp", fname);

	pv_fs_path_remove(tmp, true);

	if (pv_fs_mkdir_p(tmp, 0755) != 0) {
		memset(tmp, 0, PATH_MAX);
		return -1;
	}

	return 0;
}

int pv_fs_file_tmp(const char *fname, char *tmp)
{
	if (!fname)
		return -1;

	memset(tmp, 0, PATH_MAX);
	snprintf(tmp, PATH_MAX, "%s.tmp", fname);

	pv_fs_path_remove(tmp, false);

	int fd = open(tmp, O_RDWR | O_TRUNC | O_CLOEXEC | O_CREAT, 0600);
	if (fd < 0) {
		memset(tmp, 0, PATH_MAX);
		return -1;
	}

	return fd;
}

char *pv_fs_file_load(const char *path, off_t max)
{
	off_t size = pv_fs_path_get_size(path);
	if (size < 0)
		return NULL;

	if (max && (size > max)) {
		errno = EFBIG;
		return NULL;
	}

	char *buf = calloc(size + 1, sizeof(char));
	if (!buf)
		return NULL;

	int fd = open(path, O_RDONLY, 0664);
	if (fd < 0)
		goto out;

	if (read(fd, buf, size) < 0)
		goto out;

out:
	close_fd(&fd);
	return buf;
}

int pv_fs_file_save(const char *fname, const char *data, mode_t mode)
{
	if (!data) {
		errno = ENODATA;
		return -1;
	}

	int ret = -1;
	char tmp[PATH_MAX] = { 0 };
	int fd = pv_fs_file_tmp(fname, tmp);
	if (fd < 0)
		goto out;

	if (write(fd, data, strlen(data)) < 0)
		goto out;

	fchmod(fd, mode);
	fsync(fd);
	close_fd(&fd);
	pv_fs_path_sync(tmp);

	ret = pv_fs_path_rename(tmp, fname);

out:
	if (fd > 0)
		close_fd(&fd);

	pv_fs_path_remove(tmp, false);
	pv_fs_path_sync(tmp);

	return ret;
}

ssize_t pv_fs_file_copy_fd(int src, int dst, bool close_src)
{
	lseek(src, 0, SEEK_SET);
	lseek(dst, 0, SEEK_SET);

	char buf[4096] = { 0 };
	ssize_t read_bytes = 0;
	ssize_t write_bytes = 0;

	while (read_bytes = read(src, buf, 4096), read_bytes > 0)
		write_bytes += write(dst, buf, read_bytes);

	if (close_src)
		close_fd(&src);

	return write_bytes;
}

int pv_fs_file_copy(const char *src, const char *dst, mode_t mode)
{
	if (!pv_fs_path_exist(src))
		return -1;

	char tmp_path[PATH_MAX] = { 0 };
	int tmp_fd = pv_fs_file_tmp(dst, tmp_path);
	if (tmp_fd < 0)
		return -1;

	int ret = -1;
	int src_fd = open(src, O_RDONLY, 0);
	if (src_fd < 0)
		goto out;

	pv_fs_file_copy_fd(src_fd, tmp_fd, false);
	fchmod(tmp_fd, mode);

	ret = pv_fs_path_rename(tmp_path, dst);
out:
	if (src_fd > -1)
		close_fd(&src_fd);

	if (tmp_fd > -1) {
		fsync(tmp_fd);
		close_fd(&tmp_fd);
	}

	if (pv_fs_path_exist(tmp_path))
		pv_fs_path_remove(tmp_path, false);

	pv_fs_path_sync(src);
	pv_fs_path_sync(dst);

	return ret;
}

static off_t get_dir_size(const char *cur_path)
{
	off_t total = 0;
	DIR *dir = opendir(cur_path);
	if (!dir)
		return 0;

	struct dirent *entry = NULL;
	while ((entry = readdir(dir))) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		char path[PATH_MAX] = { 0 };
		snprintf(path, PATH_MAX, "%s/%s", cur_path, entry->d_name);

		struct stat st;
		if (stat(path, &st) == 0) {
			if (S_ISDIR(st.st_mode))
				total += get_dir_size(path);
			else
				total += st.st_size;
		}
	}
	closedir(dir);

	return total;
}

off_t pv_fs_path_get_size(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		return -1;

	if (S_ISDIR(st.st_mode))
		return get_dir_size(path);

	return st.st_size;
}

ssize_t pv_fs_file_write_nointr(int fd, const void *buf, ssize_t size)
{
	ssize_t written = 0;

	while (written != size) {
		ssize_t cur_write = write(fd, buf + written, size - written);

		if (cur_write < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		written += cur_write;
	}
	return written;
}

ssize_t pv_fs_file_read_nointr(int fd, void *buf, ssize_t size)
{
	ssize_t total_read = 0;
	errno = 0;

	while (total_read != size) {
		int cur_read = read(fd, buf + total_read, size - total_read);

		if (cur_read < 0) {
			if (errno == EINTR)
				continue;
			return total_read == 0 ? cur_read : total_read;
		}
		if (cur_read == 0)
			break;
		total_read += cur_read;
	}
	return total_read;
}

ssize_t pv_fs_file_read_to_buf(const char *path, char *buf, ssize_t size)
{
	int fd = pv_fs_file_check_and_open(path, O_RDONLY, 0);
	if (fd < 0)
		return -1;

	ssize_t read = pv_fs_file_read_nointr(fd, buf, size);
	close(fd);

	return read;
}

int pv_fs_file_lock(int fd)
{
	struct flock flock;

	flock.l_whence = SEEK_SET;
	// Lock the whole file
	flock.l_len = 0;
	flock.l_start = 0;
	flock.l_type = F_WRLCK;

	int ret = -1;
	do {
		ret = fcntl(fd, F_SETLK, &flock);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

int pv_fs_file_unlock(int fd)
{
	struct flock flock;

	flock.l_whence = SEEK_SET;
	// Lock the whole file
	flock.l_len = 0;
	flock.l_start = 0;
	flock.l_type = F_UNLCK;

	int ret = -1;
	do {
		ret = fcntl(fd, F_SETLK, &flock);
	} while (ret < 0 && errno == EINTR);

	return ret;
}

int pv_fs_file_gzip(const char *fname, const char *target_name)
{
	char cmd[PATH_MAX + 32];

	if (pv_fs_file_copy(fname, target_name, 0644) != 0)
		return -1;

	snprintf(cmd, sizeof(cmd), "gzip %s", target_name);
	tsh_run_io(cmd, 1, NULL, NULL, NULL, NULL);
	pv_fs_path_sync(target_name);
	return 0;
}

int pv_fs_file_check_and_open(const char *fname, int flags, mode_t mode)
{
	if (!pv_fs_path_exist(fname))
		return -1;
	return open(fname, flags, mode);
}

static int pv_fs_file_inode_get(const char *path, ino_t *inode)
{
	struct stat st = { 0 };
	if (stat(path, &st) != 0)
		return -1;

	*inode = st.st_ino;
	return 0;
}

bool pv_fs_file_is_same(const char *path1, const char *path2)
{
	ino_t ino1;
	ino_t ino2;

	if (pv_fs_file_inode_get(path1, &ino1) != 0)
		return false;

	if (pv_fs_file_inode_get(path2, &ino2) != 0)
		return false;

	return ino1 == ino2;
}

void pv_fs_basename(const char *path, char *base)
{
	char tmp[PATH_MAX] = { 0 };
	memccpy(tmp, path, '\0', PATH_MAX);
	char *p = basename(tmp);
	memccpy(base, p, '\0', NAME_MAX);
}

void pv_fs_dirname(const char *path, char *parent)
{
	char tmp[PATH_MAX] = { 0 };
	memccpy(tmp, path, '\0', PATH_MAX);
	char *p = dirname(tmp);
	memccpy(parent, p, '\0', PATH_MAX);
}

void pv_fs_extension(const char *path, char *ext)
{
	char base[NAME_MAX] = { 0 };
	pv_fs_basename(path, base);
	size_t size = strlen(base);
	if (!strncmp(base, "..", size) || !strncmp(base, ".", size))
		return;

	char *p = strrchr(base, '.');
	if (!p || p == &base[0])
		return;

	memccpy(ext, p, '\0', NAME_MAX);
}

void *pv_fs_file_read(const char *path, size_t *size)
{
	char *buf = NULL;
	off_t fsize = pv_fs_path_get_size(path);

	if (fsize < 0)
		goto out;

	buf = pv_fs_file_load(path, fsize);
out:
	if (size)
		*size = fsize;

	return buf;
}

int pv_fs_file_write_no_sync(const char *path, void *buf, ssize_t len)
{
	char tmp[PATH_MAX] = { 0 };
	int fd = pv_fs_file_tmp(path, tmp);
	if (fd < 0)
		return -1;

	ssize_t total = 0;
	while (total != len) {
		ssize_t to_write = len - total;
		if (to_write > PV_FS_BUF_SIZE)
			to_write = PV_FS_BUF_SIZE;
		ssize_t cur =
			pv_fs_file_write_nointr(fd, buf + total, to_write);
		if (cur > 0)
			total += cur;
	}

	close(fd);

	if (rename(tmp, path) != 0)
		return -1;

	pv_fs_path_remove_recursive_no_sync(tmp);

	return total == len ? 0 : -1;
}

int pv_fs_path_remove_recursive_no_sync(const char *path)
{
	DIR *dir = opendir(path);
	if (!dir)
		return -1;

	int ret = -1;
	struct dirent *entry = NULL;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0) {
			continue;
		}

		char new_path[PATH_MAX] = { 0 };
		pv_fs_path_concat(new_path, 2, path, entry->d_name);

		if (entry->d_type == DT_DIR) {
			if (pv_fs_path_remove_recursive_no_sync(new_path) != 0)
				goto out;
		} else {
			if (remove(new_path) != 0)
				goto out;
		}
	}

	if (remove(path) != 0)
		goto out;

	ret = 0;
out:
	closedir(dir);
	return ret;
}

int pv_fs_file_copy_no_sync(const char *src, const char *dst, mode_t mode)
{
	if (!pv_fs_path_exist(src))
		return -1;

	char tmp_path[PATH_MAX] = { 0 };
	int tmp_fd = pv_fs_file_tmp(dst, tmp_path);
	if (tmp_fd < 0)
		return -1;

	int ret = -1;
	int src_fd = open(src, O_RDONLY, 0);
	if (src_fd < 0)
		goto out;

	pv_fs_file_copy_fd(src_fd, tmp_fd, false);
	fchmod(tmp_fd, mode);

	ret = rename(tmp_path, dst);
out:
	if (src_fd > -1)
		close(src_fd);

	if (tmp_fd > -1)
		close(tmp_fd);

	if (pv_fs_path_exist(tmp_path))
		remove(tmp_path);

	return ret;
}

int pv_fs_path_copy_recursive_no_sync(const char *src, const char *dst)
{
        struct stat st;
        if (stat(src, &st) != 0)
                return -1;

        // If source is not a directory, just copy the file
        if (!S_ISDIR(st.st_mode)) {
                return pv_fs_file_copy_no_sync(src, dst, st.st_mode);
        }

        // Create destination directory
        if (mkdir(dst, st.st_mode) != 0 && errno != EEXIST)
                return -1;

        DIR *dir = opendir(src);
        if (!dir)
                return -1;

        int ret = -1;
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0) {
                        continue;
                }

                char src_path[PATH_MAX] = { 0 };
                char dst_path[PATH_MAX] = { 0 };
                pv_fs_path_concat(src_path, 2, src, entry->d_name);
                pv_fs_path_concat(dst_path, 2, dst, entry->d_name);

                if (entry->d_type == DT_DIR) {
                        if (pv_fs_path_copy_recursive_no_sync(src_path, dst_path) != 0)
                                goto out;
                } else {
                        struct stat file_st;
                        if (stat(src_path, &file_st) != 0)
                                goto out;
                        if (pv_fs_file_copy_no_sync(src_path, dst_path, file_st.st_mode) != 0)
                                goto out;
                }
        }

        // Preserve permissions on the directory
        chmod(dst, st.st_mode);

        ret = 0;
out:
        closedir(dir);
        return ret;
}

int pv_fs_rename_safe_noatomic(const char *oldpath, const char *newpath)
{
	// Try atomic rename first
	if (rename(oldpath, newpath) == 0) {
		return 0;
	}

	// If cross-device, fall back to copy + remove
	if (errno == EXDEV) {
		if (pv_fs_path_copy_recursive_no_sync(oldpath, newpath) != 0) {
			return -1;
		}

		if (pv_fs_path_remove_recursive_no_sync(oldpath) != 0) {
			return -1;
		}

		return 0;
	}

	return -1;
}