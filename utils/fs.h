/*
 * Copyright (c) 2022-2025 Pantacor Ltd.
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

#ifndef UTILS_FS_H
#define UTILS_FS_H

#include <stdbool.h>
#include <sys/types.h>

bool pv_fs_path_exist(const char *path);
bool pv_fs_path_exist_timeout(const char *path, unsigned int timeout);
bool pv_fs_path_is_directory(const char *path);
void pv_fs_path_sync(const char *path);
void pv_fs_path_concat(char *buf, int size, ...);
int pv_fs_mkdir_p(const char *path, mode_t mode);
int pv_fs_mkbasedir_p(const char *path, mode_t mode);
int pv_fs_path_remove(const char *path, bool recursive);
int pv_fs_path_rename(const char *src_path, const char *dst_path);
off_t pv_fs_path_get_size(const char *path);
int pv_fs_file_tmp(const char *fname, char *tmp);
int pv_fs_path_tmpdir(const char *fname, char *tmp);
char *pv_fs_file_load(const char *path, off_t max);
int pv_fs_file_save(const char *fname, const char *data, mode_t mode);
int pv_fs_file_copy(const char *src, const char *dst, mode_t mode);

// This function doesn't perform sync
ssize_t pv_fs_file_copy_fd(int src, int dst, bool close_src);

// This function doesn't perform sync
ssize_t pv_fs_file_write_nointr(int fd, const void *buf, ssize_t size);
ssize_t pv_fs_file_read_nointr(int fd, void *buf, ssize_t size);

// check path, open, read nointr and close
ssize_t pv_fs_file_read_to_buf(const char *path, char *buf, ssize_t size);

int pv_fs_file_lock(int fd);
int pv_fs_file_unlock(int fd);
int pv_fs_file_gzip(const char *fname, const char *target_name);
int pv_fs_file_check_and_open(const char *fname, int flags, mode_t mode);
bool pv_fs_file_is_same(const char *path1, const char *path2);
void pv_fs_basename(const char *path, char *base);
void pv_fs_dirname(const char *path, char *parent);
void pv_fs_extension(const char *path, char *ext);

void *pv_fs_file_read(const char *path, size_t *size);

int pv_fs_file_write_no_sync(const char *path, void *buf, ssize_t size);
int pv_fs_path_remove_recursive_no_sync(const char *path);
int pv_fs_file_copy_no_sync(const char *src, const char *dst, mode_t mode);

#endif
