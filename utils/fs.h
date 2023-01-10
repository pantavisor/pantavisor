/*
 * Copyright (c) 2022 Pantacor Ltd.
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
bool pv_fs_path_is_directory(const char *path);
void pv_fs_path_sync(const char *path);
void pv_fs_path_concat(char *buf, int size, ...);
int pv_fs_mkdir_p(const char *path, mode_t mode);
int pv_fs_mkbasedir_p(const char *path, mode_t mode);
int pv_fs_path_remove(const char *path, bool recursive);
int pv_fs_path_rename(const char *src_path, const char *dst_path);
off_t pv_fs_path_get_size(const char *path);
int pv_fs_file_tmp(char *tmp, const char *fname);
char *pv_fs_file_load(const char *path, off_t max);
int pv_fs_file_save(const char *fname, const char *data, mode_t mode);
int pv_fs_file_copy(const char *src, const char *dst, mode_t mode);

// This function doesn't perform sync
ssize_t pv_fs_file_copy_fd(int src, int dst, bool close_src);

// This function doesn't perform sync
ssize_t pv_fs_file_write_nointr(int fd, const char *buf, ssize_t size);
ssize_t pv_fs_file_read_nointr(int fd, char *buf, ssize_t size);
int pv_fs_file_lock(int fd);
int pv_fs_file_unlock(int fd);
int pv_fs_file_gzip(const char *fname, const char *target_name);
int pv_fs_file_check_and_open(const char *fname, int flags, mode_t mode);

#endif
