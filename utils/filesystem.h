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

#ifndef UTILS_FILESYSTEM_H
#define UTILS_FILESYSTEM_H

#include <stdbool.h>
#include <sys/types.h>

/*
 * Check if the given path exist
 * */
bool pv_filesystem_path_exist(const char *path);
/*
 * check if the given path is a directory
 * */
bool pv_filesystem_path_is_directory(const char *path);
/*
 * Sync the given path. If path points to a file,
 * then the parent folder is synced
 * */
void pv_filesystem_path_sync(const char *path);
/*
 * Path concatenation, the value is returned on the given buffer
 * */
void pv_filesystem_path_concat(char *buf, int size, ...);
/*
 * Creates a directory with the given path and mode
 * All subdirectories will be created.
 * */
int pv_filesystem_mkdir_p(const char *path, mode_t mode);
/*
 * Remove a path (file or directory). If recursive is true then all
 * subdirectories will be deleted
 * */
int pv_filesystem_path_remove(const char *path, bool recursive);
/*
 * Rename a path(file or directory)
 * */
int pv_filesystem_path_rename(const char *src_path, const char *dst_path);
/*
 * Returns the file size for the given path
 * */
size_t pv_filesystem_path_get_size(const char *path);
/*
 * Creates a temporary path based on the given fname
 * */
int pv_filesystem_file_tmp(char *tmp, const char *fname);
/* Save the given data on fname using a specific mode.
 * If the file doesn't exist, will be created.
 * If file exists, it will be truncated.
 * */
int pv_filesystem_file_save(const char *fname, const char *data, mode_t mode);
/*
 * Copy a file from src to dst.
 * */
int pv_filesystem_file_copy_from_path(const char *src, const char *dst, mode_t mode);
/*
 * Copy the contents of the src file descriptor to dst. If close_src is true
 * the file pointed by src will be closed.
 * */
ssize_t pv_filesystem_file_copy_fd(int src, int dst, bool close_src);
/*
 * Get an extended attribute from the given file.
 * NOTE: This function recives a buffer (value) where the attribute
 * will be write, so is important to provide a buffer with the right size.
 * */
int pv_filesystem_file_get_xattr(char *value, size_t size, const char *fname, const char *attr);
/*
 * Set an extended attribute in the given file
 * */
int pv_filesystem_file_set_xattr(const char *fname, const char *attr, const char *value);
/*
 * Write the given buffer in the file pointed by fd.
 * NOTE: this function blocks until the file is completely written.
 * */
ssize_t pv_filesystem_file_write_nointr(int fd, const char *buf, ssize_t size);
/*
 * Reads into the given buffer from the file pointed by fd.
 * NOTE: this function blocks until the file completely read.
 * */
ssize_t pv_filesystem_file_read_nointr(int fd, char *buf, ssize_t size);
/*
 * Lock the given file descriptor
 * */
int pv_filesystem_file_lock(int fd);
/*
 * Unlock the given file descriptor
 * */
int pv_filesystem_file_unlock(int fd);
/*
 * Gzip the given file
 * */
int pv_filesystem_file_gzip(const char *fname, const char *target_name);
/*
 * Checks if the given file exists and open it usign the flags and mode
 * provided.
 * */
int pv_filesystem_file_check_and_open(const char *fname, int flags, mode_t mode);

#endif
