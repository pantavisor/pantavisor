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

#ifndef UTILS_PV_FILE_H_
#define UTILS_PV_FILE_H_

#include <sys/types.h>

char* pv_file_load(const char *path, const unsigned int max_size);
size_t pv_file_get_size(const char *path);

/*
 * Returns 0 on success.
 * For setting, value holds a null terminated string.
 * For get, the value is returned back in dst.
 */
int pv_file_set_file_xattr(const char *filename, char *attr, char *value);
int pv_file_get_file_xattr(const char *filename, char *attr, char **dst, int (*alloc)(char **, int));
ssize_t pv_file_write_nointr(int fd, char *buf, ssize_t len);
ssize_t pv_file_read_nointr(int fd, char *buf, ssize_t len);
int pv_file_lock_file(int fd);
/*
 * Returns the file descriptor on success.
 */
int pv_file_open_and_lock_file(const char *fname, int flags, mode_t mode);
int pv_file_unlock_file(int fd);
int pv_file_gzip_file(const char *filename, const char *target_name);
int pv_file_check_and_open_file(const char *fname, int flags, mode_t mode);
int pv_file_copy_and_close(int s_fd, int d_fd);

#endif /* UTILS_PV_FILE_H_ */
