/*
 * Copyright (c) 2024-2025 Pantacor Ltd.
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

#ifndef PV_DISK_ZRAM_UTILS_H
#define PV_DISK_ZRAM_UTILS_H

#include <stddef.h>

int pv_disk_zram_utils_find_or_create_device(void);
int pv_disk_zram_utils_reset(int devno);
int pv_disk_zram_utils_set_compression(int devno, const char *comp);
int pv_disk_zram_utils_set_size(int devno, const char *size);
int pv_disk_zram_utils_set_streams(int devno, const char *n);
int pv_disk_zram_utils_set_multple_ops(int devno, char *options);
int pv_disk_zram_utils_get_compression(int devno, char *buf, size_t size);
int pv_disk_zram_utils_get_size(int devno, char *buf, size_t size);
int pv_disk_zram_utils_get_stream(int devno, char *buf, size_t size);
char *pv_disk_zram_utils_get_path(int devno);
int pv_disk_zram_utils_get_devno(const char *path);

#endif
