/*
 * Copyright (c) 2023 Pantacor Ltd.
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

#ifndef PV_DISK_UTILS_H
#define PV_DISK_UTILS_H

#include "disk.h"

#include <stdbool.h>

int pv_disk_utils_run_cmd(const char *tmpl, const char *out_name,
			  const char *err_name, ...);

pv_disk_status_t pv_disk_utils_is_mounted(struct pv_disk *disk,
					  const char *source,
					  bool check_mount_point);
int pv_disk_utils_mount(struct pv_disk *disk);
int pv_disk_utils_umount(struct pv_disk *disk);
int pv_disk_utils_format(struct pv_disk *disk);
int pv_disk_utils_mkswap(struct pv_disk *disk);
int pv_disk_utils_swapon(struct pv_disk *disk);
int pv_disk_utils_swapoff(struct pv_disk *disk);
int pv_disk_utils_create_file(const char *path, const char *size);

#endif
