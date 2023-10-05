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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "disk_volume.h"
#include "disk_impl.h"
#include "disk_utils.h"

#include <sys/mount.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#define MODULE_NAME "disk-volume"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

int pv_disk_volume_init(struct pv_disk *disk)
{
	if (!disk->provision) {
		pv_log(ERROR, "disk definition error, provision not defined");
		return -1;
	}

	if (!disk->type) {
		pv_log(ERROR, "disk definition error, type not defined");
		return -1;
	}

	if (!disk->format) {
		pv_log(ERROR, "disk definition error, format not defined");
		return -1;
	}

	if (!disk->mount_target) {
		pv_log(ERROR,
		       "disk definition error, mount target not defined");
		return -1;
	}

	if (!disk->path) {
		pv_log(ERROR, "disk definition error, path not defined");
		return -1;
	}

	if (disk->format != DISK_FORMAT_EXT3 &&
	    disk->format != DISK_FORMAT_EXT4) {
		pv_log(ERROR,
		       "cannot identify format, disk %s will not be mounted",
		       disk->path);
		return -1;
	}

	return 0;
}

static pv_disk_status_t pv_disk_volume_status(struct pv_disk *disk)
{
	return pv_disk_utils_is_mounted(disk, "/proc/self/mounts", true);
}

static int pv_disk_volume_format(struct pv_disk *disk)
{
	return pv_disk_utils_format(disk);
}

static int pv_disk_volume_mount(struct pv_disk *disk)
{
	return pv_disk_utils_mount(disk);
}

static int pv_disk_volume_umount(struct pv_disk *disk)
{
	return pv_disk_utils_umount(disk);
}

struct pv_disk_impl volume_impl = {
	.init = pv_disk_volume_init,
	.status = pv_disk_volume_status,
	.format = pv_disk_utils_format,
	.mount = pv_disk_volume_mount,
	.umount = pv_disk_volume_umount,
};
