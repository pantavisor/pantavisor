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

#include "disk_impl.h"
#include "disk_utils.h"
#include "disk_volume.h"
#include "disk_zram_utils.h"
#include "disk.h"
#include "utils/fs.h"

#include <string.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#define MODULE_NAME "disk-zram"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static int pv_disk_zram_init(struct pv_disk *disk)
{
	if (!disk->provision) {
		pv_log(ERROR, "disk definition error, provision not defined");
		return -1;
	}

	if (!disk->type) {
		pv_log(ERROR, "disk definition error, type not defined");
		return -1;
	}

	if (disk->type != DISK_SWAP && disk->type != DISK_VOLUME) {
		pv_log(ERROR, "unknow disk type for %s", disk->name);
		return -1;
	}

	int devno = pv_disk_zram_utils_find_or_create_device();
	if (devno < 0) {
		pv_log(WARN, "cannot create or find a zram device");
		return -1;
	}

	disk->path = pv_disk_zram_utils_get_path(devno);
	pv_log(DEBUG, "using disk %s", disk->path);

	int not_set =
		pv_disk_zram_utils_set_multple_ops(devno, disk->provision_ops);
	if (not_set > 0)
		pv_log(WARN, "warning some options cannot be set for %s",
		       disk->path);

	if (disk->type == DISK_VOLUME)
		return pv_disk_volume_init(disk);
	return 0;
}

static pv_disk_status_t pv_disk_zram_status(struct pv_disk *disk)
{
	if (disk->type == DISK_VOLUME) {
		return pv_disk_utils_is_mounted(disk, "/proc/self/mounts",
						true);
	} else if (disk->type == DISK_SWAP) {
		return pv_disk_utils_is_mounted(disk, "/proc/swaps", false);
	}
	pv_log(ERROR, "disk %s has unknown type");
	return DISK_STATUS_ERROR;
}

static int pv_disk_zram_format(struct pv_disk *disk)
{
	if (disk->type == DISK_VOLUME)
		return pv_disk_utils_format(disk);
	else if (disk->type == DISK_SWAP)
		return pv_disk_utils_mkswap(disk);
	return -1;
}

static int pv_disk_zram_mount(struct pv_disk *disk)
{
	if (disk->type == DISK_VOLUME)
		return pv_disk_utils_mount(disk);
	else if (disk->type == DISK_SWAP)
		return pv_disk_utils_swapon(disk);
	return -1;
}

static int pv_disk_zram_umount(struct pv_disk *disk)
{
	int ret = 0;
	if (disk->type == DISK_VOLUME)
		ret = pv_disk_utils_umount(disk);
	else if (disk->type == DISK_SWAP)
		ret = pv_disk_utils_swapoff(disk);

	if (ret != 0)
		return ret;

	int devno = pv_disk_zram_utils_get_devno(disk->path);
	pv_disk_zram_utils_reset(devno);
	return 0;
	pv_log(DEBUG, "ZRAM_UMOUNT");
	return 0;
}

struct pv_disk_impl zram_impl = {
	.init = pv_disk_zram_init,
	.status = pv_disk_zram_status,
	.format = pv_disk_zram_format,
	.mount = pv_disk_zram_mount,
	.umount = pv_disk_zram_umount,
};
