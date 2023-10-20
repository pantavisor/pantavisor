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

#include "disk.h"
#include "disk_impl.h"
#include "paths.h"
#include "utils/tsh.h"
#include "utils/fs.h"
#include "logserver/logserver.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <linux/limits.h>

#define MODULE_NAME "disk"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define DISK_ZRAM_CONFIG_PATH "/sys/devices/virtual/block/%s/%s"

static void pv_disk_free(struct pv_disk *disk)
{
	if (disk->name)
		free(disk->name);
	if (disk->path)
		free(disk->path);
	if (disk->uuid)
		free(disk->uuid);
	if (disk->mount_ops)
		free(disk->mount_ops);
	if (disk->format_ops)
		free(disk->format_ops);
	if (disk->provision_ops)
		free(disk->provision_ops);
	if (disk->provision)
		free(disk->provision);

	free(disk);
}

void pv_disk_empty(struct pv_state *s)
{
	if (!s)
		return;

	int num_disk = 0;
	struct pv_disk *d, *tmp;
	struct dl_list *disks = &s->disks;

	if (!disks)
		return;

	// Iterate over all disks from state
	dl_list_for_each_safe(d, tmp, disks, struct pv_disk, list)
	{
		pv_log(DEBUG, "removing disk %s", d->name);
		dl_list_del(&d->list);
		pv_disk_free(d);
		num_disk++;
	}

	pv_log(INFO, "removed %d disks", num_disk);
}

static int mount_disk(struct pv_disk *disk, struct pv_disk_impl *impl)
{
	pv_log(DEBUG, "trying to mount disk %s", disk->name);

	pv_disk_status_t status = impl->status(disk);
	if (status == DISK_STATUS_MOUNTED) {
		pv_log(DEBUG, "disk %s already mounted", disk->path);
		return 0;
	} else if (status == DISK_STATUS_ERROR) {
		pv_log(WARN, "disk %s status error", disk->path);
		return -1;
	}

	if (impl->format(disk) != 0) {
		pv_log(WARN, "cannot format %s, the disk will not be used",
		       disk->path);
		return -1;
	}

	if (impl->mount(disk) != 0) {
		pv_log(WARN, "cannot mount %s, the disk will not be used",
		       disk->path);
		return -1;
	}

	pv_log(DEBUG, "disk %s mounted!", disk->name);
	return 0;
}

static int umount_disk(struct pv_disk *disk, struct pv_disk_impl *impl)
{
	pv_disk_status_t status = impl->status(disk);

	if (status == DISK_STATUS_NOT_MOUNTED) {
		pv_log(DEBUG, "disk %s already not mounted", disk->path);
		return 0;
	} else if (status == DISK_STATUS_ERROR) {
		pv_log(WARN, "disk %s status error", disk->path);
		return -1;
	}

	if (impl->umount(disk) != 0) {
		pv_log(WARN, "cannot umount %s", disk->path);
		return -1;
	}

	return 0;
}

int pv_disk_mount_handler(struct pv_disk *disk, const char *action)
{
	struct pv_disk_impl *impl = NULL;

	switch (disk->type) {
	case DISK_DM_CRYPT_CAAM:
	case DISK_DM_CRYPT_DCP:
	case DISK_DM_CRYPT_VERSATILE:
		impl = &crypt_impl;
		break;
	case DISK_SWAP:
		if (!disk->provision) {
			pv_log(ERROR,
			       "cannot use disk, must define a provision");
			return -1;
		}
		if (!strcmp(disk->provision, "zram")) {
			impl = &zram_impl;
		} else {
			impl = &swap_impl;
		}
		break;
	case DISK_VOLUME:
		if (!disk->provision) {
			pv_log(ERROR,
			       "cannot use disk, must define a provision");
			return -1;
#define PV_DISK_
		}

		if (!strcmp(disk->provision, "zram"))
			impl = &zram_impl;
		else
			impl = &volume_impl;
		break;
	case DISK_DIR:
	case DISK_UNKNOWN:
	default:
		pv_log(ERROR, "unknown disk type %d", disk->type);
		return -4;
	}

	if (impl->init(disk) != 0) {
		pv_log(WARN, "cannot init %s, the disk will not be used",
		       disk->path);
		return -1;
	}

	pv_log(DEBUG, "%s action %s", disk->name, action);

	int ret = 0;
	if (!strcmp(action, "mount")) {
		ret = mount_disk(disk, impl);
	} else if (!strcmp(action, "umount")) {
		ret = umount_disk(disk, impl);
	} else {
		pv_log(WARN, "unknown action '%s' cannot be executed", action);
		ret = -1;
	}

	return ret;
}

int pv_disk_mount_swap(struct pv_state *s)
{
	if (!s)
		return -1;

	struct pv_disk *d, *tmp;
	struct dl_list *disk = &s->disks;

	if (!disk)
		return -1;

	pv_log(INFO, "mounting all swap disk");
	dl_list_for_each_safe(d, tmp, disk, struct pv_disk, list)
	{
		if (d->type != DISK_SWAP)
			continue;

		int err = pv_disk_mount_handler(d, "mount");
		if (err != 0)
			pv_log(ERROR, "cannot mount %s", d->name);
	}

	return 0;
}

int pv_disk_umount_all(struct pv_state *s)
{
	int ret = 0;

	if (!s)
		return ret;

	struct pv_disk *d, *tmp;
	struct dl_list *disks = &s->disks;

	if (!disks)
		return ret;

	pv_log(INFO, "unmounting all disks...");
	dl_list_for_each_safe(d, tmp, disks, struct pv_disk, list)
	{
		int r;
		if ((r = pv_disk_mount_handler(d, "umount"))) {
			pv_log(ERROR, "error unmounting disk (%d), %s", r,
			       d->name);
			ret |= r;
		} else {
			pv_log(DEBUG, "successfully unmounted disk %s",
			       d->name);
		}
	}
	return ret;
}

struct pv_disk *pv_disk_add(struct pv_state *s)
{
	struct pv_disk *d = calloc(1, sizeof(struct pv_disk));

	if (d) {
		dl_list_init(&d->list);
		dl_list_add_tail(&s->disks, &d->list);
	}

	return d;
}
