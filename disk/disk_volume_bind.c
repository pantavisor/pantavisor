/*
 * Copyright (c) 2025 Pantacor Ltd.
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

/*
 * volume-disk without a provision field: bind-mounts a persistent directory
 * from /storage into the ephemeral tmpfs at /run/pantavisor/media/pv/dmcrypt/<name>.
 *
 * The mount target path uses the "dmcrypt" namespace because volumes.c hardcodes
 * that namespace when building paths for disk-backed volumes.  The backing store
 * lives under /storage (Docker bind-mount from the workspace) so it survives
 * repeated pantavisor restarts within the same appengine container.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "disk.h"
#include "disk_impl.h"
#include "config.h"
#include "paths.h"
#include "utils/fs.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <linux/limits.h>

#define MODULE_NAME "disk-volume-bind"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static int pv_disk_volume_bind_init(struct pv_disk *disk)
{
	if (!disk->name) {
		pv_log(ERROR, "disk definition error, name not defined");
		return -1;
	}

	if (!disk->mount_target) {
		char buf[PATH_MAX];
		pv_paths_storage_mounted_disk_path(buf, sizeof(buf), "dmcrypt",
						   disk->name);
		disk->mount_target = strdup(buf);
		if (!disk->mount_target) {
			pv_log(ERROR, "OOM allocating mount_target for %s",
			       disk->name);
			return -1;
		}
	}

	return 0;
}

static pv_disk_status_t pv_disk_volume_bind_status(struct pv_disk *disk)
{
	struct stat st;

	if (!disk->mount_target)
		return DISK_STATUS_ERROR;

	if (stat(disk->mount_target, &st) == 0 && S_ISDIR(st.st_mode))
		return DISK_STATUS_MOUNTED;

	return DISK_STATUS_NOT_MOUNTED;
}

static int pv_disk_volume_bind_format(struct pv_disk *disk)
{
	return 0;
}

static int pv_disk_volume_bind_mount(struct pv_disk *disk)
{
	char backing[PATH_MAX];
	snprintf(backing, sizeof(backing), "%s/pv/volume-disk/%s",
		 pv_config_get_str(PV_STORAGE_MNTPOINT), disk->name);

	if (pv_fs_mkdir_p(backing, 0755) != 0) {
		pv_log(WARN, "cannot create backing dir %s: %s", backing,
		       strerror(errno));
		return -1;
	}

	if (pv_fs_mkdir_p(disk->mount_target, 0755) != 0) {
		pv_log(WARN, "cannot create mount target %s: %s",
		       disk->mount_target, strerror(errno));
		return -1;
	}

	if (mount(backing, disk->mount_target, "none", MS_BIND, NULL) != 0) {
		pv_log(WARN, "cannot bind-mount %s -> %s: %s", backing,
		       disk->mount_target, strerror(errno));
		return -1;
	}

	pv_log(DEBUG, "volume-disk %s bind-mounted %s -> %s", disk->name,
	       backing, disk->mount_target);
	return 0;
}

static int pv_disk_volume_bind_umount(struct pv_disk *disk)
{
	if (!disk->mount_target)
		return 0;

	if (umount(disk->mount_target) != 0) {
		pv_log(WARN, "cannot umount %s: %s", disk->mount_target,
		       strerror(errno));
		return -1;
	}

	return 0;
}

struct pv_disk_impl volume_bind_impl = {
	.init = pv_disk_volume_bind_init,
	.status = pv_disk_volume_bind_status,
	.format = pv_disk_volume_bind_format,
	.mount = pv_disk_volume_bind_mount,
	.umount = pv_disk_volume_bind_umount,
};
