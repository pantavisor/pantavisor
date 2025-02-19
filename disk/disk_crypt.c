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
#include "disk.h"
#include "paths.h"

#include <linux/limits.h>
#include <unistd.h>
#include <string.h>

#define MODULE_NAME "disk-crypt"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_DISK_CRYPT_CMD_TMPL "%s %s %s %s %s"

static int run_action(struct pv_disk *disk, const char *action)
{
	const char *type = pv_disk_type_to_str(disk->type);

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_mounted_disk_path(path, PATH_MAX, "dmcrypt",
					   disk->name);
	char script[PATH_MAX] = { 0 };
	pv_paths_lib_crypt(script, PATH_MAX, "crypt");

	int ret = pv_disk_utils_run_cmd(PV_DISK_CRYPT_CMD_TMPL,
					"disk-crypt-info", "disk-crypt-err",
					script, action, type, disk->path, path);
	if (ret == 0) {
		if (!strcmp(action, "mount"))
			disk->mounted = true;
		else
			disk->mounted = false;
	}

	return ret;
}

static int pv_disk_crypt_init(struct pv_disk *disk)
{
	if (disk->type == DISK_UNKNOWN) {
		pv_log(ERROR, "disk %s has unknown type", disk->name);
		return -1;
	}
	return 0;
}

static pv_disk_status_t pv_disk_crypt_status(struct pv_disk *disk)
{
	char path[PATH_MAX] = { 0 };
	pv_paths_storage_mounted_disk_path(path, PATH_MAX, "dmcrypt",
					   disk->name);

	if (!access(path, F_OK)) {
		pv_log(DEBUG, "disk %s already mounted", disk->path);
		return DISK_STATUS_MOUNTED;
	}

	return DISK_STATUS_NOT_MOUNTED;
}

static int pv_disk_crypt_format(struct pv_disk *disk)
{
	return 0;
}

static int pv_disk_crypt_mount(struct pv_disk *disk)
{
	return run_action(disk, "mount");
}

static int pv_disk_crypt_umount(struct pv_disk *disk)
{
	return run_action(disk, "umount");
}

struct pv_disk_impl crypt_impl = {
	.init = pv_disk_crypt_init,
	.status = pv_disk_crypt_status,
	.format = pv_disk_crypt_format,
	.mount = pv_disk_crypt_mount,
	.umount = pv_disk_crypt_umount,
};
