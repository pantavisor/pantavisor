/*
 * Copyright (c) 2020-2022 Pantacor Ltd.
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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "mount.h"
#include "init.h"
#include "blkid.h"
#include "utils/tsh.h"
#include "pantavisor.h"
#include "utils/fs.h"
#include "loop.h"
#include "blkid.h"
#include "utils/str.h"
#include "paths.h"

#define MODULE_NAME "mount-init"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static int _mount_pv_dir_interfaces()
{
	struct stat st;
	char storage_path[PATH_MAX], pv_path[PATH_MAX];

	// Make pantavisor control area
	pv_paths_pv_file(pv_path, PATH_MAX, "");
	if (stat(pv_path, &st) != 0)
		pv_fs_mkdir_p(pv_path, 0500);

	// Logs
	pv_paths_storage_log(storage_path, PATH_MAX);
	if (stat(storage_path, &st) != 0)
		pv_fs_mkdir_p(storage_path, 0500);

	// Dropbear
	pv_paths_storage_dropbear(storage_path, PATH_MAX);
	if (stat(storage_path, &st) != 0)
		pv_fs_mkdir_p(storage_path, 0500);
	pv_paths_etc_file(pv_path, PATH_MAX, DROPBEAR_DNAME);
	if (stat(pv_path, &st) != 0)
		pv_fs_mkdir_p(pv_path, 0755);
	mount_bind(storage_path, pv_path);

	return 0;
}

void pv_mount_umount(void)
{
	char path[PATH_MAX];

	pv_paths_etc_file(path, PATH_MAX, DROPBEAR_DNAME);
	if (umount(path))
		pv_log(ERROR, "Error unmounting etc_file %s", strerror(errno));

	if (pv_config_get_str(PV_STORAGE_LOGTEMPSIZE)) {
		pv_paths_storage(path, PATH_MAX);
		size_t logmount_size = strlen(path) + strlen("/logs  ");
		char *logmount = malloc(sizeof(char) * logmount_size);
		SNPRINTF_WTRUNC(logmount, logmount_size, "%s%s", path, "/logs");
		if (umount(logmount))
			pv_log(ERROR, "Error unmounting logmount: %s / %s",
			       logmount, strerror(errno));
		free(logmount);
	}
}

static int pv_mount_install(struct pv_init *this)
{
	char path[PATH_MAX];
	struct stat st;
	sprintf(path, "/lib/pv/pantavisor-installer");

	if (stat(path, &st)) {
		pv_log(ERROR, "Installer not available/exectuable: %s (%s)",
		       path, strerror(errno));
	}

	tsh_run(path, 1, NULL);

	return 0;
}

static int pv_mount_init(struct pv_init *this)
{
	struct stat st;
	struct blkid_info dev_info = { 0 };
	char path[PATH_MAX];
	int ret = -1;

	if (pv_config_get_system_init_mode() == IM_APPENGINE) {
		ret = 0;
		goto out;
	}

	if (pv_config_get_system_init_mode() == IM_INSTALLER)
		return pv_mount_install(this);

	// Create storage mountpoint and mount device
	pv_paths_storage(path, PATH_MAX);
	pv_fs_mkdir_p(path, 0755);
	blkid_init(&dev_info);
	/*
	 * Check that storage device has been enumerated and wait if not there yet
	 * (RPi2 for example is too slow to pvan the MMC devices in time)
	 */
	for (int wait = pv_config_get_int(PV_STORAGE_WAIT); wait > 0; wait--) {
		/*
		 * storage.path will contain UUID=XXXX or LABEL=XXXX
		 * */
		const char *storage_path = pv_config_get_str(PV_STORAGE_DEVICE);
		if (get_blkid(&dev_info, storage_path))
			pv_log(ERROR, "cannot get block device from '%s'",
			       storage_path);
		if (dev_info.device && stat(dev_info.device, &st) == 0)
			break;
		pv_log(INFO,
		       "trail storage not yet available. Waiting %d seconds...",
		       wait);
		sleep(1);
		continue;
	}

	if (!dev_info.device) {
		pv_log(FATAL, "could not mount '%s': %s", dev_info.device,
		       strerror(errno));
		exit_error(errno, NULL);
	}

	pv_log(INFO, "trail storage found: '%s'", dev_info.device);

	// attempt auto resize only if we have ext4 and in embedded init mode
	if ((pv_config_get_system_init_mode() == IM_EMBEDDED) &&
	    !strcmp(pv_config_get_str(PV_STORAGE_FSTYPE), "ext4")) {
		size_t run_size = strlen("/lib/pv/pv_e2fsgrow") +
				  strlen(dev_info.device) + 3;
		char *run = malloc(sizeof(char) * run_size);
		SNPRINTF_WTRUNC(run, run_size, "/lib/pv/pv_e2fsgrow %s",
				dev_info.device);
		tsh_run(run, 1, NULL);
		free(run);
	}

	const char *mnttype = pv_config_get_str(PV_STORAGE_MNTTYPE);
	const char *logtempsize = pv_config_get_str(PV_STORAGE_LOGTEMPSIZE);

	if (!mnttype) {
		ret = mount(dev_info.device, path,
			    pv_config_get_str(PV_STORAGE_FSTYPE), 0, NULL);
		if (ret < 0)
			goto out;
	} else {
		int status;
		size_t mntcmd_size = strlen("/btools/pvmnt.%s %s") +
				     strlen(mnttype) + strlen(path) + 1;
		char *mntcmd = calloc(mntcmd_size, sizeof(char));

		if (!mntcmd) {
			pv_log(FATAL, "couldn't allocate mount command");
			goto out;
		}
		SNPRINTF_WTRUNC(mntcmd, mntcmd_size, "/btools/pvmnt.%s %s",
				mnttype, path);
		pv_log(DEBUG, "mounting through helper: %s\n", mntcmd);
		ret = tsh_run(mntcmd, 1, &status);
		free(mntcmd);
	}
	free_blkid_info(&dev_info); /*Keep if device_info is required later.*/

	if (logtempsize) {
		size_t logmount_size = strlen(path) + strlen("/logs  ");
		char *logmount = malloc(sizeof(char) * logmount_size);
		size_t opts_size = strlen(logtempsize) + strlen("size=%s") + 1;
		char *opts = malloc(sizeof(char) * opts_size);
		SNPRINTF_WTRUNC(opts, opts_size, "size=%s", logtempsize);
		SNPRINTF_WTRUNC(logmount, logmount_size, "%s%s", path, "/logs");
		pv_fs_mkdir_p(logmount, 0755);
		pv_log(DEBUG, "mounting tmpfs logmount: %s with opts: %s",
		       logmount, opts);
		ret = mount("none", logmount, "tmpfs", 0, opts);
		free(logmount);
		if (opts)
			free(opts);
	}
out:
	if (ret < 0)
		exit_error(errno, "Could not mount trails storage");
	_mount_pv_dir_interfaces();
	return 0;
}

struct pv_init pv_init_mount = {
	.init_fn = pv_mount_init,
	.flags = 0,
};
