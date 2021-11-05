/*
 * Copyright (c) 2020 Pantacor Ltd.
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

#include "init.h"
#include "blkid.h"
#include "tsh.h"
#include "pantavisor.h"
#include "utils/fs.h"
#include "loop.h"
#include "blkid.h"

#define MODULE_NAME		"mount-init"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static int ph_mount_init(struct pv_init *this)
{
	struct stat st;
	int ret = -1;

	// Make pantavisor control area
	if (stat("/pv", &st) != 0)
		mkdir_p("/pv", 0500);

	if (stat(pv_config_get_log_logdir(), &st) != 0)
		mkdir_p(pv_config_get_log_logdir(), 0500);

	if (stat(pv_config_get_cache_metacachedir(), &st) != 0)
		mkdir_p(pv_config_get_cache_metacachedir(), 0500);

	if (stat(pv_config_get_cache_dropbearcachedir(), &st) != 0)
		mkdir_p(pv_config_get_cache_dropbearcachedir(), 0500);
	mkdir_p("/pv/user-meta/", 0755);
	if (pv_config_get_cache_metacachedir())
		mount_bind(pv_config_get_cache_metacachedir(), "/pv/user-meta");

	mkdir_p("/etc/dropbear/", 0755);
	if (pv_config_get_cache_dropbearcachedir())
		mount_bind(pv_config_get_cache_dropbearcachedir(), "/etc/dropbear");
	ret = 0;

	return ret;
}

static int pv_mount_init(struct pv_init *this)
{
	struct stat st;
	struct blkid_info dev_info;
	int ret = -1;

	// Create storage mountpoint and mount device
	mkdir_p(pv_config_get_storage_mntpoint(), 0755);
	blkid_init(&dev_info);
	/*
	 * Check that storage device has been enumerated and wait if not there yet
	 * (RPi2 for example is too slow to pvan the MMC devices in time)
	 */
	for (int wait = pv_config_get_storage_wait(); wait > 0; wait--) {
		/*
		 * storage.path will contain UUID=XXXX or LABEL=XXXX
		 * */
		get_blkid(&dev_info, pv_config_get_storage_path());
		if (dev_info.device && stat(dev_info.device, &st) == 0)
			break;
		printf("INFO: trail storage not yet available, waiting %d seconds...\n", wait);
		sleep(1);
		continue;
	}

	if (!dev_info.device)
		exit_error(errno, "Could not mount trails storage. No device found.");

	printf("INFO: trail storage found: %s.\n", dev_info.device);

	// attempt auto resize only if we have ext4
	if (!strcmp(pv_config_get_storage_fstype(), "ext4")) {
		char *run = malloc(sizeof(char) * (strlen("/lib/pv/pv_e2fsgrow") + strlen(dev_info.device) + 3));
		sprintf(run, "/lib/pv/pv_e2fsgrow %s", dev_info.device);
		tsh_run(run, 1, NULL);
		free(run);
	}

	if (!pv_config_get_storage_mnttype()) {
		ret = mount(dev_info.device, pv_config_get_storage_mntpoint(), pv_config_get_storage_fstype(), 0, NULL);
		if (ret < 0)
			goto out;
	} else {
		int status;
		char *mntcmd = calloc(sizeof(char), strlen("/btools/pvmnt.%s %s") +
						strlen (pv_config_get_storage_mnttype()) +
						strlen (pv_config_get_storage_mntpoint()) + 1);

		if (!mntcmd) {
			printf("Couldn't allocate mount command \n");
			goto out;
		}
		sprintf(mntcmd, "/btools/pvmnt.%s %s", pv_config_get_storage_mnttype(), pv_config_get_storage_mntpoint());
		printf("Mounting through helper: %s\n", mntcmd);
		ret = tsh_run(mntcmd, 1, &status);
		free(mntcmd);
	}
	free_blkid_info(&dev_info); /*Keep if device_info is required later.*/

	if (pv_config_get_storage_logtempsize()) {
		char *logmount = malloc(sizeof(char) * (strlen(pv_config_get_storage_mntpoint()) + strlen("/logs  ")));
		char *opts = NULL;
		opts = malloc(sizeof(char) * (strlen(pv_config_get_storage_logtempsize()) + strlen("size=%s") + 1));
		sprintf(opts, "size=%s", pv_config_get_storage_logtempsize());
		sprintf(logmount, "%s%s", pv_config_get_storage_mntpoint(), "/logs");
		mkdir_p(logmount, 0755);
		printf("Mounting tmpfs logmount: %s with opts: %s\n", logmount, opts);
		ret = mount("none", logmount, "tmpfs", 0, opts);
		free (logmount);
		if (opts) free (opts);
	}
out:
	if (ret < 0)
		exit_error(errno, "Could not mount trails storage");
	return 0;
}

struct pv_init pv_init_mount = {
	.init_fn = pv_mount_init,
	.flags = 0,
};

struct pv_init ph_init_mount = {
	.init_fn = ph_mount_init,
	.flags = 0,
};

