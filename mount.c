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

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include "init.h"
#include "blkid.h"
#include "tsh.h"
#include "pantavisor.h"
#include "utils.h"
#include "loop.h"
#include "cmd.h"

#define MODULE_NAME		"mount-init"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static int ph_mount_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	struct stat st;
	int ret = -1;

	pv = get_pv_instance();
	if (!pv || !pv->config)
		goto out;
	config = pv->config;

	// Make pantavisor control area - host parts
	if (stat(config->rundir, &st) != 0)
		mkdir_p(config->rundir, 0500);

	if (stat(config->logdir, &st) != 0)
		mkdir_p(config->logdir, 0500);

	if (stat(config->metacachedir, &st) != 0)
		mkdir_p(config->metacachedir, 0500);

	if (stat(config->dropbearcachedir, &st) != 0)
		mkdir_p(config->dropbearcachedir, 0500);

	char dropbeardir[PATH_MAX];
	sprintf(dropbeardir, "%s/dropbear/", config->etcdir);

	if (stat(dropbeardir, &st) != 0)
		mkdir_p(dropbeardir, 0755);

	// Make pantavisor control area - run part
	if (stat(config->pvdir_usermeta, &st) != 0)
		mkdir_p(config->pvdir_usermeta, 0755);

	if (stat(config->pvdir_logsdir, &st) != 0)
		mkdir_p(config->pvdir_logsdir, 0500);


	// setup bind mounts - if not in place
	while (umount2(config->pvdir_usermeta, MNT_FORCE) == 0);
	mount_bind(config->metacachedir, config->pvdir_usermeta);

	while(umount2(config->pvdir_logsdir, MNT_FORCE) == 0);
	mount_bind(pv->config->logdir, pv->config->pvdir_logsdir);

	while(umount2(dropbeardir, MNT_FORCE) == 0);
	mount_bind(config->dropbearcachedir, dropbeardir);

	ret = 0;
 out:
	return ret;
}

static int pv_mount_init(struct pv_init *this)
{
	struct stat st;
	struct blkid_info dev_info;
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	int ret = -1;

	pv = get_pv_instance();
	if (!pv || !pv->config)
		exit_error(errno, "Pantavisor must be configured before pv_mount_init can be done");

	config = pv->config;

	if ((!config->storage.path || !strlen(config->storage.path))) {
		if (!pv->system->is_embedded)
			exit_error(errno, "Mount storage.path config is required unless pantavisor runs in embedded mode");
		ret = 0;
		// skip the mount code ...
		goto out;
	}

	// Create storage mountpoint and mount device
	mkdir_p(config->storage.mntpoint, 0755);
	blkid_init(&dev_info);
	/*
	 * Check that storage device has been enumerated and wait if not there yet
	 * (RPi2 for example is too slow to pvan the MMC devices in time)
	 */
	for (int wait = 5; wait > 0; wait--) {
		/*
		 * storage.path will contain UUID=XXXX or LABEL=XXXX
		 * */
		get_blkid(&dev_info, config->storage.path);
		if (dev_info.device && stat(dev_info.device, &st) == 0)
			break;
		printf("INFO: trail storage not yet available, waiting...\n");
		sleep(1);
		continue;
	}

	if (!dev_info.device)
		exit_error(errno, "Could not mount trails storage. No device found.");

	if (!config->storage.mnttype) {
		ret = mount(dev_info.device, config->storage.mntpoint, config->storage.fstype, 0, NULL);
	} else {
		int status;
		char *mntcmd = calloc(sizeof(char), strlen("/btools/pvmnt.%s %s") +
						strlen (config->storage.mnttype) +
						strlen (config->storage.mntpoint) + 1);

		if (!mntcmd) {
			printf("Couldn't allocate mount command \n");
			goto out;
		}
		sprintf(mntcmd, "/btools/pvmnt.%s %s", config->storage.mnttype, config->storage.mntpoint);
		printf("Mounting through helper: %s\n", mntcmd);
		ret = tsh_run(mntcmd, 1, &status);
		free(mntcmd);
	}
	free_blkid_info(&dev_info); /*Keep if device_info is required later.*/
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
