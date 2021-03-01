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

	// Make pantavisor control area
	if (stat("/pv", &st) != 0)
		mkdir_p("/pv", 0500);

	if (stat(config->log.logdir, &st) != 0)
		mkdir_p(config->log.logdir, 0500);

	if (stat(config->metacachedir, &st) != 0)
		mkdir_p(config->metacachedir, 0500);

	if (stat(config->dropbearcachedir, &st) != 0)
		mkdir_p(config->dropbearcachedir, 0500);
	mkdir_p("/pv/user-meta/", 0755);
	if (config->metacachedir)
		mount_bind(config->metacachedir, "/pv/user-meta");

	mkdir_p("/etc/dropbear/", 0755);
	if (config->dropbearcachedir)
		mount_bind(config->dropbearcachedir, "/etc/dropbear");
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
		goto out;

	config = pv->config;
	// Create storage mountpoint and mount device
	mkdir_p(config->storage.mntpoint, 0755);
	blkid_init(&dev_info);
	/*
	 * Check that storage device has been enumerated and wait if not there yet
	 * (RPi2 for example is too slow to pvan the MMC devices in time)
	 */
	for (int wait = config->storage.wait; wait > 0; wait--) {
		/*
		 * storage.path will contain UUID=XXXX or LABEL=XXXX
		 * */
		get_blkid(&dev_info, config->storage.path);
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
	if (!strcmp(config->storage.fstype, "ext4")) {
		char *run = malloc(sizeof(char) * (strlen("/lib/pv/pv_e2fsgrow") + strlen(dev_info.device) + 3));
		sprintf(run, "/lib/pv/pv_e2fsgrow %s", dev_info.device);
		tsh_run(run, 1, NULL);
		free(run);
	}

	if (!config->storage.mnttype) {
		ret = mount(dev_info.device, config->storage.mntpoint, config->storage.fstype, 0, NULL);
		if (ret < 0)
			goto out;
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

	/* log.capture == 2 -> we capture to tmpfs */
	if (config->storage.logtempsize && strlen(config->storage.logtempsize)) {
		char *logmount = malloc(sizeof(char) * (strlen(config->storage.mntpoint) + strlen("/logs  ")));
		char *opts = NULL;
		opts = malloc(sizeof(char) * (strlen(config->storage.logtempsize) + strlen("size=%s") + 1));
		sprintf(opts, "size=%s",config->storage.logtempsize);
		sprintf(logmount, "%s%s", config->storage.mntpoint,"/logs");
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

