/*
 * Copyright (c) 2018-2025 Pantacor Ltd.
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
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>
#include <linux/limits.h>

#include "bootloader.h"
#include "config.h"
#include "paths.h"
#include "uboot_env_file.h"
#include "uboot_env_buf.h"
#include "uboot_mtd_env.h"
#include "utils/str.h"
#include "utils/fs.h"

#define MODULE_NAME "uboot"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

static char *pv_env = 0;
static char *uboot_txt = 0;
static char trying_mtd[64];
static int single_env;

#define MTD_ENV "pv-env"
#define MTD_ENV_SIZE 65536
#define TRYING_ENV_MTD "mtd:"

static void uboot_free()
{
	if (uboot_txt)
		free(uboot_txt);
	if (pv_env)
		free(pv_env);
	uboot_txt = NULL;
	pv_env = NULL;
}

static int uboot_init()
{
	char buf[PATH_MAX];
	const char *trying;

	// already init'd?
	if (uboot_txt)
		return 0;

	// setup uboot.txt location
	pv_paths_storage_boot_file(buf, PATH_MAX, UBOOTTXT_FNAME);
	uboot_txt = strdup(buf);

	pv_log(DEBUG, "uboot.txt@%s", uboot_txt);

	// get mtd_path from config or else use default
	single_env = pv_config_get_bool(PV_BOOTLOADER_MTD_ONLY);
	const char *mtd_path = pv_config_get_str(PV_BOOTLOADER_MTD_ENV);
	if (!mtd_path || !*mtd_path)
		mtd_path = MTD_ENV;

	// find pv-env for trying flag store
	if (!pv_uboot_mtd_find(mtd_path, buf, sizeof(buf)))
		pv_env = strdup(buf);

	trying = pv_config_get_str(PV_BOOTLOADER_TRYING_ENV);
	if (trying && !strncmp(trying, TRYING_ENV_MTD, strlen(TRYING_ENV_MTD)))
		SNPRINTF_WTRUNC(trying_mtd, sizeof(trying_mtd), "%s",
				trying + strlen(TRYING_ENV_MTD));

	pv_log(DEBUG, "pv-env@%s", pv_env);

	return 0;
}

// the key=value list lives in the pv-env partition or in uboot.txt
static char *uboot_get_env_key(char *key)
{
	static unsigned char buf[MTD_ENV_SIZE];
	int fd, ret;

	if (single_env)
		return pv_env ? pv_uboot_mtd_env_get(pv_env, UBOOT_MTD_RAW,
						     key) :
				NULL;

	fd = open(uboot_txt, O_RDONLY);
	if (fd < 0)
		return NULL;
	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret <= 0)
		return NULL;

	return uboot_env_get(buf, ret, key);
}

// set the key to value, or remove it when value is NULL
static int uboot_edit_env_key(char *key, char *value)
{
	static unsigned char buf[MTD_ENV_SIZE];
	int fd, ret = -1;

	pv_log(DEBUG, "%s boot env key %s", value ? "setting" : "removing",
	       key);

	if (single_env)
		return pv_env && !pv_uboot_mtd_env_set(pv_env, UBOOT_MTD_RAW,
						       key, value) ?
			       0 :
			       -1;

	memset(buf, 0, sizeof(buf));
	fd = open(uboot_txt, O_RDWR | O_CREAT | O_SYNC, 0600);
	if (fd < 0) {
		pv_log(ERROR, "open failed for %s: %s", uboot_txt,
		       strerror(errno));
		return -1;
	}

	if (read(fd, buf, sizeof(buf)) < 0)
		goto out;
	if (uboot_env_edit(buf, sizeof(buf), key, value)) {
		pv_log(ERROR, "no room for %s in %s", key, uboot_txt);
		goto out;
	}

	lseek(fd, 0, SEEK_SET);
	if (write(fd, buf, sizeof(buf)) == (ssize_t)sizeof(buf) && !fsync(fd))
		ret = 0;
out:
	close(fd);
	pv_fs_path_sync(uboot_txt);

	return ret;
}

static int uboot_set_env_key(char *key, char *value)
{
	return uboot_edit_env_key(key, value);
}

static int uboot_unset_env_key(char *key)
{
	return uboot_edit_env_key(key, NULL);
}

// only pv_trying is cleared, whatever else the partition holds stays
static int uboot_flush_env(void)
{
	if (pv_env)
		pv_uboot_mtd_env_set(pv_env, UBOOT_MTD_RAW, "pv_trying", NULL);

	return 0;
}

// failing to clear pv_trying only makes the device fall back, so none of
// this fails the re-arm
static void uboot_clear_trying(void)
{
	char dev[PATH_MAX];

	if (!*trying_mtd) {
		pv_uboot_env_file_clear_trying();
		return;
	}

	if (pv_uboot_mtd_find(trying_mtd, dev, sizeof(dev))) {
		pv_log(INFO, "no MTD partition %s, not clearing pv_trying",
		       trying_mtd);
		return;
	}

	pv_uboot_mtd_env_set(dev, UBOOT_MTD_STD, "pv_trying", NULL);
}

static int uboot_rearm_try(void)
{
	// the pv-env partition was already cleared by flush_env
	if (single_env || pv_env)
		return 0;

	// only appengine's boot script reads an empty pv_trying as "try again"
	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		uboot_set_env_key("pv_trying", "");

	// failing here only means the device falls back to the committed revision
	uboot_clear_trying();

	return 0;
}

const struct bl_ops uboot_ops = {
	.free = uboot_free,
	.init = uboot_init,
	.set_env_key = uboot_set_env_key,
	.unset_env_key = uboot_unset_env_key,
	.get_env_key = uboot_get_env_key,
	.flush_env = uboot_flush_env,
	.install_update = NULL,
	.commit_update = NULL,
	.fail_update = NULL,
	.rearm_try = uboot_rearm_try,
};
