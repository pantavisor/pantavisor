/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>

#include "utils.h"

#include "bootloader.h"
#include "init.h"

#define MODULE_NAME			"bootloader"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

struct pv_bootloader {
	char pv_rev[64];
	char pv_try[64];
};

static struct pv_bootloader pv_bootloader;

extern const struct bl_ops uboot_ops;
extern const struct bl_ops grub_ops;

const struct bl_ops *ops = 0;

static int pv_bl_init(struct pantavisor *pv)
{
	int ret;

	switch (pv_config_get_bl_type()) {
	case BL_UBOOT_PLAIN:
	case BL_UBOOT_PVK:
		ops = &uboot_ops;
		break;
	case BL_GRUB:
		ops = &grub_ops;
		break;
	default:
		pv_log(ERROR, "Unknown bootoader type!");
		return -1;
		break;
	}

	ret = ops->init();
	if (ret)
		pv_log(ERROR, "Unable to initialize bl controls");

	return ret;
}

char* pv_bootloader_get_rev()
{
	return pv_bootloader.pv_rev;
}

char* pv_bootloader_get_try()
{
	return pv_bootloader.pv_try;
}

static int pv_bootloader_set_rev(char *rev)
{
	int len = strnlen(rev);

	if (!ops)
		return -1;

	if (len >= 64)
		return -1;

	strncpy(pv_bootloader.pv_rev, rev, len);
	return ops->set_env_key("pv_rev", rev);
}

static int pv_bootloader_set_try(char *rev)
{
	int len = strnlen(rev);

	if (!ops)
		return -1;

	if (len >= 64)
		return -1;

	strncpy(pv_bootloader.pv_try, rev, len);
	return ops->set_env_key("pv_try", rev);
}

static int pv_bootloader_unset_try()
{
	if (!ops)
		return -1;

	memset(pv_bootloader.pv_try, 0, sizeof(pv_bootloader.pv_try));
	return ops->unset_env_key("pv_try");
}

bool pv_bootloader_update_in_progress()
{
	return (pv_bootloader_get_try()[0] != '\0');
}

bool pv_bootloader_trying_update()
{
	return (pv_bootloader_update_in_progress() &&
			!strncmp(pv_bootloader_get_rev(),
					pv_bootloader_get_try(),
					sizeof(pv_bootloader_get_rev())));
}

int pv_bootloader_set_installed(char *rev)
{
	pv_log(INFO, "setting installed bootloader %s to be started after next reboot", rev);
	return pv_bootloader_set_try(rev);
}

void pv_bootloader_set_rolledback()
{
	if (!ops)
		return -1;

	pv_log(INFO, "setting old bootloader %s to be started after next reboot", pv_bootloader_get_rev());
}

int pv_bootloader_set_commited(char *rev)
{
	if (!ops)
		return -1;

	pv_log(INFO, "setting done bootloader %s to be started after next reboot", rev);
	return (pv_bootloader_set_rev(rev) ||
			pv_bootloader_unset_try() ||
			ops->flush_env());
}

int pv_bootloader_set_failed()
{
	pv_log(INFO, "setting failed bootloader %s not to be started after next reboot", pv_bootloader_get_try());
	return pv_bootloader_unset_try();
}

static int pv_bl_early_init(struct pv_init *this)
{
	struct pantavisor *pv = pv_get_instance();
	int fd = -1;
	char *buf = NULL;
	char *token = NULL;
	ssize_t bytes = 0;
	const int CMDLINE_OFFSET = 7;

	if (!pv)
		return -1;

	memset(pv_bootloader.pv_rev, 0, sizeof(pv_bootloader.pv_rev));
	memset(pv_bootloader.pv_try, 0, sizeof(pv_bootloader.pv_try));

	// Get current step bootloader from cmdline
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -1;

	buf = calloc(1, sizeof(char) * (1024 + 1));
	if (!buf)
		return -1;
	bytes = read_nointr(fd, buf, sizeof(char)*1024);
	close(fd);
	if (bytes <= 0)
		return -1;

	token = strtok(buf, " ");
	while (token) {
		if (strncmp("pv_rev=", token, CMDLINE_OFFSET) == 0)
			strncpy(pv_bootloader.pv_rev,
					token + CMDLINE_OFFSET,
					strlen(token + CMDLINE_OFFSET));
		else if (strncmp("pv_try=", token, CMDLINE_OFFSET) == 0)
			strncpy(pv_bootloader.pv_try,
					token + CMDLINE_OFFSET
					strlen(token + CMDLINE_OFFSET));
		token = strtok(NULL, " ");
	}
	free(buf);

	// init bootloader ops
	if (pv_bl_init(pv) < 0)
		return -1;

	return 0;
}

struct pv_init pv_init_bl = {
	.init_fn = pv_bl_early_init,
	.flags = 0,
};
