/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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

#include "bootloader.h"
#include "config.h"
#include "init.h"
#include "pantavisor.h"
#include "utils/str.h"

#define MODULE_NAME "bootloader"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pv_bootloader {
	char *pv_rev;
	char *pv_try;
	char *pv_done;
};

static struct pv_bootloader pv_bootloader;

extern const struct bl_ops uboot_ops;
extern const struct bl_ops grub_ops;
extern const struct bl_ops rpiab_ops;
extern const struct bl_ops ubootab_ops;

const struct bl_ops *ops = 0;

void pv_bootloader_print()
{
	pv_log(DEBUG, "rev=%s;try=%s;done=%s", pv_bootloader.pv_rev,
	       pv_bootloader.pv_try, pv_bootloader.pv_done);
}

const char *pv_bootloader_get_rev()
{
	return pv_bootloader.pv_rev;
}

const char *pv_bootloader_get_try()
{
	return pv_bootloader.pv_try;
}

const char *pv_bootloader_get_done()
{
	return pv_bootloader.pv_done;
}

static int pv_bootloader_set_rev(char *rev)
{
	int len = strlen(rev) + 1;

	if (!ops)
		return -1;

	pv_bootloader.pv_rev =
		realloc(pv_bootloader.pv_rev, len * sizeof(char));
	SNPRINTF_WTRUNC(pv_bootloader.pv_rev, len, "%s", rev);
	pv_bootloader.pv_done =
		realloc(pv_bootloader.pv_done, len * sizeof(char));
	SNPRINTF_WTRUNC(pv_bootloader.pv_done, len, "%s", rev);
	return ops->set_env_key("pv_rev", rev);
}

static int pv_bootloader_set_try(char *rev)
{
	int len = strlen(rev) + 1;

	if (!ops)
		return -1;

	pv_bootloader.pv_try =
		realloc(pv_bootloader.pv_try, len * sizeof(char));
	SNPRINTF_WTRUNC(pv_bootloader.pv_try, len, "%s", rev);
	return ops->set_env_key("pv_try", rev);
}

static int pv_bootloader_unset_try()
{
	if (!ops)
		return -1;

	if (pv_bootloader.pv_try)
		free(pv_bootloader.pv_try);
	pv_bootloader.pv_try = NULL;
	return ops->unset_env_key("pv_try");
}

bool pv_bootloader_update_in_progress()
{
	return (pv_bootloader_get_try() && strlen(pv_bootloader_get_try()));
}

bool pv_bootloader_trying_update()
{
	const char *pv_try = pv_bootloader_get_try();
	if (!pv_try)
		return false;

	return (pv_bootloader_update_in_progress() &&
		!strncmp(pv_bootloader_get_rev(), pv_try,
			 strlen(pv_bootloader_get_rev()) + 1));
}

int pv_bootloader_install_update(char *rev)
{
	pv_log(INFO,
	       "setting installed revision %s to be started after next reboot",
	       rev);

	if (ops->install_update) {
		if (ops->install_update(rev)) {
			pv_log(ERROR, "could not install update");
			return -1;
		}
	}

	if (pv_bootloader_set_try(rev)) {
		pv_log(ERROR, "could not set pv_try");
		return -1;
	}

	return 0;
}

int pv_bootloader_pre_commit_update(char *rev)
{
	if (!ops)
		return -1;

	pv_log(INFO, "preparing revision %s to be commited...", rev);

	if (pv_bootloader_set_rev(rev) || pv_bootloader_unset_try() ||
	    ops->flush_env()) {
		pv_log(ERROR, "could not set pv_rev or unset pvtry");
		return -1;
	}

	return 0;
}

int pv_bootloader_post_commit_update(const char *rev)
{
	if (!ops)
		return -1;

	if (ops->commit_update) {
		if (ops->commit_update()) {
			pv_log(ERROR, "could not finish commiting update");
			return -1;
		}
	}

	pv_log(INFO, "revision %s commited", rev);

	return 0;
}

int pv_bootloader_fail_update()
{
	pv_log(INFO,
	       "setting failed revision %s not to be started after next reboot",
	       pv_bootloader_get_try() ? pv_bootloader_get_try() : "<NA>");

	return pv_bootloader_unset_try();
}

void pv_bootloader_remove()
{
	ops->free();

	if (pv_bootloader.pv_rev)
		free(pv_bootloader.pv_rev);
	if (pv_bootloader.pv_try)
		free(pv_bootloader.pv_try);
	if (pv_bootloader.pv_done)
		free(pv_bootloader.pv_done);
}

static int pv_bl_init()
{
	int ret;

	switch (pv_config_get_bootloader_type()) {
	case BL_UBOOT_PLAIN:
	case BL_UBOOT_PVK:
		ops = &uboot_ops;
		break;
	case BL_RPIAB:
		ops = &rpiab_ops;
		break;
	case BL_GRUB:
		ops = &grub_ops;
		break;
	case BL_UBOOT_AB:
		ops = &ubootab_ops;
		break;
	default:
		pv_log(ERROR, "unknown bootoader type!");
		return -1;
		break;
	}

	ret = ops->init();
	if (ret)
		pv_log(ERROR, "unable to initialize bl controls");

	return ret;
}

static int pv_bl_early_init(struct pv_init *this)
{
	struct pantavisor *pv = pv_get_instance();
	int len;
	char *done = NULL, *token = NULL, *buf = NULL;
	const int CMDLINE_OFFSET = 7;

	// initialize to factory revision
	len = strlen("0") + 1;
	pv_bootloader.pv_rev = calloc(len, sizeof(char));
	SNPRINTF_WTRUNC(pv_bootloader.pv_rev, len, "0");
	pv_bootloader.pv_try = NULL;
	pv_bootloader.pv_done = strdup(pv_bootloader.pv_rev);

	// parse command line
	buf = strdup(pv->cmdline);
	token = strtok(buf, " ");
	while (token) {
		if (strncmp("pv_rev=", token, CMDLINE_OFFSET) == 0) {
			len = strlen(token + CMDLINE_OFFSET) + 1;
			pv_bootloader.pv_rev = realloc(pv_bootloader.pv_rev,
						       len * sizeof(char));
			SNPRINTF_WTRUNC(pv_bootloader.pv_rev, len, "%s",
					token + CMDLINE_OFFSET);
		}
		token = strtok(NULL, " ");
	}
	free(buf);

	free(pv_bootloader.pv_done);
	pv_bootloader.pv_done = strdup(pv_bootloader.pv_rev);

	// init boot env file
	if (pv_bl_init() < 0)
		return -1;

	// get latest pv_try from /storage place
	pv_bootloader.pv_try = ops->get_env_key("pv_try");

	// overload pv_done with value from boot env file
	done = ops->get_env_key("pv_rev");
	if (done) {
		free(pv_bootloader.pv_done);
		pv_bootloader.pv_done = done;
	}

	return 0;
}

struct pv_init pv_init_bl = {
	.init_fn = pv_bl_early_init,
	.flags = 0,
};
