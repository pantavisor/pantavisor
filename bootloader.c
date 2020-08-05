/*
 * Copyright (c) 2017-2018 Pantacor Ltd.
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

#define MODULE_NAME			"bootloader"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"

#include "bootloader.h"
#include "init.h"

const struct bl_ops *ops = 0;

int pv_bl_init(struct pantavisor *pv)
{
	int ret;

	switch (pv->config->bl.type) {
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

	ret = ops->init(pv->config);
	if (ret)
		pv_log(ERROR, "Unable to initialize bl controls");

	return ret;
}

int pv_bl_set_try(struct pantavisor *pv, int rev)
{
	if (!ops)
		return -1;

	return ops->set_env_key("pv_try", rev);
}

int pv_bl_get_try(struct pantavisor *pv)
{
	if (!ops)
		return -1;

	return ops->get_env_key("pv_try");
}

int pv_bl_set_current(struct pantavisor *pv, int rev)
{
	return __pv_bl_set_current(pv, rev, true);
}

int __pv_bl_set_current(struct pantavisor *pv, int rev, bool unset_pvtry)
{
	if (!ops)
		return -1;

	if (unset_pvtry)
		ops->unset_env_key("pv_try");

	return ops->set_env_key("pv_rev", rev);
}

int pv_bl_get_current(struct pantavisor *pv)
{
	if (!ops)
		return -1;

	return ops->get_env_key("pv_rev");
}

int pv_bl_clear_update(struct pantavisor *pv)
{
	if (!ops)
		return -1;

	return ops->flush_env();
}

int pv_bl_install_kernel(struct pantavisor *pv, char *obj)
{
	if (!ops)
		return -1;

	return ops->install_kernel(obj);
}

static int pv_bl_early_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;

	pv = get_pv_instance();
	if (!pv)
		return -1;
	// init bootloader ops
	if (pv_bl_init(pv) < 0)
		return -1;
	return 0;
}

struct pv_init pv_init_bl = {
	.init_fn = pv_bl_early_init,
	.flags = 0,
};
