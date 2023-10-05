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
#include "utils/fs.h"

#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>

#define MODULE_NAME "disk-swap"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static char *get_option(const char *key, const char *options)
{
	if (!options)
		return NULL;

	char *ops = strdup(options);

	char *value = NULL;
	char *tmp = NULL;
	char *tok = strtok_r(ops, " ", &tmp);
	while (tok) {
		char *cur_key = tok;
		char *cur_value = strstr(tok, "=");
		*cur_value = '\0';
		++cur_value;

		if (!strcmp(cur_key, key)) {
			value = strdup(cur_value);
			break;
		}

		tok = strtok_r(NULL, " ", &tmp);
	}

	free(ops);
	return value;
}

static int pv_disk_swap_init(struct pv_disk *disk)
{
	if (!disk->provision) {
		pv_log(ERROR, "disk definition error, provision not defined");
		return -1;
	}

	if (!disk->type) {
		pv_log(ERROR, "disk definition error, type not defined");
		return -1;
	}

	if (!disk->path) {
		pv_log(ERROR, "disk definition error, path not defined");
		return -1;
	}

	return 0;
}

static pv_disk_status_t pv_disk_swap_status(struct pv_disk *disk)
{
	return pv_disk_utils_is_mounted(disk, "/proc/swaps", false);
}

static int pv_disk_swap_format(struct pv_disk *disk)
{
	if (!strcmp(disk->provision, "file")) {
		char *size = get_option("size", disk->provision_ops);
		if (!size) {
			pv_log(ERROR,
			       "No size provided, cannot create swap file");
			return -1;
		}
		int err = pv_disk_utils_create_file(disk->path, size);
		free(size);

		if (err != 0)
			return -1;
	}

	return pv_disk_utils_mkswap(disk);
}

static int pv_disk_swap_mount(struct pv_disk *disk)
{
	return pv_disk_utils_swapon(disk);
}

static int pv_disk_swap_umount(struct pv_disk *disk)
{
	return pv_disk_utils_swapoff(disk);
}

struct pv_disk_impl swap_impl = {
	.init = pv_disk_swap_init,
	.status = pv_disk_swap_status,
	.format = pv_disk_swap_format,
	.mount = pv_disk_swap_mount,
	.umount = pv_disk_swap_umount,
};
