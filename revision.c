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

#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include "init.h"
#include "utils.h"
#define MODULE_NAME		"revision-init"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"
#include "revision.h"
#include "bootloader.h"

struct pv_revision {
	int pv_rev;
	int pv_try;
};

static struct pv_revision pv_revision;

int pv_revision_get_rev()
{
	return pv_revision.pv_rev;
}

int pv_revision_get_try()
{
	return pv_revision.pv_try;
}

int pv_revision_set_rev(struct pantavisor *pv, int rev)
{
	if (pv_bl_set_current(pv, rev))
		return -1;

	pv_revision.pv_rev = rev;
	return 0;
}

int pv_revision_set_try(struct pantavisor *pv, int rev)
{
	if (pv_bl_set_try(pv, rev))
		return -1;

	pv_revision.pv_try = rev;
	return 0;
}

int pv_revision_unset_try(struct pantavisor *pv)
{
	if (pv_bl_unset_try(pv))
		return -1;

	pv_revision.pv_try = 0;
	return 0;
}

/*
 * Initializes the current revision.
 */
static int pv_revision_init(struct pv_init *this)
{
	int fd = -1;
	int ret = -1;
	char *buf = NULL;
	char *token = NULL;
	ssize_t bytes = 0;
	int pv_rev = 0, pv_try = 0;
	const int CMDLINE_OFFSET = 7;

	// Get current step revision from cmdline
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		goto out;

	buf = calloc(1, sizeof(char) * (1024 + 1));
	if (!buf)
		goto out;
	bytes = read_nointr(fd, buf, sizeof(char)*1024);
	close(fd);
	if (bytes <= 0)
		goto out;

	token = strtok(buf, " ");
	while (token) {
		if (strncmp("pv_rev=", token, CMDLINE_OFFSET) == 0)
			pv_rev = atoi(token + CMDLINE_OFFSET);
		else if (strncmp("pv_try=", token, CMDLINE_OFFSET) == 0)
			pv_try = atoi(token + CMDLINE_OFFSET);
		token = strtok(NULL, " ");
	}
	free(buf);
	pv_revision.pv_rev = pv_rev;
	pv_revision.pv_try = pv_try;
	ret = 0;
out:
	return ret;
}

struct pv_init pv_init_revision = {
	.init_fn = pv_revision_init,
	.flags = 0,
};
