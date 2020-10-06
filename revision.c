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
#define MODULE_NAME		"revision"
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

static int pv_revision_set_rev(int rev)
{
	if (pv_bl_set_rev(rev))
		return -1;

	pv_revision.pv_rev = rev;
	return 0;
}

static int pv_revision_set_try(int rev)
{
	if (pv_bl_set_try(rev))
		return -1;

	pv_revision.pv_try = rev;
	return 0;
}

static int pv_revision_unset_try()
{
	if (pv_bl_unset_try())
		return -1;

	pv_revision.pv_try = 0;
	return 0;
}

bool pv_revision_update_in_progress()
{
	return (pv_revision_get_try() > 0);
}

bool pv_revision_trying_update()
{
	return (pv_revision_update_in_progress() &&
			(pv_revision_get_try() == pv_revision_get_rev()));
}

int pv_revision_set_installed(int rev)
{
	pv_log(INFO, "setting installed revision %d to be started after next reboot", rev);
	return pv_revision_set_try(rev);
}

int pv_revision_set_roolledback()
{
	pv_log(INFO, "setting old revision %d to be started after next reboot", pv_bl_get_rev());
	return 0;
}

int pv_revision_set_commited(int rev)
{
	pv_log(INFO, "setting done revision %d to be started after next reboot", rev);
	return (pv_revision_set_rev(rev) ||
			pv_revision_unset_try() ||
			pv_bl_clear_update());
}

int pv_revision_set_failed()
{
	pv_log(INFO, "setting failed revision %d not to be started after next reboot", pv_revision_get_try());
	return pv_revision_unset_try();
}

/*
 * Initializes the current revision.
 */
static int pv_revision_init(struct pv_init *this)
{
	int ret = -1;
	char *buf = NULL;
	char *token = NULL;
	int pv_rev = 0, pv_try = 0;
	const int CMDLINE_OFFSET = 7;

	buf = strdup(get_pv_system()->cmdline);

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
	return ret;
}

struct pv_init pv_init_revision = {
	.init_fn = pv_revision_init,
	.flags = 0,
};
