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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <libgen.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <linux/limits.h>

#include "updater.h"
#include "pantavisor.h"
#include "ctrl.h"
#include "config.h"
#include "state.h"
#include "utils.h"
#include "addons.h"
#include "parser/parser.h"
#include "version.h"
#include "controller.h"
#include "init.h"

#define MODULE_NAME             "core"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static struct pantavisor* global_pv;

struct pantavisor* pv_get_pv()
{
	return global_pv;
}

static void pv_remove(struct pantavisor *pv)
{

	pv_log(DEBUG, "removing pantavisor");

	if (pv->conn)
		free(pv->conn);

	pv_update_free(pv->update);
	pv->update = NULL;
	pv_state_free(pv->state);
	pv->state = NULL;
	pv_ctrl_free_cmd(pv->cmd);
	pv_trail_remote_remove(pv);
	pv_config_free();

	free(pv);
	pv = NULL;
}

void pv_teardown(struct pantavisor *pv)
{
	if (!pv)
		return;

	pv_ctrl_socket_close(pv->ctrl_fd);

	pv_remove(pv);
}

void pv_init()
{
	int ret;
	struct pantavisor *pv;

	printf("Pantavisor (TM) (%s) - www.pantahub.com\n", pv_build_version);
	sprintf(pv_user_agent, PV_USER_AGENT_FMT, pv_build_arch, pv_build_version, pv_build_date);

	prctl(PR_SET_NAME, "pantavisor");
	pv = calloc(1, sizeof(struct pantavisor));
	if (pv)
		global_pv = pv;

	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	setrlimit(RLIMIT_CORE, &core_limit);

	char *core = "/storage/corepv";
	int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY | O_SYNC);
	if (fd)
		write(fd, core, strlen(core));

	// Enter state machine
	ret = pv_controller_start(pv);

	// Clean exit -> reboot
	exit(ret);
}

static int pv_pantavisor_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	int ret = -1;

	pv = pv_get_pv();
	if (!pv)
		goto out;
	// Make sure this is initialized
	pv->state = NULL;
	pv->remote = NULL;
	pv->update = NULL;
	pv->online = false;
	pv->unclaimed = false;
	ret = 0;
out:
	return 0;
}

struct pv_init pv_init_pantavisor = {
	.init_fn = pv_pantavisor_init,
	.flags = 0,
};
