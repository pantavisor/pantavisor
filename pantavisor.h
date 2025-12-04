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
#ifndef PV_PANTAVISOR_H
#define PV_PANTAVISOR_H

#include <stdbool.h>

#include "config.h"
#include "cgroup.h"

#include "update/update.h"

#include "utils/system.h"

#define RUNLEVEL_DATA 0
#define RUNLEVEL_ROOT 1
#define RUNLEVEL_PLATFORM 2
#define RUNLEVEL_APP 3

// pantavisor.h

extern char pv_user_agent[4096];

#define PV_USER_AGENT_FMT "Pantavisor/2 (Linux; %s) PV/%s Date/%s"

struct pantavisor {
	struct pv_update *update;
	struct pv_state *state;
	struct pv_ctrl_cmd *cmd;
	struct trail_remote *remote;
	struct pv_metadata *metadata;
	char *cmdline;
	bool remote_mode;
	bool loading_objects;
	pv_system_transition_t issued_transition;
	cgroup_version_t cgroupv;
	int ctrl_fd;
};

void pv_init(void);
int pv_start(void);
void pv_stop(void);

pv_system_transition_t pv_run_update(void);

void pv_issue_nonreboot(void);
void pv_issue_reboot(void);
void pv_issue_poweroff(void);

struct pantavisor *pv_get_instance(void);

#endif
