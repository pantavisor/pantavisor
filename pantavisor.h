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
#ifndef PV_PANTAVISOR_H
#define PV_PANTAVISOR_H

#include <stdbool.h>

#include "config.h"

#define RUNLEVEL_DATA 0
#define RUNLEVEL_ROOT 1
#define RUNLEVEL_PLATFORM 2
#define RUNLEVEL_APP 3

// pantavisor.h

extern char pv_user_agent[4096];

#define PV_USER_AGENT_FMT "Pantavisor/2 (Linux; %s) PV/%s Date/%s"

struct pv_system {
	/* true if we run inside a main OS; false if we run as PID 1 */
	bool is_embedded;

	/* true if we want to run in foreground */
	bool is_standalone;

	/* cmdline from /proc/cmdline or actual argv in embedded case */
	char *cmdline;

	/* common directories */
	char *prefix; /* PID1: / | EMBED: /opt/pantavisor */
	char *bindir; /* PID1: / | EMBED: /opt/pantavisor/bin */
	char *vardir; /* PID1: /storage | EMBED: $prefix/var/pantavisor */
	char *logdir; /* PID1: /storage/logs | EMBED: $prefix/var/log/pantavisor */
	char *etcdir; /* PID1: /etc | EMBED: $prefix/etc/ */
	char *rundir; /* PID1: / | EMBED: $prefix/run/pantavisor */
	char *pvdir; /* PID1: /pv | EMBED: $rundir/pv */
	char *datadir; /* PID1: /pshare | EMBED: /opt/pantavisor/share */;
	char *pluginsdir /* PID1: /plugins | EMBED: /opt/pantavisor/plugins */;
};

struct pantavisor {
	struct pv_device *dev;
	struct pv_update *update;
	struct pv_state *state;
	struct pv_cmd *cmd;
	struct pantavisor_config config;
	struct trail_remote *remote;
	struct pv_metadata *metadata;
	struct pv_connection *conn;
	struct pv_system *sys;
	bool remote_mode;
	bool online;
	bool unclaimed;
	bool synced;
	bool loading_objects;
	int ctrl_fd;
};

void pv_init(void);
int pv_start(void);
void pv_stop(void);

struct pv_system* pv_system_get_instance(void);
struct pantavisor* pv_get_instance(void);

#endif
