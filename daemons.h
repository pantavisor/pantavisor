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

#ifndef PV_DAEMONS_H
#define PV_DAEMONS_H

#include <sys/types.h>
#include <unistd.h>

#include "config.h"

// Daemon mode flags (bitmask for init_mode_t)
#define DM_EMBEDDED (1 << IM_EMBEDDED)
#define DM_STANDALONE (1 << IM_STANDALONE)
#define DM_APPENGINE (1 << IM_APPENGINE)
#define DM_ALL (DM_EMBEDDED | DM_STANDALONE | DM_APPENGINE)

struct pv_init_daemon {
	char *name;
	pid_t pid;
	int respawn;
	char *testpath;
	char *cmd;
	unsigned int modes; // bitmask of allowed init modes
	int _respawning;
};

struct pv_init_daemon *pv_init_get_daemons(void);

int pv_init_spawn_daemons(init_mode_t mode);

int pv_init_is_daemon(pid_t pid);

int pv_init_daemon_exited(pid_t pid);

void pv_init_stop_daemons(void);

#endif // PV_DAEMONS_H
