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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "daemons.h"
#include "tsh.h"

#define MODULE_NAME "daemons"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

struct pv_init_daemon daemons[] = {
	{ "hwrngd", 0, 1, "/usr/sbin/rngd", "/usr/sbin/rngd -f", 0 },
#ifdef PANTAVISOR_XCONNECT
	{ "pv-xconnect", 0, 1, "/usr/bin/pv-xconnect", "/usr/bin/pv-xconnect",
	  0 },
#endif
	{ 0, 0, 0, 0, 0, 0 }
};

static int daemon_spawn(struct pv_init_daemon *self)
{
	self->pid = 0;
	pv_log(INFO, "Spawning %s daemon.", self->name);
	if (self->_respawning) {
		pv_log(INFO, "... deferring respawn by 5 seconds");
		self->pid = tsh_run("/bin/sleep 5", 0, 0);
		self->_respawning = 0;
	} else {
		self->pid = tsh_run(self->cmd, 0, 0);
		self->_respawning = 1;
	}
	if (self->pid < 0) {
		pv_log(ERROR, "error forking child: '%s': %s", self->name,
		       strerror(errno));
		return self->pid;
	}

	return self->pid;
}
struct pv_init_daemon *pv_init_get_daemons(void)
{
	return daemons;
}

int pv_init_spawn_daemons()
{
	int i = 0;
	struct stat sb;

	sigset_t blocked_sig, old_sigset;
	sigemptyset(&blocked_sig);
	sigaddset(&blocked_sig, SIGCHLD);
	sigprocmask(SIG_BLOCK, &blocked_sig, &old_sigset);

	for (i = 0; daemons[i].name; i++) {
		if (daemons[i].pid > 0 ||
		    (daemons[i].pid == 0 && !daemons[i].respawn))
			continue;

		if (stat(daemons[i].testpath, &sb)) {
			pv_log(INFO,
			       "daemon not enabled %s: disabling respawn\n",
			       daemons[i].name);
			daemons[i].pid = 0;
			daemons[i].respawn = 0;
			continue;
		}

		daemons[i].pid = daemon_spawn(&daemons[i]);

		pv_log(INFO, "spawned daemon %s: %d \n", daemons[i].name,
		       daemons[i].pid);
	}
	sigprocmask(SIG_SETMASK, &old_sigset, NULL);
	return 0;
}

int pv_init_is_daemon(pid_t pid)
{
	int i = 0;
	while (daemons[i].name) {
		if (daemons[i].pid == pid)
			return 1;
		i++;
	}
	return 0;
}

int pv_init_daemon_exited(pid_t pid)
{
	int i = 0;
	while (daemons[i].name) {
		if (daemons[i].pid == pid)
			daemons[i].pid = daemons[i].respawn ? 0 : -1;
		i++;
	}
	return 0;
}
