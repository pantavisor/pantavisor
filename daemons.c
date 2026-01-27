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

#include "init.h"
#include "daemons.h"
#include "tsh.h"

#define MODULE_NAME "daemons"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

struct pv_init_daemon daemons[] = {
	{ "hwrngd", 0, 1, "/usr/bin/rngd", "/usr/bin/rngd -f",
	  DM_EMBEDDED | DM_STANDALONE, 0 },
#ifdef PANTAVISOR_XCONNECT
	{ "pv-xconnect", 0, 1, "/usr/bin/pv-xconnect", "/usr/bin/pv-xconnect",
	  DM_ALL, 0 },
#endif
	{ 0, 0, 0, 0, 0, 0, 0 }
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
#ifndef DISABLE_LOGSERVER
                char out_name[64], err_name[64];
                snprintf(out_name, sizeof(out_name), "%s-out", self->name);
                snprintf(err_name, sizeof(err_name), "%s-err", self->name);
                self->pid = tsh_run_daemon_logserver(self->cmd, out_name,
                                                     err_name);
#else
                self->pid = tsh_run(self->cmd, 0, 0);
#endif
                self->_respawning = 1;
        }
        if (self->pid < 0) {
                pv_log(ERROR, "error forking child: '%s': %s", self->name,
                       strerror(errno));
                return self->pid;
        }

        return self->pid;
}struct pv_init_daemon *pv_init_get_daemons(void)
{
	return daemons;
}

int pv_init_spawn_daemons(init_mode_t mode)
{
	int i = 0;
	struct stat sb;
	unsigned int mode_flag = (1 << mode);

	sigset_t blocked_sig, old_sigset;
	sigemptyset(&blocked_sig);
	sigaddset(&blocked_sig, SIGCHLD);
	sigprocmask(SIG_BLOCK, &blocked_sig, &old_sigset);

	        for (i = 0; daemons[i].name; i++) {
	                if (daemons[i].pid > 0 || !daemons[i].respawn)
	                        continue;
	                // skip daemons not enabled for this init mode
	                if (!(daemons[i].modes & mode_flag)) {
	                        pv_log(DEBUG, "daemon %s not enabled for init mode %d",
	                               daemons[i].name, mode);
	                        continue;
	                }
	
	                pv_log(INFO, "enabling daemon: %s", daemons[i].name);
	
	                if (stat(daemons[i].testpath, &sb)) {
	                        pv_log(INFO,
	                               "daemon not found %s: disabling respawn",
	                               daemons[i].name);
	                        daemons[i].pid = 0;
	                        daemons[i].respawn = 0;
	                        continue;
	                }
	
	                daemons[i].pid = daemon_spawn(&daemons[i]);
	
	                pv_log(INFO, "spawned daemon %s: %d", daemons[i].name,
	                       daemons[i].pid);
	        }	sigprocmask(SIG_SETMASK, &old_sigset, NULL);
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

void pv_init_stop_daemons(void)
{
	int i = 0;
	while (daemons[i].name) {
		if (daemons[i].pid > 0) {
			pv_log(INFO, "Stopping daemon %s (pid %d)",
			       daemons[i].name, daemons[i].pid);
			daemons[i].respawn = 0;
			kill(daemons[i].pid, SIGTERM);
		}
		i++;
	}
}

static int pv_daemons_init(struct pv_init *this)
{
        init_mode_t mode = pv_config_get_system_init_mode();

        pv_init_spawn_daemons(mode);

        return 0;
}

struct pv_init pv_init_daemons = {
        .init_fn = pv_daemons_init,
        .flags = 0,
};
