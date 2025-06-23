/*
 * Copyright (c) 2021-2024 Pantacor Ltd.
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

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <linux/limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "debug.h"
#include "config.h"
#include "paths.h"

#include "utils/tsh.h"
#include "utils/timer.h"
#include "utils/wall.h"

#define MODULE_NAME "debug"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#ifdef PANTAVISOR_DEBUG

static pid_t db_pid = -1;
static pid_t shell_pid = -1;
static struct timer timer_shell_timeout;
static bool shell_timeout_active = false;

void pv_debug_start_shell()
{
	char c[64] = { 0 };
	int t = 5;
	int con_fd;

	if (shell_pid > -1)
		return;

	con_fd = open("/dev/console", O_RDWR);
	if (con_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
		return;
	}

	dprintf(con_fd, "Press [ENTER] for debug ash shell... ");
	fcntl(con_fd, F_SETFL, fcntl(con_fd, F_GETFL) | O_NONBLOCK);
	while (t && (read(con_fd, &c, sizeof(c)) < 0)) {
		dprintf(con_fd, "%d ", t);
		fflush(NULL);
		sleep(1);
		t--;
	}
	dprintf(con_fd, "\n");

	if (c[0] == '\n' || pv_config_get_bool(PV_DEBUG_SHELL_AUTOLOGIN)) {
		shell_pid =
			tsh_run("/sbin/getty -n -l /bin/sh 0 console", 0, NULL);

		pv_log(INFO, "DEBUG SHELL started with pid %d", shell_pid);
	}
}

void pv_debug_get_shell()
{
	char c[64] = { 0 };
	int con_fd;
	int t = 1;

	con_fd = open("/dev/console", O_RDWR);
	if (con_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
		return;
	}

	fcntl(con_fd, F_SETFL, fcntl(con_fd, F_GETFL) | O_NONBLOCK);
	while (t && (read(con_fd, &c, sizeof(c)) < 0)) {
		fflush(NULL);
		sleep(1);
		t--;
	}

	if (c[0] == '\n') {
		shell_pid =
			tsh_run("/sbin/getty -n -l /bin/sh 0 console", 0, NULL);

		wall("### DEBUG SHELL ###");
		pv_log(INFO, "DEBUG SHELL started with pid %d", shell_pid);
	}
}

void pv_debug_stop_shell()
{
	if (shell_pid < 0)
		return;

	sigset_t blocked_sig, old_sigset;
	int status = 0;
	sigemptyset(&blocked_sig);
	sigaddset(&blocked_sig, SIGCHLD);
	/*
		 * Block SIGCHLD while we want to wait on this child.
		 * */
	sigprocmask(SIG_BLOCK, &blocked_sig, &old_sigset);
	if (!kill(shell_pid, SIGKILL))
		waitpid(shell_pid, &status, 0);
	sigprocmask(SIG_SETMASK, &old_sigset, NULL);
	shell_pid = -1;

	wall("### DEBUG SHELL stopped ###");
	pv_log(INFO, "DEBUG SHELL stopped");
}

void pv_debug_start_timeout_shell()
{
	int debug_timeout = 0;

	if (!pv_config_get_bool(PV_DEBUG_SHELL_ACTIVE)) {
		return;
	}
	debug_timeout = pv_config_get_int(PV_DEBUG_SHELL_TIMEOUT);
	timer_start(&timer_shell_timeout, debug_timeout, 0, RELATIV_TIMER);

	shell_timeout_active = true;
	pv_log(INFO, "DEBUG SHELL timeout started with %d secs", debug_timeout);
}

bool pv_debug_check_shell()
{
	struct timer_state timeout_debug_shell;
	timeout_debug_shell = timer_current_state(&timer_shell_timeout);

	if (shell_pid < 0) {
		pv_config_set_debug_shell_active(false);
		return false;
	}

	if (!shell_timeout_active)
		return false;

	if (timeout_debug_shell.nsec == 10) {
		wall("System will reboot in 10 seconds... "
		     "to defer reboot, run 'pvcontrol defer-reboot [new timeout]'");
		return false;
	}

	if (timeout_debug_shell.fin) {
		wall("DEBUG SHELL timeout reached, rebooting...");
		pv_debug_stop_shell();
		pv_config_set_debug_shell_active(false);
		pv_log(INFO, "DEBUG SHELL timeout reached, rebooting...");
		return true;
	}
}

void pv_debug_defer_reboot_shell(const char *payload)
{
	int new_timeout = 0;

	new_timeout = atoi(payload);

	timer_stop(&timer_shell_timeout);
	timer_start(&timer_shell_timeout, (long)new_timeout, 0, RELATIV_TIMER);
	pv_log(INFO, "DEBUG SHELL timeout deferred to %d seconds", new_timeout);
}

#define DBCMD "dropbear -F -p 0.0.0.0:8222 -n %s -R -c /usr/bin/fallbear-cmd"

void pv_debug_start_ssh()
{
	char *dbcmd;
	char path[PATH_MAX];

	if (db_pid > -1)
		return;

	pv_log(DEBUG, "starting SSH server...");

	const char *keys = pv_config_get_str(PV_DEBUG_SSH_AUTHORIZED_KEYS);

	if (!keys || !strcmp(keys, "__default__"))
		pv_paths_pv_usrmeta_key(path, PATH_MAX, SSH_KEY_FNAME);
	else
		pv_paths_etc_ssh_file(path, PATH_MAX, keys);

	dbcmd = calloc(sizeof(DBCMD) + strlen(path) + 1, sizeof(char));
	sprintf(dbcmd, DBCMD, path);

	tsh_run("ifconfig lo up", 0, NULL);
	db_pid = tsh_run(dbcmd, 0, NULL);

	pv_log(DEBUG, "SSH server started with pid %d", db_pid);

	free(dbcmd);
}

void pv_debug_stop_ssh()
{
	if (db_pid > -1) {
		pv_log(DEBUG, "stopping SSH server with pid %d...", db_pid);

		sigset_t blocked_sig, old_sigset;
		int status = 0;
		sigemptyset(&blocked_sig);
		sigaddset(&blocked_sig, SIGCHLD);
		/*
		 * Block SIGCHLD while we want to wait on this child.
		 * */
		sigprocmask(SIG_BLOCK, &blocked_sig, &old_sigset);
		if (!kill(db_pid, SIGKILL))
			waitpid(db_pid, &status, 0);
		sigprocmask(SIG_SETMASK, &old_sigset, NULL);
		db_pid = -1;

		pv_log(DEBUG, "SSH server stopped");
	}
}

void pv_debug_check_ssh_running()
{
	if (pv_config_get_bool(PV_DEBUG_SSH))
		pv_debug_start_ssh();
	else
		pv_debug_stop_ssh();
}

bool pv_debug_is_ssh_pid(pid_t pid)
{
	return (pid != -1) && (pid == db_pid);
}

pid_t pv_debug_get_ssh_pid()
{
	return db_pid;
}

#else
void pv_debug_start_shell()
{
}
void pv_debug_wait_shell()
{
}
void pv_debug_start_ssh()
{
}
void pv_debug_stop_ssh()
{
}
void pv_debug_check_ssh_running()
{
}

bool pv_debug_is_ssh_pid(pid_t pid)
{
	return false;
}
#endif
