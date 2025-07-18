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
#include <limits.h>
#include <errno.h>

#include <linux/limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "debug.h"
#include "config.h"
#include "paths.h"
#include "wall.h"

#include "utils/tsh.h"
#include "utils/timer.h"
#include "utils/pvsignals.h"

#define MODULE_NAME "debug"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#ifdef PANTAVISOR_DEBUG

static pid_t db_pid = -1;
static pid_t shell_pid = -1;
static struct timer timer_shell_timeout;
static bool shell_timeout_active = false;

bool pv_debug_start_shell()
{
	char c[64] = { 0 };
	int con_fd;

	if (shell_pid < 0) {
		pv_config_set_debug_shell_active(false);
		pv_log(INFO, "shell stopped");
	}

	con_fd = open("/dev/console", O_RDONLY | O_NONBLOCK);
	if (con_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
	}

	fcntl(con_fd, F_SETFL, fcntl(con_fd, F_GETFL) | O_NONBLOCK);
	read(con_fd, &c, sizeof(c));
	close(con_fd);

	if (c[0] == '\n') {
		shell_pid =
			tsh_run("/sbin/getty -n -l /bin/sh 0 console", 0, NULL);

		pv_config_set_debug_shell_active(true);
		pv_wall_welcome();
		pv_log(INFO, "shell started with pid %d", shell_pid);
		return true;
	}

	return false;
}

void pv_debug_stop_shell()
{
	if (shell_pid < 0)
		return;

	sigset_t old_sigset;
	int status = 0;
	if (pvsignals_block_chld(&old_sigset) != 0) {
		pv_log(WARN, "Failed to block SIGCHLD");
		return;
	}

	if (!kill(shell_pid, SIGKILL)) {
		waitpid(shell_pid, &status, 0);
	}

	if (pvsignals_setmask(&old_sigset) != 0) {
		pv_log(WARN, "Failed to restore signal mask");
	}

	shell_pid = -1;
	pv_config_set_debug_shell_active(false);
	pv_log(INFO, "shell stopped");

}

void pv_debug_start_timeout_shell()
{
	int debug_timeout = 0;

	debug_timeout = pv_config_get_int(PV_DEBUG_SHELL_TIMEOUT);
	timer_start(&timer_shell_timeout, debug_timeout, 0, RELATIV_TIMER);

	shell_timeout_active = true;
	pv_log(INFO, "shell timeout started with %d secs", debug_timeout);
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
		pv_wall("System will reboot in 10 seconds... "
		     "to defer reboot, run 'pvcontrol defer-reboot [new timeout]'");
		pv_wall_ssh_users(
			"System will reboot in 10 seconds... "
			"to defer reboot, run 'pvcontrol defer-reboot [new timeout]'");
		return false;
	}

	if (timeout_debug_shell.fin) {
		shell_timeout_active = false;
		pv_debug_stop_shell();
		pv_wall("shell timeout reached, rebooting...");
		pv_wall_ssh_users("shell timeout reached, rebooting...");
		pv_log(INFO, "shell timeout reached, rebooting...");
		return true;
	}

	return false;
}

void pv_debug_defer_reboot_shell(const char *payload)
{
	char *endptr = NULL;
	long new_timeout = 0;

	errno = 0;
	new_timeout = strtol(payload, &endptr, 10);

	if (errno != 0 || endptr == payload || *endptr != '\0' ||
	    new_timeout < 0 || new_timeout > INT_MAX) {
		pv_log(WARN, "Invalid timeout value: '%s'", payload);
		return;
	}

	timer_stop(&timer_shell_timeout);
	timer_start(&timer_shell_timeout, new_timeout, 0, RELATIV_TIMER);
	pv_log(INFO, "shell timeout deferred to %d seconds", new_timeout);
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
