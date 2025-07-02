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

bool pv_parse_positive_long(const char *str, long *out)
{
	if (!str || !*str)
		return false;

	long result = 0;

	// Skip leading whitespace
	while (*str == ' ' || *str == '\t')
		str++;

	for (; *str != '\0'; ++str) {
		if (*str >= '0' && *str <= '9') {
			result = result * 10 + (*str - '0');

			// Simple overflow protection (adjust threshold as needed)
			if (result > 1000000)
				return false;
		} else if (*str == ' ' || *str == '\t') {
			// Allow trailing whitespace after number
			break;
		} else {
			// Invalid non-digit character
			return false;
		}
	}

	// Skip any remaining trailing whitespace
	while (*str == ' ' || *str == '\t')
		str++;

	// If anything remains, input was invalid
	if (*str != '\0')
		return false;

	if (result <= 0)
		return false;

	*out = result;
	return true;
}

void pv_debug_start_shell()
{
	char c[64] = { 0 };
	int t = 5;
	int con_fd;

	int debug_timeout = pv_config_get_int(PV_DEBUG_SHELL_TIMEOUT);

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
		timer_start(&timer_shell_timeout, debug_timeout, 0,
			    RELATIV_TIMER);

		pv_config_set_debug_shell_active(true);

		pv_log(DEBUG, "DEBUG SHELL timeout started with %d secs",
		       debug_timeout);

		shell_pid =
			tsh_run("/sbin/getty -n -l /bin/sh 0 console", 0, NULL);

		wall("A reboot timeout is set for 60 seconds. "
		     "To defer the reboot, run 'pvcontrol defer-reboot [new timeout]'");

		pv_log(INFO, "DEBUG SHELL started with pid %d", shell_pid);
	}
}

void pv_debug_stop_shell()
{
	if (shell_pid < 0)
		return;

	pv_log(DEBUG, "stopping DEBUG SHELL with pid %d...", shell_pid);

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

	pv_log(DEBUG, "DEBUG SHELL stopped");
}

void pv_debug_wait_shell()
{
	struct timer_state timeout_debug_shell;
	timeout_debug_shell = timer_current_state(&timer_shell_timeout);

	if (shell_pid < 0)
		return;

	if (timeout_debug_shell.fin) {
		pv_debug_stop_shell();
		return;
	}

	pv_log(DEBUG, "waiting for debug shell with pid %d to exit", shell_pid);
	waitpid(shell_pid, NULL, 0);
}

void pv_debug_defer_reboot_shell(const char *payload)
{
	long new_timeout = 0;

	if (!pv_parse_positive_long(payload, &new_timeout))
		return;

	timer_stop(&timer_shell_timeout);
	timer_start(&timer_shell_timeout, new_timeout, 0, RELATIV_TIMER);
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

bool pv_debug_check_shell_running()
{
	struct timer_state timeout_debug_shell;
	timeout_debug_shell = timer_current_state(&timer_shell_timeout);

	if (!pv_config_get_bool(PV_DEBUG_SHELL_ACTIVE))
		return false;

	if (!timeout_debug_shell.fin) {
		pv_log(DEBUG, "DEBUG SHELL is active, timeout : %d secs",
		       timeout_debug_shell.nsec);

		if (timeout_debug_shell.nsec < 10) {
			pv_log(DEBUG, "DEBUG SHELL ");
			wall("System will reboot in 10 seconds... to defer reboot, run 'pvcontrol defer-reboot [new timeout]'");
		}

		return false;
	}
	pv_log(DEBUG, "DEBUG SHELL timeout reached, moving to reboot state");
	return true;
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
