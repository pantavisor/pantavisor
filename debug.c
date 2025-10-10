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
static struct timer shell_timer;
static bool shell_session = false;
static bool shell_timeout_active = false;
static bool shell_notify_last_message = false;

static uint64_t pv_debug_timeout_elapsed_sec()
{
	struct timer_state state = timer_current_state(&shell_timer);
	if (!state.fin) {
		pv_log(DEBUG, "shell timeout to reboot: %ju",
		       (intmax_t)state.sec);
		return state.sec;
	}
	return 0;
}

static int is_shell_alive(void)
{
	if (kill(shell_pid, 0) == 0)
		return 1;

	return 0;
}

static void pv_debug_stop_shell()
{
	sigset_t old_sigset;
	int status = 0;

	shell_session = false;
	pv_log(INFO, "stopping debug shell");

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
}

static int pv_debug_check_shell()
{
	struct timer_state timeout_debug_shell;
	timeout_debug_shell = timer_current_state(&shell_timer);

	if (!shell_timeout_active)
		return 1;

	if (pv_debug_timeout_elapsed_sec() < 10 && !shell_notify_last_message) {
		pv_wall("System will reboot in 10 seconds, to defer reboot:\n"
			"run 'pventer -c <container-name> pvcontrol defer-reboot [new timeout]'");
		pv_wall_ssh_users(
			"System will reboot in 10 seconds, to defer reboot:\n"
			"run 'pventer -c <container-name> pvcontrol defer-reboot [new timeout]'");
		shell_notify_last_message = true;
		return 0;
	}

	if (!timeout_debug_shell.fin)
		return 0;

	pv_log(INFO, "Shell timeout reached!");

	pv_wall("Shell timeout reached, rebooting system...");
	pv_log(INFO, "Shell timeout reached, rebooting system...");

	pv_debug_stop_shell();

	return 1;
}

static void pv_debug_shell_new_session(int print_wall)
{
	shell_pid = tsh_run("/sbin/getty -n -l /bin/sh 0 console", 0, NULL);
	shell_session = true;
	pv_log(INFO, "shell started with pid %d", shell_pid);
	if (print_wall)
		pv_wall_welcome();
}

static void pv_debug_shell_get()
{
	char c[64] = { 0 };
	int con_fd;

	con_fd = open("/dev/console", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (con_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
		return;
	}

	read(con_fd, &c, sizeof(c));
	close(con_fd);

	if (c[0] == '\n') {
		pv_debug_shell_new_session(1);
		return;
	}
}

void pv_debug_run_early_shell()
{
	char c[64] = { 0 };
	int t = 5;
	int con_fd;

	if (!pv_config_get_bool(PV_DEBUG_SHELL))
		return;

	if (shell_pid > -1)
		return;

	con_fd = open("/dev/console", O_RDWR);
	if (con_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
		return;
	}

	if (pv_config_get_bool(PV_DEBUG_SHELL_AUTOLOGIN)) {
		pv_debug_shell_new_session(0);
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

	if (c[0] == '\n') {
		pv_debug_shell_new_session(0);
	}
}

int pv_debug_run_shell()
{
	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		return 1;

	if (!pv_config_get_bool(PV_DEBUG_SHELL))
		return 1;

	if (!is_shell_alive()) {
		shell_session = false;
		pv_log(INFO, "shell with pid %d closed", shell_pid);
		shell_pid = -1;
		pv_wall("Shell session closed");

		if (shell_timeout_active)
			return 1;
	}

	if (shell_session)
		goto out;

	pv_debug_shell_get();

out:
	return pv_debug_check_shell();
}

int pv_debug_check_timeout_shell()
{
	int debug_timeout = 0;

	if (!shell_session)
		return 0;

	if (!shell_timeout_active) {
		debug_timeout = pv_config_get_int(PV_DEBUG_SHELL_TIMEOUT);
		timer_start(&shell_timer, debug_timeout, 0, RELATIV_TIMER);
		shell_timeout_active = true;

		pv_log(INFO, "shell timeout started with %d secs",
		       debug_timeout);

		pv_wall("System will reboot in %d seconds, to defer reboot:\n"
			"run 'pventer -c <container-name> pvcontrol defer-reboot [new timeout]'\n"
			"If you exit the shell, the system will reboot immediately.",
			debug_timeout);

		pv_wall_ssh_users(
			"System will reboot in %d seconds, to defer reboot:\n"
			"run 'pventer -c <container-name> pvcontrol defer-reboot [new timeout]'\n"
			"If you exit the shell, the system will reboot immediately.",
			debug_timeout);

		return 1;
	}

	return 0;
}

void pv_debug_defer_reboot_shell(const char *payload)
{
	char *endptr = NULL;
	long new_timeout = 0;

	if (!shell_timeout_active) {
		pv_log(WARN,
		       "shell timeout is not active, cannot defer reboot");
		return;
	}

	errno = 0;
	new_timeout = strtol(payload, &endptr, 10);

	if (errno != 0 || endptr == payload || *endptr != '\0' ||
	    new_timeout < 0 || new_timeout > INT_MAX) {
		pv_log(WARN, "Invalid timeout value: '%s'", payload);
		return;
	}

	if (new_timeout > 10)
		shell_notify_last_message = false;

	timer_stop(&shell_timer);
	timer_start(&shell_timer, new_timeout, 0, RELATIV_TIMER);
	pv_wall("shell timeout deferred to %ld seconds", new_timeout);
	pv_wall_ssh_users("shell timeout deferred to %ld seconds", new_timeout);
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
void pv_debug_run_shell()
{
}
void pv_debug_stop_shell()
{
}
void pv_debug_defer_reboot_shell(const char *payload)
{
}
bool pv_debug_check_timeout_shell()
{
}
int pv_debug_check_shell()
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
