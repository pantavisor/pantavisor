
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

#include "event/event.h"
#include "event/event_socket.h"
#include "event/event_periodic.h"

#include "utils/tsh.h"
#include "utils/timer.h"
#include "utils/pvsignals.h"

#define MODULE_NAME "debug"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#ifdef PANTAVISOR_DEBUG

static pid_t db_pid = -1;
static pid_t shell_pid = -1;
static struct timer shell_timer;
static bool shell_session = false;
static bool shell_timeout_active = false;
static bool shell_notify_last_message = false;

static struct pv_event_periodic console_checker;
static struct pv_event_socket console_listener = { -1, NULL };

static void pv_debug_is_shell_alive();
static void _debug_console_check(int con_fd, short events, void *arg);
static void _debug_console_listener(int con_fd, short events, void *arg);
static int console_fd = 0;

#define DEBUG_EVENT_INTERVAL 5
#define TIMEOUT_WARNING_INTERVAL 10

static const char *REBOOT_DEFERRAL_MESSAGE =
	"System will reboot in %d seconds, to defer reboot:\n"
	"run 'pventer -c <container-name> pvcontrol cmd defer-reboot [new timeout]'";

static uint64_t pv_debug_timeout_elapsed_sec()
{
	static uint32_t seconds_elapsed = 0;

	struct timer_state timer = timer_current_state(&shell_timer);

	if (timer.fin)
		return 0;

	if (seconds_elapsed > TIMEOUT_WARNING_INTERVAL)
		seconds_elapsed = 0;

	if (seconds_elapsed == 0)
		pv_log(DEBUG, "system will reboot in: %ju seconds",
		       (intmax_t)timer.sec);

	seconds_elapsed++;

	return timer.sec;
}

static void pv_debug_shell_new_session(int print_wall)
{
	shell_pid = tsh_run("/sbin/getty -n -l /bin/sh 0 console", 0, NULL);
	shell_session = true;
	pv_log(INFO, "shell started with pid %d", shell_pid);
	if (print_wall)
		pv_wall_shell_open();

	pv_event_socket_ignore(&console_listener);
	pv_event_periodic_start(&console_checker, DEBUG_EVENT_INTERVAL,
				_debug_console_check);
}

static void _debug_console_listener(int con_fd, short events, void *arg)
{
	char c[64] = { 0 };

	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		goto out;

	if (!pv_config_get_bool(PV_DEBUG_SHELL))
		goto out;

	if (shell_session)
		goto out;

	read(con_fd, &c, sizeof(c));

	if (c[0] == '\n') {
		pv_debug_shell_new_session(1);
	}

out:
	return;
}

static void pv_debug_is_shell_alive()
{
	int console_fd = 0;

	if (kill(shell_pid, 0) == 0)
		return;

	// shell process is not alive anymore, restart console listener
	shell_session = false;
	pv_log(INFO, "shell with pid %d closed", shell_pid);
	shell_pid = -1;
	pv_wall("Shell session closed");

	console_fd = open("/dev/console", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (console_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
	}

	pv_event_periodic_stop(&console_checker);
	pv_event_socket_listen(&console_listener, console_fd,
			       _debug_console_listener, NULL);

	return;
}

static void _debug_console_check(int con_fd, short events, void *arg)
{
	// we need to check if the shell was closed by the user
	pv_debug_is_shell_alive();
}

static void pv_debug_stop_console()
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

static int pv_debug_check_shell_timeout()
{
	int debug_timeout;
	struct timer_state timeout_debug_shell;
	timeout_debug_shell = timer_current_state(&shell_timer);

	// first warning message
	if (!shell_timeout_active) {
		shell_timeout_active = true;

		debug_timeout = pv_config_get_int(PV_DEBUG_SHELL_TIMEOUT);
		timer_start(&shell_timer, debug_timeout, 0, RELATIV_TIMER);

		pv_log(INFO, "shell timeout started with %d secs",
		       debug_timeout);

		pv_wall(REBOOT_DEFERRAL_MESSAGE, debug_timeout);

		return 1;
	}

	// last warning message
	if (pv_debug_timeout_elapsed_sec() < 10 && !shell_notify_last_message) {
		pv_wall(REBOOT_DEFERRAL_MESSAGE, 10);
		shell_notify_last_message = true;
		return 1;
	}

	// timeout not yet reached -> keep waiting
	if (!timeout_debug_shell.fin)
		return 1;

	// timeout reached -> close shell and proceed to normal reboot

	pv_log(DEBUG, "Shell timeout reached, rebooting system...");

	pv_debug_stop_shell();

	return 0;
}

void pv_debug_start()
{
	console_fd = open("/dev/console", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (console_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
	}

	pv_event_socket_listen(&console_listener, console_fd,
			       _debug_console_listener, NULL);
}

bool pv_debug_is_shell_open()
{
	pv_debug_is_shell_alive();

	if (!shell_session)
		return false;

	return pv_debug_check_shell_timeout();
}

void pv_debug_stop_shell()
{
	close(console_fd);
	pv_event_socket_ignore(&console_listener);
	pv_event_periodic_stop(&console_checker);
	pv_debug_stop_console();
}

void pv_debug_run_shell_early()
{
	char c[64] = { 0 };
	int t = 5;

	if (!pv_config_get_bool(PV_DEBUG_SHELL))
		goto out;

	// check appengine mode and if debug shell config is enabled
	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		goto out;

	if (shell_pid > -1)
		goto out;

	console_fd = open("/dev/console", O_RDWR);
	if (console_fd < 0) {
		pv_log(WARN, "Unable to open /dev/console");
		goto out;
	}

	if (pv_config_get_bool(PV_DEBUG_SHELL_AUTOLOGIN)) {
		pv_debug_shell_new_session(0);
		close(console_fd);
		goto out;
	}

	dprintf(console_fd, "Press [ENTER] for debug ash shell... ");
	fcntl(console_fd, F_SETFL, fcntl(console_fd, F_GETFL) | O_NONBLOCK);
	while (t && (read(console_fd, &c, sizeof(c)) < 0)) {
		dprintf(console_fd, "%d ", t);
		fflush(NULL);
		sleep(1);
		t--;
	}
	dprintf(console_fd, "\n");

	if (c[0] == '\n') {
		pv_debug_shell_new_session(0);
		close(console_fd);
	}
out:
	return;
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
bool pv_debug_is_shell_open()
{
}
void pv_debug_run_shell_early()
{
}
void pv_debug_start()
{
}
void pv_debug_defer_reboot_shell(const char *payload)
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
