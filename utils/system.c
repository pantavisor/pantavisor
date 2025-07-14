/*
 * Copyright (c) 2021-2025 Pantacor Ltd.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>

#include <linux/reboot.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "system.h"
#include "fs.h"

#define PREFIX_MODEL "model name\t:"

int get_endian(void)
{
	unsigned long t = 0x00102040;
	return ((((char *)(&t))[0]) == 0x40);
}

int get_dt_model(char *buf, int buflen)
{
	int fd = -1;
	int ret = -1;

	fd = pv_fs_file_check_and_open("/proc/device-tree/model", O_RDONLY, 0);
	if (fd >= 0) {
		ret = pv_fs_file_read_nointr(fd, buf, buflen);
		close(fd);
	}
	return ret >= 0 ? 0 : ret;
}

int get_cpu_model(char *buf, int buflen)
{
	int fd = -1;
	int ret = -1;
	char *cur = NULL, *value = NULL;
	int bytes_read = 0;

	if (!buf || buflen <= 0)
		goto out;

	fd = pv_fs_file_check_and_open("/proc/cpuinfo", O_RDONLY, 0);
	if (fd >= 0) {
		bytes_read = pv_fs_file_read_nointr(fd, buf, buflen);
		close(fd);
	}
	if (bytes_read > 0)
		buf[bytes_read - 1] = '\0';
	else
		goto out;

	cur = strstr(buf, PREFIX_MODEL);
	if (cur) {
		int len = 0;
		/*
		 * sizeof gets us past the space after
		 * colon as well if present. For example
		 * model name	: XXX Processor rev YY (ZZZ)
		 */
		value = cur + sizeof(PREFIX_MODEL);
		cur = strchr(value, '\n');
		if (cur) {
			char *__value = NULL;
			/*
			 * don't copy the newline
			 */
			len = cur - value;
			__value = calloc(len + 1, sizeof(char));
			if (__value) {
				memcpy(__value, value, len);
				snprintf(buf, buflen, "%s", __value);
				free(__value);
				ret = 0;
			}
		}
	}
out:
	return ret;
}

void pv_system_kill_lenient(pid_t pid)
{
	if (pid <= 0)
		return;

	kill(pid, SIGTERM);
}

void pv_system_kill_force(pid_t pid)
{
	bool exited = false;

	if (pid <= 0)
		return;

	// check process has end
	for (int i = 0; i < 5; i++) {
		if (kill(pid, 0))
			exited = true;
		if (exited)
			break;
		sleep(1);
	}

	// force kill if process could not finish
	if (!exited)
		kill(pid, SIGKILL);
}

/**
 * @brief Wrapper around pv_system_kill_force that blocks SIGCHLD, attempts to kill,
 * collects process status, and then unblocks SIGCHLD.
 *
 * @param pid The process ID to kill.
 * @return The exit status of the killed process, or -1 if waitpid failed (e.g., ECHILD)
 * or 0 if the process was already gone before attempting to kill.
 * Note: The returned status is the raw status from waitpid. Use WIFEXITED, etc.
 */
int pv_system_kill_and_wait(pid_t pid)
{
	sigset_t block_mask, old_mask;
	int status = -1; // Default status if waitpid fails or not applicable

	if (pid <= 0) {
		return 0; // Or some other indication that no action was taken
	}

	// 1. Initialize a signal set to block SIGCHLD
	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGCHLD);

	// 2. Block SIGCHLD and save the old signal mask
	//    IMPORTANT: If your application is multithreaded, use pthread_sigmask() here!
	if (sigprocmask(SIG_BLOCK, &block_mask, &old_mask) == -1) {
		perror("pv_system_kill_and_wait: sigprocmask SIG_BLOCK");
		// We can't proceed reliably if we can't block signals.
		// Depending on your error handling, you might exit, log, or continue unreliably.
		// For this example, we'll return -1 and hope for the best if kill is called.
		pv_system_kill_force(pid); // Still attempt to kill
		return -1;
	}

	// 3. Call the original kill function
	pv_system_kill_force(pid);

	// 4. Try to wait for the process to get its exit status
	//    Use WNOHANG to not block indefinitely if the process is not a direct child
	//    or has already been reaped by another mechanism (unlikely with SIGCHLD blocked).
	//    However, usually, we'd want to block here to ensure we get the status.
	//    Forcing it to block to ensure status collection after termination.
	pid_t result_pid = waitpid(pid, &status, 0);
	if (result_pid == -1) {
		if (errno == ECHILD) {
			fprintf(stderr,
				"pv_system_kill_and_wait: waitpid failed for PID %d (ECHILD - already reaped or not a child).\n",
				pid);
			status = 0; // Indicate it's likely gone.
		} else {
			perror("pv_system_kill_and_wait: waitpid");
		}
	} else if (result_pid == 0) {
		// This case should ideally not happen if we called waitpid(pid, &status, 0)
		// (i.e., not using WNOHANG) and the child was indeed terminated.
		// If it did, it means the child might still be running (e.g., kill failed)
		// or it's not a direct child.
		fprintf(stderr,
			"pv_system_kill_and_wait: waitpid returned 0 for PID %d, process might still be running or not a direct child.\n",
			pid);
		status = 0; // Indicate uncertain state
	}

	// 5. Unblock SIGCHLD (restore the old mask)
	if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1) {
		perror("pv_system_kill_and_wait: sigprocmask SIG_SETMASK");
		// Log this, but it doesn't prevent the previous actions from happening
	}

	return status;
}

void pv_system_set_process_name(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	// prctl truncates everything bigger than 16 anyway
	char name[16] = { 0 };
	if (vsnprintf(name, 16, fmt, args) < 0)
		goto out;

	prctl(PR_SET_NAME, (unsigned long)name, 0, 0, 0);

out:
	va_end(args);
}

char *pv_system_transition_str(pv_system_transition_t t)
{
	switch (t) {
	case PV_SYSTEM_TRANSITION_NONE:
		return "none";
	case PV_SYSTEM_TRANSITION_NONREBOOT:
		return "nonreboot";
	case PV_SYSTEM_TRANSITION_REBOOT:
		return "reboot";
	case PV_SYSTEM_TRANSITION_POWEROFF:
		return "power off";
	default:
		return "invalid shutdown type";
	}
}

int pv_system_linux_reboot_cmd(pv_system_transition_t t)
{
	switch (t) {
	case PV_SYSTEM_TRANSITION_POWEROFF:
		return LINUX_REBOOT_CMD_POWER_OFF;
	case PV_SYSTEM_TRANSITION_REBOOT:
		return LINUX_REBOOT_CMD_RESTART;
	default:
		return LINUX_REBOOT_CMD_RESTART;
	}
}
