/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "tsh.h"
#include "timer.h"
#include "utils/pvsignals.h"
#include "log.h"

#ifndef DISABLE_LOGSERVER
#include "logserver/logserver.h"
#endif

#define TSH_MAX_LENGTH 32
#define TSH_DELIM " \t\r\n\a"

#define MODULE_NAME "tsh"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)

static char **_tsh_split_cmd(char *cmd)
{
	int pos = 0;
	char **ts = malloc(TSH_MAX_LENGTH * sizeof(char *));
	char *t;

	if (!ts)
		return NULL;

	t = strtok(cmd, TSH_DELIM);
	while (t != NULL) {
		ts[pos] = t;
		pos++;

		if (pos >= TSH_MAX_LENGTH)
			break;

		t = strtok(NULL, TSH_DELIM);
	}
	ts[pos] = NULL;

	return ts;
}

static pid_t _tsh_exec(char **argv, int wait, int *status, int stdin_p[],
		       int stdout_p[], int stderr_p[])
{
	int pid = -1;
	sigset_t blocked_sig, old_sigset;
	sigset_t oldmask;
	int ret = 0;

	if (wait) {
		sigemptyset(&blocked_sig);
		sigaddset(&blocked_sig, SIGCHLD);
		/*
		 * Block SIGCHLD while we want to wait on this child.
		 * */
		ret = sigprocmask(SIG_BLOCK, &blocked_sig, &old_sigset);
	} else if (pvsignals_block_chld(&oldmask)) {
		return -1;
	}

	pid = fork();

	if (pid == -1) {
		pvsignals_setmask(&oldmask);

		if ((ret == 0) && wait)
			sigprocmask(SIG_SETMASK, &old_sigset, NULL);
		return -1;
	} else if (pid > 0) {
		if (wait) {
			if (ret == 0) {
				/* wait only if we blocked SIGCHLD */
				waitpid(pid, status, 0);
				sigprocmask(SIG_SETMASK, &old_sigset, NULL);
			}
		} else {
			pvsignals_setmask(&oldmask);
		}
		free(argv);
	} else {
		ret = 0;
		// closed all unused fds right away ..
		if (stdin_p) // close writing end for stdin dup
			close(stdin_p[1]);
		if (stdout_p) // close reading ends for out and err dup
			close(stdout_p[0]);
		if (stderr_p)
			close(stderr_p[0]);

		signal(SIGCHLD, SIG_DFL);

		if (wait)
			sigprocmask(SIG_SETMASK, &old_sigset, NULL);
		else if (pvsignals_setmask(&oldmask)) {
			goto exit_failure;
		}

		// dup2 things
		while (stdin_p &&
		       ((ret = dup2(stdin_p[0], STDIN_FILENO)) == -1) &&
		       (errno == EINTR)) {
		}
		if (ret == -1)
			goto exit_failure;
		while (stdout_p &&
		       ((ret = dup2(stdout_p[1], STDOUT_FILENO)) == -1) &&
		       (errno == EINTR)) {
		}
		if (ret == -1)
			goto exit_failure;
		while (stderr_p &&
		       ((ret = dup2(stderr_p[1], STDERR_FILENO)) == -1) &&
		       (errno == EINTR)) {
		}
		if (ret == -1)
			goto exit_failure;

		// close all the duped ones now too
		if (stdin_p) // close reading end for stdin dup
			close(stdin_p[0]);
		if (stdout_p) // close writing ends for out and err dup
			close(stdout_p[1]);
		if (stderr_p)
			close(stderr_p[1]);

		// now we let it flow ...
		setenv("PATH",
		       "/bin:/sbin:/usr/bin:/usr/sbin:/lib/pv:/lib/pv/volmount/crypt",
		       0);
		execvp(argv[0], argv);
	exit_failure:
		exit(EXIT_FAILURE);
	}

	return pid;
}

// Run command, either built-in or exec
pid_t tsh_run(char *cmd, int wait, int *status)
{
	return tsh_run_io(cmd, wait, status, NULL, NULL, NULL);
}

// Run command, either built-in or exec
pid_t tsh_run_io(char *cmd, int wait, int *status, int stdin_p[],
		 int stdout_p[], int stderr_p[])
{
	pid_t pid;
	char **args;
	char *vcmd;

	vcmd = strdup(cmd);
	if (!vcmd)
		return -1;

	args = _tsh_split_cmd(vcmd);
	if (!args) {
		free(vcmd);
		return -1;
	}

	pid = _tsh_exec(args, wait, status, stdin_p, stdout_p, stderr_p);
	free(vcmd);

	if (pid < 0)
		printf("Cannot run \"%s\"\n", cmd);

	return pid;
}

#ifndef DISABLE_LOGSERVER
static int logserver_subscribe_pipe(int *cmd_pipe, const char *name, int level)
{
	errno = 0;
	if (pipe(cmd_pipe) == -1) {
		pv_log(ERROR, "cannot create pipe for %s, err: %s", name,
		       strerror(errno));
		return -1;
	}

	pv_logserver_subscribe_fd(cmd_pipe[0], "pantavisor", name, level);

	return 0;
}

int tsh_run_logserver(char *cmd, int *wstatus, const char *log_source_out,
		      const char *log_source_err)
{
	int ret = 0;
	int out_pipe[2] = { 0 };
	int err_pipe[2] = { 0 };

	if (logserver_subscribe_pipe(out_pipe, log_source_out, INFO) != 0 ||
	    logserver_subscribe_pipe(err_pipe, log_source_err, WARN) != 0) {
		return -1;
	}

	ret = tsh_run_io(cmd, 1, wstatus, NULL, out_pipe, err_pipe);

	if (ret < 0) {
		pv_log(ERROR, "command: %s error: %s", cmd);
		return ret;
	} else if (WIFEXITED(*wstatus) && WEXITSTATUS(*wstatus)) {
		pv_log(ERROR, "command failed %s status: %d", cmd,
		       WEXITSTATUS(*wstatus));
		ret = -1;
	} else if (WIFEXITED(*wstatus)) {
		pv_log(DEBUG, "command succeeded: %s", cmd);
		ret = 0;
	} else if (WIFSIGNALED(*wstatus)) {
		pv_log(ERROR, "command signalled %s: %d", cmd,
		       WTERMSIG(*wstatus));
		ret = -2;
	} else {
		pv_log(ERROR, "command failed with wstatus: %d", wstatus);
		ret = -3;
	}
	close(out_pipe[1]);
	close(err_pipe[1]);

	return ret;
}

#endif

static int safe_fd_set(int fd, fd_set *fds, int *max_fd)
{
	FD_SET(fd, fds);
	if (fd > *max_fd) {
		*max_fd = fd;
	}
	return 0;
}

int tsh_run_output(const char *cmd, int timeout_s, char *out_buf, int out_size,
		   char *err_buf, int err_size)
{
	int ret = -1, max_fd = -1, res, out_i = 0, err_i = 0;
	pid_t pid = -1;
	char **args = NULL;
	char *vcmd = NULL;
	fd_set master;
	int outfd[2], errfd[2];
	struct timespec ts;
	sighandler_t oldsig;
	sigset_t mask;
	sigset_t orig_mask;

	memset(outfd, -1, sizeof(outfd));
	memset(errfd, -1, sizeof(errfd));

	vcmd = strdup(cmd);
	if (!vcmd)
		goto out;

	args = _tsh_split_cmd(vcmd);
	if (!args)
		goto out;

	// pipes for communication between main process and command process
	if (pipe(outfd) < 0)
		goto out;
	if (pipe(errfd) < 0)
		goto out;

	// set SIGCHLD mask for timeout on waitpid()
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &orig_mask);

	pid = fork();
	if (pid < 0)
		goto out;
	else if (pid == 0) {
		// redirect out and err of command to pipe
		dup2(outfd[1], STDOUT_FILENO);
		dup2(errfd[1], STDERR_FILENO);
		close(outfd[0]);
		close(errfd[0]);
		// uncomment below to try how child that ignores SIGTERM
		// also gets reaped
		// signal(SIGTERM, SIG_IGN);
		if (args && args[0])
			execvp(args[0], args);
		goto out;
	} else {
		close(outfd[1]);
		close(errfd[1]);
		ts.tv_sec = timeout_s;
		ts.tv_nsec = 0;

		oldsig = signal(SIGCHLD, SIG_DFL);
		while (1) {
			int ret;

			FD_ZERO(&master);
			safe_fd_set(outfd[0], &master, &max_fd);
			safe_fd_set(errfd[0], &master, &max_fd);
			if ((ret = pselect(max_fd + 1, &master, NULL, NULL, &ts,
					   &orig_mask)) < 0) {
				break;
			}
			if (!ret) {
				// if we timed out, we send a nice SIGTERM
				// and break ....
				kill(pid, SIGTERM);
				break;
			}

			if (FD_ISSET(outfd[0], &master)) {
				res = read(outfd[0], &out_buf[out_i], out_size);
				if (res > 0) {
					out_size -= res;
					out_i += res;
				} else if (res < 0 && errno != EAGAIN) {
					break;
				}
				if (res == 0) {
					break;
				}
			}

			if (FD_ISSET(errfd[0], &master)) {
				res = read(errfd[0], &err_buf[err_i], err_size);
				if (res > 0) {
					err_size -= res;
					err_i += res;
				} else if (res < 0 && errno != EAGAIN) {
					break;
				} else if (res == 0) {
					break;
				}
			}
		}
		signal(SIGCHLD, oldsig);
	}

out:
	if (pid == 0) {
		close(outfd[1]);
		close(errfd[1]);
		free(args);
		exit(127);
	} else {
	waitpidagain:
		if (waitpid(pid, &ret, WNOHANG)) {
			if (WIFEXITED(ret)) {
				ret = WEXITSTATUS(ret);
			} else if (WIFSIGNALED(ret)) {
				ret = WTERMSIG(ret);
			} else {
				printf("WARNING: waitpid returned unexpected state %d\n",
				       ret);
			}
		} else {
			if ((ret = sigtimedwait(&mask, NULL, &ts)) < 0) {
				if (errno == EINTR) {
					goto waitpidagain;
				} else if (errno == EAGAIN) {
					kill(pid, SIGKILL);
					goto waitpidagain;
				}
			} else if (ret > 0) {
				goto waitpidagain;
			}
			// usually this goto loop will leave through waitpid branch above.
			printf("ERROR on sigtimedwait wait %s",
			       strerror(errno));
			ret = -1;
		}

		sigprocmask(SIG_SETMASK, &orig_mask, NULL);
		close(outfd[0]);
		close(errfd[0]);
	}

	if (vcmd)
		free(vcmd);

	if (args)
		free(args);

	return ret;
}
