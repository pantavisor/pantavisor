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
#include <sys/mman.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "tsh.h"
#include "utils/pvsignals.h"
#include "utils/fs.h"

#ifndef DISABLE_LOGSERVER
#include "logserver/logserver.h"
#endif

#define TSH_MAX_LENGTH 32
#define TSH_DELIM " \t\r\n\a"
#define TSH_PATH_VAR                                                           \
	"/bin:/sbin:/usr/bin:/usr/sbin:/lib/pv:/lib/pv/volmount/crypt"

#define MODULE_NAME "tsh"
#ifdef DISABLE_LOGSERVER
#define pv_log(level, msg, ...)                                                \
	fprintf(stderr, "[tsh] (%s:%d) " msg "\n", __FUNCTION__, __LINE__,     \
		##__VA_ARGS__)
#else
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"
#endif

/*
 * Split cmd into argv-style tokens on whitespace, with shell-like quoting:
 *   - Single quotes: everything inside is literal (no escaping).
 *   - Double quotes: backslash escapes \ and " inside; other \ are literal.
 *   - Outside quotes: backslash escapes the next character.
 * Quotes are stripped from the resulting tokens.  Modifies cmd in-place.
 */
static char **_tsh_split_cmd(char *cmd)
{
	int pos = 0;
	char **ts = malloc(TSH_MAX_LENGTH * sizeof(char *));

	if (!ts)
		return NULL;

	char *p = cmd;
	while (*p && pos < TSH_MAX_LENGTH - 1) {
		/* skip leading delimiters */
		while (*p && strchr(TSH_DELIM, *p))
			p++;
		if (!*p)
			break;

		char *out = p; /* write position (in-place, always <= p) */
		ts[pos] = out;

		while (*p && !strchr(TSH_DELIM, *p)) {
			if (*p == '\'') {
				p++; /* skip opening quote */
				while (*p && *p != '\'')
					*out++ = *p++;
				if (*p == '\'')
					p++; /* skip closing quote */
			} else if (*p == '"') {
				p++; /* skip opening quote */
				while (*p && *p != '"') {
					if (*p == '\\' &&
					    (p[1] == '"' || p[1] == '\\')) {
						p++;
					}
					*out++ = *p++;
				}
				if (*p == '"')
					p++; /* skip closing quote */
			} else if (*p == '\\' && p[1]) {
				p++; /* skip backslash */
				*out++ = *p++;
			} else {
				*out++ = *p++;
			}
		}
		if (*p)
			p++; /* skip the delimiter */
		*out = '\0';
		pos++;
	}
	ts[pos] = NULL;

	return ts;
}

// NOTE: timeout == 0  => TSH_DEFAULT_TIMEOUT
//	 timeout == -1 => no timeout
static int _tsh_wait(int timeout, sigset_t mask, sigset_t old, int pid)
{
	timeout = timeout == 0 ? TSH_DEFAULT_TIMEOUT : timeout;

	struct timespec tm = {
		.tv_sec = timeout,
		.tv_nsec = 0,
	};

	int sig = 0;
	while (1) {
		errno = 0;
		if (timeout < 0)
			sig = sigwaitinfo(&mask, NULL);
		else
			sig = sigtimedwait(&mask, NULL, &tm);

		if (sig == -1 && errno == EINTR)
			continue;
		break;
	}

	int status = 0;

	if (sig == SIGCHLD) {
		if (!waitpid(pid, &status, WNOHANG))
			waitpid(pid, &status, 0);
	} else if (sig == -1) {
		if (errno == EAGAIN && timeout >= 0) {
			pv_log(DEBUG, "timeout reached");
		} else {
			pv_log(DEBUG, "wait call fail");
		}

		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
	}
	sigprocmask(SIG_SETMASK, &old, NULL);
	return status;
}

static pid_t _tsh_exec(char **argv, int wait, int *status, int timeout,
		       int stdin_p[], int stdout_p[], int stderr_p[])
{
	pid_t pid = -1;
	sigset_t blocked_sig, old_sigset;
	sigset_t oldmask;

	int st = 0;
	if (!status)
		status = &st;

	if (wait) {
		sigemptyset(&blocked_sig);
		sigaddset(&blocked_sig, SIGCHLD);

		// Block SIGCHLD while we want to wait on this child.
		if (sigprocmask(SIG_BLOCK, &blocked_sig, &old_sigset) != 0)
			return -1;
	} else if (pvsignals_block_chld(&oldmask)) {
		return -1;
	}

	pid = fork();

	if (pid == -1) {
		if (!wait)
			pvsignals_setmask(&oldmask);
		else
			sigprocmask(SIG_SETMASK, &old_sigset, NULL);

		return -1;

	} else if (pid > 0) {
		if (!wait)
			pvsignals_setmask(&oldmask);
		else // wait only if we blocked SIGCHLD
			*status = _tsh_wait(timeout, blocked_sig, old_sigset,
					    pid);
	} else {
		int ret = 0;
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
		else if (pvsignals_setmask(&oldmask))
			_exit(EXIT_FAILURE);

		// dup2 things
		while (stdin_p &&
		       ((ret = dup2(stdin_p[0], STDIN_FILENO)) == -1) &&
		       (errno == EINTR)) {
		}
		if (ret == -1)
			_exit(EXIT_FAILURE);
		while (stdout_p &&
		       ((ret = dup2(stdout_p[1], STDOUT_FILENO)) == -1) &&
		       (errno == EINTR)) {
		}
		if (ret == -1)
			_exit(EXIT_FAILURE);
		while (stderr_p &&
		       ((ret = dup2(stderr_p[1], STDERR_FILENO)) == -1) &&
		       (errno == EINTR)) {
		}
		if (ret == -1)
			_exit(EXIT_FAILURE);

		// close all the duped ones now too
		if (stdin_p) // close reading end for stdin dup
			close(stdin_p[0]);
		if (stdout_p) // close writing ends for out and err dup
			close(stdout_p[1]);
		if (stderr_p)
			close(stderr_p[1]);

		// now we let it flow ...
		setenv("PATH", TSH_PATH_VAR, 0);
		execvp(argv[0], argv);
		_exit(EXIT_FAILURE);
	}

	return pid;
}
pid_t tsh_run_io_timeout(const char *cmd, int wait, int *status, int timeout_s,
			 int stdin_p[], int stdout_p[], int stderr_p[])
{
	pid_t pid = -1;
	char **args = NULL;
	char *vcmd = NULL;

	vcmd = strdup(cmd);
	if (!vcmd)
		goto out;

	args = _tsh_split_cmd(vcmd);
	if (!args)
		goto out;

	pid = _tsh_exec(args, wait, status, timeout_s, stdin_p, stdout_p,
			stderr_p);
	if (pid < 0)
		pv_log(DEBUG, "cannot run \"%s\"", cmd);

out:
	if (vcmd)
		free(vcmd);
	if (args)
		free(args);

	return pid;
}

pid_t tsh_run_timeout(const char *cmd, int wait, int *status, int timeout_s)
{
	return tsh_run_io_timeout(cmd, wait, status, timeout_s, NULL, NULL,
				  NULL);
}

// Run command, either built-in or exec
pid_t tsh_run(const char *cmd, int wait, int *status)
{
	return tsh_run_io_timeout(cmd, wait, status, TSH_DEFAULT_TIMEOUT, NULL,
				  NULL, NULL);
}

// Run command, either built-in or exec
pid_t tsh_run_io(const char *cmd, int wait, int *status, int stdin_p[],
		 int stdout_p[], int stderr_p[])
{
	return tsh_run_io_timeout(cmd, wait, status, TSH_DEFAULT_TIMEOUT,
				  stdin_p, stdout_p, stderr_p);
}

static int _tsh_eval_output(const char *cmd, int wstatus)
{
	int ret = 0;

	if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus)) {
		pv_log(ERROR, "command failed %s status: %d", cmd,
		       WEXITSTATUS(wstatus));
		ret = -1;
	} else if (WIFEXITED(wstatus)) {
		pv_log(DEBUG, "command succeeded: %s", cmd);
		ret = 0;
	} else if (WIFSIGNALED(wstatus)) {
		pv_log(ERROR, "command signalled %s: %d", cmd,
		       WTERMSIG(wstatus));
		ret = -2;
	} else {
		pv_log(ERROR, "command failed with wstatus: %d", wstatus);
		ret = -3;
	}
	return ret;
}

static void _tsh_close_pipe(int *p)
{
	if (p[0] >= 0) {
		close(p[0]);
		p[0] = -1;
	}
	if (p[1] >= 0) {
		close(p[1]);
		p[1] = -1;
	}
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

int tsh_run_logserver_timeout(const char *cmd, int *wstatus, int timeout_s,
			      const char *log_source_out,
			      const char *log_source_err)
{
	int ret = -1;
	int out_pipe[] = { -1, -1 };
	int err_pipe[] = { -1, -1 };

	if (logserver_subscribe_pipe(out_pipe, log_source_out, INFO) != 0 ||
	    logserver_subscribe_pipe(err_pipe, log_source_err, WARN) != 0) {
		ret = -1;
		goto out;
	}

	ret = tsh_run_io_timeout(cmd, 1, wstatus, timeout_s, NULL, out_pipe,
				 err_pipe);

	if (ret < 0) {
		pv_log(ERROR, "command: %s error", cmd);
		goto out;
	}

	ret = _tsh_eval_output(cmd, *wstatus);

out:
	_tsh_close_pipe(out_pipe);
	_tsh_close_pipe(err_pipe);

	return ret;
}

int tsh_run_logserver(const char *cmd, int *wstatus, const char *log_source_out,
		      const char *log_source_err)
{
	return tsh_run_logserver_timeout(cmd, wstatus, TSH_DEFAULT_TIMEOUT,
					 log_source_out, log_source_err);
}

pid_t tsh_run_daemon_logserver(const char *cmd, const char *log_source_out,
			       const char *log_source_err)
{
	pid_t pid;
	int out_pipe[] = { -1, -1 };
	int err_pipe[] = { -1, -1 };

	if (logserver_subscribe_pipe(out_pipe, log_source_out, INFO) != 0 ||
	    logserver_subscribe_pipe(err_pipe, log_source_err, WARN) != 0) {
		pid = -1;
		goto out;
	}

	pid = tsh_run_io_timeout(cmd, 0, NULL, TSH_NO_TIMEOUT, NULL, out_pipe,
				 err_pipe);

	if (pid < 0)
		pv_log(ERROR, "daemon start failed: %s", cmd);
out:
	_tsh_close_pipe(out_pipe);
	_tsh_close_pipe(err_pipe);

	return pid;
}

#endif

static int _tsh_mem_pipe(const char *name, int *mem_pipe, int size)
{
	mem_pipe[1] = memfd_create(name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (mem_pipe[1] < 0) {
		pv_log(DEBUG, "couldn't create memfd for %s: %s", name,
		       strerror(errno));
		return -1;
	}

	mem_pipe[0] = fcntl(mem_pipe[1], F_DUPFD_CLOEXEC, 0);
	if (mem_pipe[0] < 0) {
		pv_log(DEBUG, "couldn't create %s dup: %s", name,
		       strerror(errno));
		goto err;
	}

	if (ftruncate(mem_pipe[1], size) < 0) {
		pv_log(DEBUG, "couldn't trucate the mem_pipe %s: %s", name,
		       strerror(errno));
		goto err;
	}

	if (fcntl(mem_pipe[0], F_ADD_SEALS, F_SEAL_GROW) == -1) {
		pv_log(DEBUG, "couldn't limit size in stdout");
		goto err;
	}

	return 0;

err:
	_tsh_close_pipe(mem_pipe);
	return -1;
}

static void _tsh_read(int fd, char *buf, int size)
{
	if (!buf || size <= 0)
		return;

	memset(buf, 0, size);
	lseek(fd, 0, SEEK_SET);
	read(fd, buf, size - 1);
}

int tsh_run_output(const char *cmd, int timeout_s, char *out_buf, int out_size,
		   char *err_buf, int err_size)
{
	int ret = -1;
	int wstatus = 0;

	int out_p[2] = { -1, -1 };
	int err_p[2] = { -1, -1 };

	if (_tsh_mem_pipe("tsh_out", out_p, out_size) != 0)
		goto out;
	if (_tsh_mem_pipe("tsh_err", err_p, err_size) != 0)
		goto out;

	ret = tsh_run_io_timeout(cmd, 1, &wstatus, timeout_s, NULL, out_p,
				 err_p);

	// command couldn't run
	if (ret < 0)
		goto out;

	ret = _tsh_eval_output(cmd, wstatus);

	if (ret == 0)
		_tsh_read(out_p[0], out_buf, out_size);

	else
		_tsh_read(err_p[0], err_buf, err_size);
out:
	_tsh_close_pipe(out_p);
	_tsh_close_pipe(err_p);

	return ret;
}
