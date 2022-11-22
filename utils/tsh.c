/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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

#include "tsh.h"
#include "fs.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#define TSH_MAX_LEN 32
#define TSH_DELIM " \t\r\n\a"
#define TSH_MAX_EVENTS 2

static char **split_cmd(char *cmd_str)
{
	if (!cmd_str)
		return NULL;

	char *str = strdup(cmd_str);
	char **cmd = calloc(TSH_MAX_LEN, sizeof(char *));
	if (!cmd)
		return NULL;

	char *tkn = strtok(str, TSH_DELIM);
	int pos = 0;
	while (tkn != NULL) {
		cmd[pos] = tkn;
		++pos;

		if (pos == TSH_MAX_LEN)
			break;

		tkn = strtok(NULL, TSH_DELIM);
	}
	cmd[pos] = NULL;
	return cmd;
}

static void close_pipe(int *pipe)
{
	if (pipe) {
		if (pipe[0] > -1)
			close(pipe[0]);
		if (pipe[1] > -1)
			close(pipe[1]);
	}
}

static int dup_io(int *pipe, int dup_idx, int io)
{
	if (!pipe)
		return 0;

	if (pipe[0] < 0 || pipe[1] < 0)
		return -1;

	errno = 0;
	while (dup2(pipe[dup_idx], io) == -1 && errno == EINTR)
		;

	close_pipe(pipe);

	return 0;
}

static void exec_cmd(char **cmd, int *in, int *out, int *err)
{
	if (dup_io(in, 0, STDIN_FILENO) != 0)
		exit(EXIT_FAILURE);

	if (dup_io(out, 1, STDOUT_FILENO) != 0)
		exit(EXIT_FAILURE);

	if (dup_io(err, 1, STDERR_FILENO) != 0)
		exit(EXIT_FAILURE);

	setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
	execvp(cmd[0], cmd);
	exit(EXIT_FAILURE);
}

static pid_t exec_cmd_forked(char **cmd, bool wait, int *status, int *in,
			     int *out, int *err)
{
	sigset_t old_set;
	// block SIGCHLD while finish the child process
	if (wait) {
		sigset_t block;
		sigemptyset(&block);
		sigaddset(&block, SIGCHLD);
		sigprocmask(SIG_BLOCK, &block, &old_set);
	}

	pid_t pid = fork();

	if (pid > 0) {
		if (wait) {
			waitpid(pid, status, 0);
			sigprocmask(SIG_SETMASK, &old_set, NULL);
		}
	} else if (pid == 0) {
		exec_cmd(cmd, in, out, err);
	} else if (pid == -1) {
		if (wait)
			sigprocmask(SIG_SETMASK, &old_set, NULL);
		return -1;
	}

	return pid;
}

static int io_add(int epfd, int fd)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLONESHOT,
				  .data.fd = fd };
	return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

pid_t tsh_run(char *cmd_str, int wait, int *status)
{
	return tsh_run_io(cmd_str, wait, status, NULL, NULL, NULL);
}

pid_t tsh_run_io(char *cmd_str, bool wait, int *status, int *in, int *out,
		 int *err)
{
	char **cmd = split_cmd(cmd_str);
	if (!cmd)
		return -1;

	pid_t p = exec_cmd_forked(cmd, wait, status, in, out, err);

	free(cmd[0]);
	free(cmd);
	return p;
}

int tsh_run_output(const char *cmd_str, int timeout, char *out_buf,
		   int out_size, char *err_buf, int err_size)
{
	int out[] = { -1, -1 };
	int err[] = { -1, -1 };
	int epfd = -1;
	int status = -1;
	int ready = -1;
	char *cmd_copy = NULL;
	pid_t pid = -1;
	struct epoll_event ev[TSH_MAX_EVENTS] = { 0 };

	if (pipe2(out, O_CLOEXEC | O_NONBLOCK) != 0)
		goto out;

	if (pipe2(err, O_CLOEXEC | O_NONBLOCK) != 0)
		goto out;

	cmd_copy = strdup(cmd_str);
	if (!cmd_copy)
		goto out;

	pid = tsh_run_io(cmd_copy, false, NULL, NULL, out, err);

	epfd = epoll_create1(0);
	if (epfd < 0)
		goto out;

	io_add(epfd, out[0]);
	io_add(epfd, err[0]);

	ready = epoll_wait(epfd, &ev[0], TSH_MAX_EVENTS, timeout * 1000);

	if (ready < 1)
		goto out;

	for (int i = 0; i < ready; ++i) {
		if (ev[i].data.fd == out[0])
			pv_fs_file_read_nointr(out[0], out_buf, out_size);

		if (ev[i].data.fd == err[0])
			pv_fs_file_read_nointr(err[0], err_buf, err_size);
	}

	usleep(100000);
	waitpid(pid, &status, WNOHANG);

	if (WIFEXITED(status))
		status = WEXITSTATUS(status);
out:
	close_pipe(out);
	close_pipe(err);
	if (epfd > 0)
		close(epfd);
	if (cmd_copy)
		free(cmd_copy);
	return status;
}
