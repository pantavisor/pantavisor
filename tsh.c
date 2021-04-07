/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "tsh.h"
#include "log.h"
#include "init.h"
#include <signal.h>

#define TSH_MAX_LENGTH	32
#define TSH_DELIM	" \t\r\n\a"

static pid_t _tsh_exec(char **argv, int wait, int *status, int stdin_p[], int stdout_p[], int stderr_p[])
{
	int pid = -1;
	sigset_t blocked_sig, old_sigset;
	int ret = 0;

	if (wait) {
		sigemptyset(&blocked_sig);
		sigaddset(&blocked_sig, SIGCHLD);
		/*
		 * Block SIGCHLD while we want to wait on this child.
		 * */
		ret = sigprocmask(SIG_BLOCK, &blocked_sig, &old_sigset);
	}
	pid = fork_child_process("pvtsh");

	if (pid == -1) {
		if ( (ret == 0) && wait)
			sigprocmask(SIG_SETMASK, &old_sigset, NULL);
		return -1;
	} else if (pid > 0) {
		// In parent
		if (wait) {
			if (ret == 0) {
				/*wait only if we blocked SIGCHLD*/
				waitpid(pid, status, 0);
				sigprocmask(SIG_SETMASK, &old_sigset, NULL);
			}
		}
		free(argv);
	} else {
		ret = 0;
		// closed all unused fds right away ..
		if(stdin_p) // close writing end for stdin dup
			close(stdin_p[1]);
		if(stdout_p) // close reading ends for out and err dup
			close(stdout_p[0]);
		if(stderr_p)
			close(stderr_p[0]);

		// dup2 things
		while (stdin_p && ((ret = dup2(stdin_p[0], STDIN_FILENO)) == -1) && (errno == EINTR)) {}
		if (ret == -1)
			goto exit_failure;
		while (stdout_p && ((ret = dup2(stdout_p[1], STDOUT_FILENO)) == -1) && (errno == EINTR)) {}
		if (ret == -1)
			goto exit_failure;
		while (stderr_p && ((ret = dup2(stderr_p[1], STDERR_FILENO)) == -1) && (errno == EINTR)) {}
		if (ret == -1)
			goto exit_failure;

		// close all the duped ones now too
		if(stdin_p) // close reading end for stdin dup
			close(stdin_p[0]);
		if(stdout_p) // close writing ends for out and err dup
			close(stdout_p[1]);
		if(stderr_p)
			close(stderr_p[1]);

		// now we let it flow ...
		setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
		execvp(argv[0], argv);
	exit_failure:
		exit(EXIT_FAILURE);
	}

	return pid;
}

static char **_tsh_split_cmd(char *cmd)
{
	int pos = 0;
	char **ts = malloc(TSH_MAX_LENGTH * sizeof(char*));
	char *t;

	if (!ts)
		exit_error(ENOMEM, "Unable to allocate cmd memory\n");

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

// Run command, either built-in or exec
pid_t tsh_run_io(char *cmd, int wait, int *status, int stdin_p[], int stdout_p[], int stderr_p[])
{
	pid_t pid;
	char **args;
	char *vcmd;

	vcmd = malloc(strlen(cmd) + 1);
	if (!vcmd)
		exit_error(ENOMEM, "Unable to allocate cmd memory\n");

	strcpy(vcmd, cmd);

	args = _tsh_split_cmd(vcmd);
	pid = _tsh_exec(args, wait, status, stdin_p, stdout_p, stderr_p);
	free(vcmd);

	if (pid < 0)
		printf("Cannot run \"%s\"\n", cmd);

	return pid;
}

// Run command, either built-in or exec
pid_t tsh_run(char *cmd, int wait, int *status)
{
	return tsh_run_io(cmd, wait, status, NULL, NULL, NULL);
}
