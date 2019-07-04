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

#define TSH_MAX_LENGTH	32
#define TSH_DELIM	" \t\r\n\a"

static pid_t _tsh_exec(char **argv, int wait)
{
	int pid = fork();

	if (pid == -1) {
		return -1;
	} else if (pid > 0) {
		// In parent
		if (wait) {
			int status;
			/*
			 * waitpid will block here,
			 * as it seems to be automatically
			 * restarted when using signal and
			 * not sigaction.
			 * Since this pid will be reaped by
			 * SIGCHLD handler, ask the handler
			 * if it got this pid or not.
			 * */
			//waitpid(pid, &status, 0);
			status = pv_wait_on_reaper_for(pid);
		}
		free(argv);
	} else {
		// In Child
		setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
		execvp(argv[0], argv);
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
pid_t tsh_run(char *cmd, int wait)
{
	pid_t pid;
	char **args;
	char *vcmd;

	vcmd = malloc(strlen(cmd) + 1);
	if (!vcmd)
		exit_error(ENOMEM, "Unable to allocate cmd memory\n");

	strcpy(vcmd, cmd);

	args = _tsh_split_cmd(vcmd);
	pid = _tsh_exec(args, wait);
	free(vcmd);

	if (pid < 0)
		printf("Cannot run \"%s\"\n", cmd);

	return pid;
}
