#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>

#include "tsh.h"
#include "log.h"

#define TSH_MAX_LENGTH	32
#define TSH_DELIM	" \t\r\n\a"

static pid_t _tsh_exec(char **argv)
{
	int pid = fork();

	if (pid == -1) {
		return -1;
	} else if (pid > 0) {
		// In parent
		/*
		int status;
		waitpid(pid, &status, 0);
		*/
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
pid_t tsh_run(char *cmd)
{
	pid_t pid;
	char **args;
	char *vcmd;

	vcmd = malloc(strlen(cmd));
	if (!vcmd)
		exit_error(ENOMEM, "Unable to allocate cmd memory\n");

	strcpy(vcmd, cmd);

	args = _tsh_split_cmd(vcmd);
	pid = _tsh_exec(args);

	if (pid < 0)
		printf("Cannot run \"%s\"\n", cmd);
		
	return pid;
}
