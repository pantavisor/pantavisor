#include "phlogger_service.h"
#include "system.h"
#include "pvsignals.h"

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>


static void sigchld_handler(int signum)
{
	// Reap the child procs.
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

int phlogger_service_start(struct phlogger_service *srv, const char *rev)
{
	sigset_t oldmask;
	sigemptyset(&oldmask);

	if (pvsignals_block_chld(&oldmask))
		return -1;

	srv->pid = fork();
	if (srv->pid == 0) {
		signal(SIGCHLD, sigchld_handler);
		if (pvsignals_setmask(&oldmask))
			_exit(EXIT_FAILURE);

		if (srv->rev)
			free(srv->rev);
		srv->rev = strdup(rev);

		if (srv->init() != 0)
			_exit(EXIT_FAILURE);

		while (!(srv->flags & PHLOGGER_FLAG_SERVICE_STOP))
			srv->loop();

		_exit(EXIT_SUCCESS);
	}

	pvsignals_setmask(&oldmask);

	return 0;
}

void phlogger_stop_lenient(struct phlogger_service *srv)
{
	if (srv->pid > 0)
		pv_system_kill_force(srv->pid);
}

void phlogger_stop_force(struct phlogger_service *srv)
{
	if (srv->pid > 0)
		pv_system_kill_force(srv->pid);
}