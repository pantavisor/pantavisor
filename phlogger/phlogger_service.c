#include "phlogger_service.h"
#include "system.h"
#include "pvsignals.h"
#include "wdt.h"

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
	if (srv->pid > 0)
		return -1;

	sigset_t oldmask;
	sigemptyset(&oldmask);

	if (pvsignals_block_chld(&oldmask))
		return -1;

	srv->pid = fork();
	if (srv->pid == 0) {
		signal(SIGCHLD, sigchld_handler);
		if (pvsignals_setmask(&oldmask))
			_exit(EXIT_FAILURE);

		pv_wdt_stop();

		if (srv->rev)
			free(srv->rev);
		srv->rev = strdup(rev);

		if (srv->init() != 0)
			_exit(EXIT_FAILURE);

		if (srv->type == PHLOGGER_SERVICE_DAEMON) {
			while (!(srv->flags & PHLOGGER_SERVICE_FLAG_STOP))
				srv->proc();
		} else if (srv->type == PHLOGGER_SERVICE_ONE_SHOT) {
			srv->proc();
		}

		_exit(EXIT_SUCCESS);
	}

	pvsignals_setmask(&oldmask);

	return 0;
}

void phlogger_service_stop_lenient(struct phlogger_service *srv)
{
	if (srv->pid > 0)
		pv_system_kill_lenient(srv->pid);
}

void phlogger_service_stop_force(struct phlogger_service *srv)
{
	if (srv->pid > 0)
		pv_system_kill_force(srv->pid);
}