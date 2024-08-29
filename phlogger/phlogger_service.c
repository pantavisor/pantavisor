#include "phlogger_service.h"
#include "system.h"
#include "pvsignals.h"
#include "wdt.h"

#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#define MODULE_NAME "phlogger_service"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

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

	if (pvsignals_block_chld(&oldmask)) {
		pv_log(ERROR,
		       "%s: failed to block SIGCHLD for starting logserver: %s",
		       srv->name, strerror(errno));
		return -1;
	}

	srv->pid = fork();
	if (srv->pid == 0) {
		signal(SIGCHLD, sigchld_handler);
		if (pvsignals_setmask(&oldmask)) {
			pv_log(ERROR,
			       "%s: unable to reset sigmask of logserver child: %s",
			       srv->name, strerror(errno));
			_exit(EXIT_FAILURE);
		}

		pv_wdt_stop();

		if (srv->rev)
			free(srv->rev);
		srv->rev = strdup(rev);

		if (srv->init() != 0)
			_exit(EXIT_FAILURE);

		pv_log(DEBUG, "%s: starting service type: %d", srv->name,
		       srv->type);

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