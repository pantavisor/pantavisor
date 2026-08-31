/*
 * Copyright (c) 2024-2026 Pantacor Ltd.
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

/*
 * pv_mcu -- MCU container plugin for Pantavisor
 *
 * Thin plugin that forks pvcm-run for each MCU container.
 * pvcm-run runs in its own mount namespace, appears to xconnect
 * as a normal container with init_pid and injectable sockets.
 *
 * Same pattern as pv_lxc.c: plugin does fork/exec, runtime does
 * the actual work.
 *
 * TODO: Full MCU device management
 *
 * Currently this plugin only fork/execs pvcm-run with the container's
 * run.json. The following is needed for production:
 *
 * 1. Parse BSP-level MCU hardware declaration from bsp/mcu.json or
 *    the "mcu" field in device.json. This tells pantavisor what MCU
 *    devices the board has (remoteproc instance, transport type,
 *    ttyRPMSG channel assignment, firmware constraints).
 *
 * 2. Map MCU containers to hardware: match the container's
 *    mcu.device name against the BSP MCU list to resolve the
 *    actual /dev/ttyRPMSG path and remoteproc instance.
 *
 * 3. Parse the xconnect service graph to set up the correct
 *    --route, --dbus-socket, and --fs-share forwards between
 *    the MCU container and Linux containers.
 *
 * 4. Lifecycle: load firmware via remoteproc before starting
 *    pvcm-run, stop remoteproc on container stop.
 */

#include "pv_mcu.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* function pointers provided by pantavisor */
static void *(*__pv_get_instance)(void) = NULL;

#define PV_VLOG __vlog
static void (*__vlog)(char *module, int level, const char *fmt, ...) = NULL;

#define MODULE_NAME "pv_mcu"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

static int loglevel = 4; /* INFO */
static bool capture = false;

/*
 * Path to pvcm-run binary.
 * Installed alongside pv_mcu.so in /lib/pv/ or /usr/lib/pantavisor/
 */
#define PVCM_RUN_BIN "pvcm-run"

void pv_set_pv_instance_fn(void *fn_pv_get_instance)
{
	__pv_get_instance = fn_pv_get_instance;
}

void pv_set_pv_paths_fn(void *fn_vlog, void *fn_pv_paths_pv_file,
			 void *fn_pv_paths_pv_log,
			 void *fn_pv_paths_pv_log_plat,
			 void *fn_pv_paths_pv_log_file,
			 void *fn_pv_paths_pv_usrmeta_key,
			 void *fn_pv_paths_pv_usrmeta_plat_key,
			 void *fn_pv_paths_pv_devmeta_key,
			 void *fn_pv_paths_pv_devmeta_plat_key,
			 void *fn_pv_paths_lib_hook,
			 void *fn_pv_paths_volumes_plat_file,
			 void *fn_pv_paths_configs_file,
			 void *fn_pv_paths_lib_lxc_rootfs_mount,
			 void *fn_pv_paths_lib_lxc_lxcpath)
{
	__vlog = fn_vlog;
}

void pv_set_pv_conf_loglevel_fn(int level)
{
	loglevel = level;
}

void pv_set_pv_conf_capture_fn(bool cap)
{
	capture = cap;
}

/*
 * Start an MCU container by forking pvcm-run.
 *
 * The child creates a new mount namespace and exec's pvcm-run
 * with the run.json config path. The parent writes the child's
 * PID back through the pipe so pantavisor can track it.
 *
 * pvcm-run then:
 *  - opens the UART/RPMsg transport
 *  - probes and optionally flashes the MCU
 *  - monitors heartbeat
 *  - creates service sockets in its namespace
 *  - bridges xconnect sockets to PVCM protocol
 */
int pv_start_container(struct pv_platform *p, const char *rev, char *conf_file,
		       int logfd, int pipefd)
{
	pid_t pid;
	sigset_t oldmask, newmask;

	/* early stderr log before any struct access — survives even if
	 * __log is not wired up or the struct pointer is bad. */
	fprintf(stderr, "pv_mcu: pv_start_container called (p=%p conf=%s)\n",
		(void *)p, conf_file ? conf_file : "(null)");

	if (!p) {
		fprintf(stderr, "pv_mcu: ERROR: p is NULL\n");
		pid_t err = -1;
		write(pipefd, &err, sizeof(pid_t));
		return -1;
	}

	fprintf(stderr, "pv_mcu: platform name='%s'\n", p->name ? p->name : "(null)");

	pv_log(INFO, "starting MCU container '%s' (conf=%s)", p->name,
		 conf_file);

	/* block SIGCHLD during fork to avoid race */
	sigemptyset(&newmask);
	sigaddset(&newmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &newmask, &oldmask);

	pid = fork();

	if (pid < 0) {
		pv_log(ERROR, "fork failed for '%s': %s", p->name,
			 strerror(errno));
		sigprocmask(SIG_SETMASK, &oldmask, NULL);
		pid_t err = -1;
		write(pipefd, &err, sizeof(pid_t));
		return -1;
	}

	if (pid == 0) {
		/* child: create new mount namespace for this MCU container */
		if (unshare(CLONE_NEWNS) < 0) {
			fprintf(stderr,
				"pvcm: unshare(CLONE_NEWNS) failed: %s\n",
				strerror(errno));
			_exit(1);
		}

		/* make mount namespace private so our mounts don't leak */
		mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL);

		/* redirect stdout/stderr to log pipe */
		if (logfd >= 0) {
			dup2(logfd, STDOUT_FILENO);
			dup2(logfd, STDERR_FILENO);
		}

		/* close inherited fds */
		close(pipefd);

		/* restore signals */
		sigprocmask(SIG_SETMASK, &oldmask, NULL);

		/*
		 * exec pvcm-run with:
		 *   --name <container-name>
		 *   --config <path-to-run.json>
		 */
		execlp(PVCM_RUN_BIN, PVCM_RUN_BIN, "--name", p->name,
		       "--config", conf_file, (char *)NULL);

		fprintf(stderr, "pvcm: exec %s failed: %s\n", PVCM_RUN_BIN,
			strerror(errno));
		_exit(1);
	}

	/* parent: send child PID back to pantavisor */
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	pv_log(INFO, "pvcm-run started for '%s' with pid %d", p->name,
		 pid);

	while (write(pipefd, &pid, sizeof(pid_t)) < 0 && errno == EINTR)
		;

	return 0;
}

/*
 * Stop an MCU container by signaling pvcm-run.
 * pvcm-run handles MCU shutdown (reset GPIO, remoteproc stop)
 * before exiting.
 */
void pv_stop_container(struct pv_platform *p, char *conf_file)
{
	pv_log(INFO, "stopping MCU container '%s' (pid=%d)", p->name,
		 p->init_pid);

	if (p->init_pid > 0)
		kill(p->init_pid, SIGTERM);
}

/*
 * Get console log fd for MCU container.
 * pvcm-run forwards MCU log output to stdout which is connected
 * to the lxc_pipe log fd.
 */
int pv_console_log_getfd(struct pv_platform *p, struct pv_platform_log *log)
{
	/* MCU logs flow through pvcm-run stdout → lxc_pipe.
	 * No separate console fd needed. */
	log->console_pt = -1;
	return -1;
}
