/*
 * Copyright (c) 2017-2020 Pantacor Ltd.
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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/sysmacros.h>
#include <stdbool.h>

#include <linux/reboot.h>

#define MODULE_NAME			"updater"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "tsh.h"
#include "pantavisor.h"
#include "version.h"
#include "init.h"
#include "utils.h"
#include "utils/list.h"
#include "pvlogger.h"
#include "platforms.h"
#include "state.h"

#define MAX_PROC_STATUS (10)
pid_t pv_pid;
pid_t shell_pid;

static int early_mounts()
{
	int ret;
	struct stat st;

	ret = mount("none", "/proc", "proc", MS_NODEV | MS_NOSUID | MS_NOEXEC, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /proc");

	ret = mount("none", "/dev", "devtmpfs", 0, "size=10240k,mode=0755");
	if (ret < 0)
		exit_error(errno, "Could not mount /dev");

	ret = mount("none", "/sys", "sysfs", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /sys");

	mkdir("/dev/pts", 0755);
	ret = mount("none", "/dev/pts", "devpts", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /dev/pts");

	remove("/dev/ptmx");
	mknod("/dev/ptmx", S_IFCHR | 0666, makedev(5, 2));

	ret = mount("none", "/sys/fs/cgroup", "cgroup", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /sys/fs/cgroup");

	mkdir("/sys/fs/cgroup/systemd", 0555);
	ret = mount("cgroup", "/sys/fs/cgroup/systemd", "cgroup", 0, "none,name=systemd");
	if (ret < 0)
		exit_error(errno, "Could not mount /sys/fs/cgroup/systemd");

	mkdir("/sys/fs/cgroup/devices", 0555);
	ret = mount("cgroup", "/sys/fs/cgroup/devices", "cgroup", 0, "none,name=devices");
	if (ret < 0)
		exit_error(errno, "Could not mount /sys/fs/cgroup/systemd");

	mkdir("/writable", 0755);
	if (!stat("/etc/fstab", &st))
		tsh_run("mount -a", 1, NULL);

	mkdir("/root", 0700);
	ret = mount("none", "/root", "tmpfs", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /root");

	mkdir("/run", 0755);
	ret = mount("none", "/run", "tmpfs", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /run");

	return 0;
}

#ifdef PANTAVISOR_DEBUG

#define DROPBEARCMD_FMT "dropbear -p 0.0.0.0:8222 -n %s/pvr-sdk.authorized_keys -R -c /usr/bin/fallbear-cmd"
static void debug_telnet()
{
	char *dropbearcmd;
	const char *pvdir_usermeta;

	if (!get_pv_config())
		pvdir_usermeta = "/pv/user-meta";
	else
		pvdir_usermeta = get_pv_config()->pvdir_usermeta;

	dropbearcmd = malloc (sizeof(char) * strlen(DROPBEARCMD_FMT) + strlen(pvdir_usermeta) + 2);
	sprintf(dropbearcmd, DROPBEARCMD_FMT, pvdir_usermeta);

	tsh_run("ifconfig lo up", 0, NULL);
	tsh_run("telnetd -b 127.0.0.1 -l /bin/sh", 0, NULL);
	tsh_run(dropbearcmd, 0, NULL);
}
#else
static void debug_telnet()
{
	printf("Pantavisor debug telnet disabled in production builds.\n");
}
#endif

static void signal_handler(int signal)
{
	pid_t pid = 0;
	int wstatus;
	struct pantavisor *pv = get_pv_instance();

	if (signal != SIGCHLD)
		return;

	while (	(pid = waitpid(-1, &wstatus, WNOHANG | WUNTRACED)) > 0) {
		struct pv_platform *p, *tmp_p;
		struct pv_log_info *l, *tmp_l;
		struct dl_list *head_platforms, *head_logger;
		bool found = false;

		/*
		 * See if the pid is one of the loggers
		 * */
		if (pv && pv->state) {
			head_platforms = &pv->state->platforms;
			dl_list_for_each_safe(p, tmp_p, head_platforms,
					struct pv_platform, list) {
				head_logger = &p->logger_list;
				dl_list_for_each_safe(l, tmp_l, head_logger,
						struct pv_log_info, next) {
					if (l->logger_pid == pid) {
						dl_list_del(&l->next);
						if (l->on_logger_closed) {
							l->on_logger_closed(l);
						}
						free(l);
						found = true;
					}
				}
				if (found)
					break;
			}
		}
		// Check for pantavisor
		if (pid != pv_pid)
			continue;

		pv_teardown(pv);

		if (WIFSIGNALED(wstatus) || WIFEXITED(wstatus)) {
			sleep(10);
			sync();
			if (!pv->system->is_embedded)
				reboot(LINUX_REBOOT_CMD_RESTART);
			else
				exit(0);
		}
	}
}

#ifdef PANTAVISOR_DEBUG
static void debug_shell(bool is_pid1)
{
	char c[64] = { 0 };
	int t = 5;
	int con_fd;
	char *ttyf;

	if (is_pid1) {
		con_fd = open("/dev/console", O_RDWR);
	} else {
		ttyf = ttyname(STDIN_FILENO);
		if (!ttyf) {
			printf("WARN: opening debug shell: %s\n", strerror(errno));
			return;
		}
		con_fd = open(ttyf , O_RDWR);
	}

	if (!con_fd) {
		printf("Unable to open %s: %s\n", ttyf, strerror(errno));
		return;
	}

	dprintf(con_fd, "Press [d] for debug ash shell... ");
	fcntl(con_fd, F_SETFL, fcntl(con_fd, F_GETFL) | O_NONBLOCK);
	while (t && (read(con_fd, &c, sizeof(c)) < 0)) {
		dprintf(con_fd, "%d ", t);
		fflush(NULL);
		sleep(1);
		t--;
	}
	dprintf(con_fd, "\n");

	if (c[0] == 'd')
		shell_pid = tsh_run("sh", 0, NULL);
}
#else
static void debug_shell(boot is_standalone)
{
	printf("Pantavisor debug shell disabled in production builds\n");
}

#endif

/* PV_STANDALONE will run pantavisor as pid 1, but without starting the
 * pantavisor main code itself; in this way one can boot the system
 * and run pantavisor in valgrind etc. from a shell for debugging
 */
#define PV_STANDALONE	(1 << 0)

/* PV_EMBEDDED will assume pantavisor is run inside an existing OS
 * it is similar to the manual run pantavisor in PV_STANDALONE case,
 * except that it also run the setup code to ensure that all the
 * essential mounts,etc. are available on the host OS.
 */
#define	PV_EMBEDDED	(1 << 1)

/* PV_EARLYMOUNTS enable earlymounts for embedded (non embedded is on by default)
 * Use this if you run in embedded mode on a system that has all the bits that
 * pantavisor needs
 */
#define PV_EARLYMOUNTS (1 << 2)

/*
 * PV_DEBUG will run pantavisor in DEBUG mode; this is the default at
 * this point
 */
#define	PV_DEBUG	(1 << 3)

static int is_arg(int argc, char *argv[], char *arg)
{
	if (argc < 2)
		return 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], arg) == 0)
			return i;
	}

	return 0;
}

static void parse_args(int argc, char *argv[], unsigned short *args)
{
	if (is_arg(argc, argv, "pv_standalone"))
		*args |= PV_STANDALONE;

	if (is_arg(argc, argv, "pv_embedded"))
		*args |= PV_EMBEDDED;

	if (is_arg(argc, argv, "pv_earlymounts"))
		*args |= PV_EARLYMOUNTS;

	if (is_arg(argc, argv, "debug"))
		*args |= PV_DEBUG;

	// For now
	*args |= PV_DEBUG;
}

static void usage(char *cmd) {
	printf("%s [pv_embedded | pv_standalone |] [pv_earlymounts] [debug]\n"
	       "\t[--version|--manifest]\n"
	       "\t[--prefix <prefix>] - custom prefix, e.g. /opt/pantavisor or PV_PREFIX\n"
	       "\t[--rundir <rundir>] - custom rundir, e.g. $prefix/run/ or PV_RUNDIR\n"
	       "\t[--pvdir <pvdirdir>] - custom prefix, e.g. $rundir/pv or PV_PVDIR\n"
	       "\t[--vardir <vardir>] - custom vardir, e.g. $prefix/var or PV_VARDIR\n"
	       "\t[--logdir <vardir>] - custom vardir, e.g. $vardir/log/pantavisor or PV_LOGDIR\n"
	       "\t[--datadir <datadir>] - custom datadir, e.g. $prefix/share or PV_DATADIR\n"
	       "\t[--etcdir <etcdir>] - custom etcdir, e.g. /etc/pantavisor or PV_ETCDIR\n", cmd);
	exit (1);
}

static struct pv_system* _init_system(bool is_embedded, int argc, char *argv[]) {

	bool is_standalone;
	char *prefix = NULL, *rundir = NULL, *etcdir = NULL;
	char *vardir = NULL, *logdir = NULL, *pvdir = NULL;
	char *pluginsdir = NULL, *datadir = NULL;
	char *cmd = argv[0];
	char *cmdline = calloc (sizeof(char), 4096);
	int pos = 0;

	is_standalone = is_arg(argc, argv, "pv_standalone");

	if (is_embedded && is_standalone) {
		printf ("ERROR: cannot use pv_embedded and pv_standalone at the same time\n");
		usage(cmd);
	}

	if ((pos = is_arg(argc, argv, "--prefix"))) {
		if (pos+1 == argc) {
			usage(cmd);
		}
		prefix = strdup(argv[pos]);
	} else if (getenv("PV_PREFIX")) {
		prefix = strdup(getenv("PV_PREFIX"));
	} else {
		prefix = is_embedded ? strdup("/opt/pantavisor") : strdup("/opt/pantavisor");
	}

	if ((pos = is_arg(argc, argv, "--rundir"))) {
		if (pos+1 == argc) {
			usage(cmd);
		}
		rundir = strdup(argv[pos]);
	} else if (getenv("PV_RUNDIR")) {
		rundir = strdup(getenv("PV_RUNDIR"));
	} else {
		rundir = strdup(prefix);
		rundir = realloc(rundir, strlen(rundir) + strlen("/run") + 1);
		rundir = strcat(rundir, "/run");
	}

	if ((pos = is_arg(argc, argv, "--pvdir"))) {
		if (pos+1 == argc) {
			usage(cmd);
		}
		pvdir = strdup(argv[pos]);
	} else if (getenv("PV_PVDIR")) {
		pvdir = strdup(getenv("PV_PVDIR"));
	} else {
		pvdir = strdup(rundir);
		pvdir = realloc(pvdir, strlen(pvdir) + strlen("/pv") + 1);
		pvdir = strcat(pvdir, "/pv");
	}

	if ((pos = is_arg(argc, argv, "--etcdir"))) {
		if (pos+1 == argc) {
			usage(cmd);
		}
		etcdir = strdup(argv[pos]);
	} else if (getenv("PV_ETCDIR")) {
		etcdir = strdup(getenv("PV_ETCDIR"));
	} else {
		etcdir = strdup(prefix);
		etcdir = realloc(etcdir, strlen(etcdir) + strlen("/etc") + 1);
		etcdir = strcat(etcdir, "/etc");
	}

	if ((pos = is_arg(argc, argv, "--vardir"))) {
		if (pos+1 == argc) {
			usage(cmd);
		}
		vardir = strdup(argv[pos]);
	} else if (getenv("PV_VARDIR")) {
		vardir = strdup(getenv("PV_VARDIR"));
	} else {
		vardir = strdup(prefix);
		vardir = realloc(vardir, strlen(vardir) + strlen("/var") + 1);
		vardir = strcat(vardir, "/var");
	}

	if ((pos = is_arg(argc, argv, "--logdir"))) {
		if (pos+1 == argc) {
			usage(cmd);
		}
		logdir = strdup(argv[pos]);
	} else if (getenv("PV_LOGDIR")) {
		logdir = strdup(getenv("PV_LOGDIR"));
	} else {
		logdir = strdup(vardir);
		logdir = realloc(logdir, (strlen(vardir) + strlen("/log/pantavisor") + 1) * sizeof(char));
		logdir = strcat(logdir, "/log/pantavisor");
	}

	if ((pos = is_arg(argc, argv, "--pluginsdir"))) {
		if (pos+1 == argc) {
			usage(cmd);
		}
		pluginsdir = strdup(argv[pos]);
	} else if (getenv("PV_PLUGINSDIR")) {
		pluginsdir = strdup(getenv("PV_PLUGINSDIR"));
	} else {
		pluginsdir = strdup(prefix);
		pluginsdir = realloc(pluginsdir, strlen(pluginsdir) + strlen("/plugins") + 1);
		pluginsdir = strcat(pluginsdir, "/plugins");
	}

	if ((pos = is_arg(argc, argv, "--datadir"))) {
		if (pos+1 == argc) {
			usage(cmd);
		}
		datadir = strdup(argv[pos]);
	} else if (getenv("PV_DATADIR")) {
		datadir = strdup(getenv("PV_DATADIR"));
	} else {
		datadir = strdup(prefix);
		datadir = realloc(datadir, strlen(datadir) + strlen("/share") + 1);
		datadir = strcat(datadir, "/share");
	}

	/* lets parse/assemble commandline */
	if (is_embedded) {
		int c = 2;
		for (int i = 1; i < argc; i++) {
			if ( (c + strlen(argv[i])) >= 4096) {
				printf("ERROR: cmdline is longer than 4096 characters ...\n");
				usage(cmd);
			}
			if (i > 1)
				cmdline = strcat(cmdline," ");
			cmdline = strcat(cmdline,argv[i]);
		}
	} else {
		int fd, bytes;
		char *buf;

		// Get current step revision from cmdline
		fd = open("/proc/cmdline", O_RDONLY);
		if (fd < 0) {
			printf("ERROR: cannot read /proc/cmdline for not embedded pantavisor: %s\n", strerror(errno));
			usage(cmd);
		}

		buf = calloc(1, sizeof(char) * 4096);
		if (!buf) {
			printf("ERROR: cannot allocate buf %s ...\n", strerror(errno));
			close(fd);
			usage(cmd);
		}

		bytes = read_nointr(fd, buf, sizeof(char)*4095);
		if (!bytes) {
			printf("ERROR: error reading bytes from /proc/cmdline %s ...\n", strerror(errno));
			close(fd);
			free(buf);
			usage(cmd);
		}
		buf[bytes] = 0;
		close(fd);
		strncpy(cmdline, buf, 4096);
		free(buf);
	}

	struct pv_system *pv_system = calloc(sizeof(struct pv_system), 1);
	pv_system->cmdline = strdup(cmdline);
	pv_system->prefix = prefix;
	pv_system->etcdir = etcdir;
	pv_system->vardir = vardir;
	pv_system->rundir = rundir;
	pv_system->pvdir  = pvdir;
	pv_system->logdir  = logdir;
	pv_system->pluginsdir = pluginsdir;
	pv_system->datadir = datadir;
	pv_system->is_embedded = is_embedded;
	pv_system->is_standalone = is_standalone;

	free(cmdline);
	return pv_system;
}

int main(int argc, char *argv[])
{
	unsigned short args = 0;
	bool is_embedded;
	struct pv_system *system;

	parse_args(argc, argv, &args);
	is_embedded = (args & PV_EMBEDDED);

	if (getpid() != 1 && !is_embedded) {
		if (is_arg(argc, argv, "--version")) {
			printf("version: %s\n", pv_build_version);
			return 0;
		}
		if (is_arg(argc, argv, "--manifest")) {
			printf("manifest: \n%s\n", pv_build_manifest);
			return 0;
		}
		if (is_arg(argc, argv, "--help")) {
			usage(argv[0]);
		}

		system = _init_system(is_embedded, argc, argv);
		goto run_pv;
	}

	if (!is_embedded || (args & PV_EARLYMOUNTS))
		early_mounts();

	system = _init_system(is_embedded, argc, argv);

	signal(SIGCHLD, signal_handler);

	if ((args & PV_DEBUG) && system->is_standalone) {
		debug_shell(true);
		debug_telnet();
	}

 run_pv:
	// Run PV main loop
	if (!system->is_standalone && !system->is_embedded)
		pv_pid = pantavisor_init(system, true);
	else
		pv_pid = pantavisor_init(system, false);

	// loop init
	for (;;)
		pause();

	return 0;
}

static int pv_debug_init(struct pv_init *this)
{
	bool ispid1 = !get_pv_system()->is_embedded;
	debug_shell(ispid1);
	debug_telnet();
	return 0;
}

struct pv_init pv_init_debug = {
	.init_fn = pv_debug_init,
	.flags = 0,
};

/*
 * The order of appearence is important here.
 * Make sure to list the initializer in the correct
 * order.
 */
struct pv_init *pv_init_tbl [] = {
	&pv_init_config,
	&pv_init_skel,
	&pv_init_debug,
	&pv_init_mount,
	&ph_init_config,
	&ph_init_mount,
	&pv_init_revision,
	&pv_init_log,
	&pv_init_device,
	&pv_init_network,
	&pv_init_platform,
	&pv_init_bl,
	&pv_init_state,
	&pv_init_update
};

int pv_do_execute_init()
{
	int i = 0;

	for ( i = 0; i < ARRAY_LEN(pv_init_tbl); i++) {
		struct pv_init *init = pv_init_tbl[i];
		int ret = 0;

		ret = init->init_fn(init);
		if (ret) {
			if (!(init->flags & PV_INIT_FLAG_CANFAIL))
				return -1;
		}
	}
	return 0;
}
