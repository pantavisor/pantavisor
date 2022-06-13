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

#include <string.h>
#include <stdbool.h>
#include <dirent.h>
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

#include <linux/reboot.h>

#include "init.h"
#include "config.h"
#include "pantavisor.h"
#include "version.h"
#include "pvlogger.h"
#include "platforms.h"
#include "volumes.h"
#include "state.h"
#include "paths.h"
#include "utils/tsh.h"
#include "utils/math.h"
#include "utils/list.h"
#include "utils/str.h"
#include "utils/filesystem.h"

#define MODULE_NAME		"init"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

#define MAX_PROC_STATUS (10)
pid_t pv_pid;
pid_t shell_pid;

static int mkcgroup(const char* cgroup) {
	char path[PATH_MAX];
	int ret;
	SNPRINTF_WTRUNC(path, sizeof (path), "/sys/fs/cgroup/%s", cgroup);

	mkdir(path, 0555);
	ret = mount("cgroup", path, "cgroup", 0, cgroup);
	if (ret < 0) {
		printf("ERROR: Could not mount cgroup %s\n", path);
		return -1;
	}
	return 0;
}

static int early_mounts()
{
	int ret;

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

	return 0;
}

static int mount_cgroups()
{
	int ret;
	struct stat st;

	mkdir("/sys/fs/cgroup", 0755);
	ret = mount("none", "/sys/fs/cgroup", "tmpfs", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /sys/fs/cgroup");

	mkdir("/sys/fs/cgroup/systemd", 0555);
	ret = mount("cgroup", "/sys/fs/cgroup/systemd", "cgroup", 0, "none,name=systemd");
	if (ret < 0)
		exit_error(errno, "Could not mount /sys/fs/cgroup/systemd");

	mkcgroup("blkio");
	mkcgroup("cpu,cpuacct");
	mkcgroup("cpu");
	mkcgroup("cpuset");
	mkcgroup("devices");
	mkcgroup("freezer");
	mkcgroup("hugetlb");
	mkcgroup("memory");
	mkcgroup("net_cls,net_prio");
	mkcgroup("net_cls");
	mkcgroup("net_prio");
	mkcgroup("perf_event");
	mkcgroup("pids");
	mkcgroup("rdma");

	mkdir("/sys/fs/cgroup/unified", 0555);
	ret = mount("none", "/sys/fs/cgroup/unified", "cgroup2", 0, NULL);
	if (ret < 0)
		printf("WARN: Could not mount cgroup2 to /sys/fs/cgroup/unified\n");

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

	mkdir("/exports", 0755);
	ret = mount("none", "/exports", "tmpfs", 0, NULL);
	if (!ret)
		ret = mount("none", "/exports", "tmpfs", MS_REC | MS_SHARED, NULL);
	if (ret < 0)
		exit_error(errno, "Could not create /exports disk");

	return 0;
}

#ifdef PANTAVISOR_DEBUG
#define DBCMD "dropbear -p 0.0.0.0:8222 -n %s -R -c /usr/bin/fallbear-cmd"

static void debug_telnet()
{
	char *dbcmd;
	char path[PATH_MAX];

	pv_paths_pv_usrmeta_key(path, PATH_MAX, SSH_KEY_FNAME);
  dbcmd = calloc(sizeof(DBCMD) + strlen(path) + 1, sizeof(char));
	sprintf(dbcmd, DBCMD, path);

	tsh_run("ifconfig lo up", 0, NULL);
	tsh_run(dbcmd, 0, NULL);

	free(dbcmd);
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

	if (signal != SIGCHLD)
		return;

	while (	(pid = waitpid(pv_pid, &wstatus, WNOHANG)) > 0) {
		if (pv_pid == 0)
			continue;

		pv_stop();

		if (WIFSIGNALED(wstatus) || WIFEXITED(wstatus)) {
			sync();
			sleep(10);
			reboot(LINUX_REBOOT_CMD_RESTART);
		}
	}
}

#define HOOKS_EARLY_SPAWN "/lib/pv/hooks_early.spawn"

static void early_spawns()
{
	DIR *d;
	struct dirent *dir;
	char path[PATH_MAX];

	pv_paths_lib_hooks_early_spawn(path, PATH_MAX, "");
	printf("starting early spawns from: %s\n", path);
	d = opendir(path);
	while (d && (dir = readdir(d)) != NULL) {
		struct stat sb;

		if (!strcmp("..", dir->d_name) || !strcmp(".", dir->d_name))
			continue;

		pv_paths_lib_hooks_early_spawn(path, PATH_MAX, dir->d_name);

		if (!(stat(path, &sb) == 0 && sb.st_mode & S_IXUSR)) {
			printf("early_spawns: skipping not executable hook: %s\n", path);
			continue;
		}
		printf("early_spawns: starting: %s\n", path);
		tsh_run(path, 0, NULL);
	}
	if (d)
		closedir(d);
}

#ifdef PANTAVISOR_DEBUG
static void debug_shell()
{
	char c[64] = { 0 };
	int t = 5;
	int con_fd;

	con_fd = open("/dev/console", O_RDWR);
	if (con_fd < 0) {
		printf("Unable to open /dev/console\n");
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
		shell_pid = tsh_run("/sbin/getty -n -l /bin/sh 0 console", 0, NULL);
}
#else
static void debug_shell()
{
	printf("Pantavisor debug shell disabled in production builds\n");
}

#endif

static int is_arg(int argc, char *argv[], char *arg)
{
	if (argc < 2)
		return 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], arg) == 0)
			return 1;
	}

	return 0;
}

static void parse_commands(int argc, char *argv[])
{
	if (is_arg(argc, argv, "pv_embedded"))
		pv_config_set_system_init_mode(IM_EMBEDDED);

	if (is_arg(argc, argv, "pv_standalone"))
		pv_config_set_system_init_mode(IM_STANDALONE);

	if (is_arg(argc, argv, "pv_appengine"))
		pv_config_set_system_init_mode(IM_APPENGINE);

	if (is_arg(argc, argv, "debug"))
		pv_config_set_debug_shell(true);

	if (!is_arg(argc, argv, "splash"))
		pv_config_set_debug_ssh(true);
}

static void redirect_io()
{
	int nullfd, outfd;
	outfd = open("/dev/kmsg", O_RDWR | O_LARGEFILE);
	nullfd = open("/dev/null", O_RDWR | O_LARGEFILE);
	if ((outfd >= 0) &&
		(nullfd >= 0)) {
		dup2(outfd, fileno(stdout));
		dup2(outfd, fileno(stderr));
		dup2(nullfd, fileno(stdin));
	}
}

static void usage(const char *cmd)
{
	printf("%s [options] [commands]\n", cmd);
	printf("options:\n");
	printf("    --help          this help\n");
	printf("    --version       show pantavisor version\n");
	printf("    --manifest      show pantavisor manifest\n");
	printf("    --config <path> pantavisor.config path (default: /etc/pantavisor.config)\n");
	printf("commands:\n");
	printf("    pv_embedded     run pantavisor starting the main thread (default)\n");
	printf("    pv_standalone   run pantavisor without starting the main thread\n");
	printf("    pv_appengine    run pantavisor inside an existing OS\n");

}

static void parse_options(int argc, char *argv[], char **config_path, char **cmdline)
{
	char *cmd = argv[0];
	int pos = 1;

	if (getpid() == 1)
		return;

	// parse options

	if (is_arg(argc, argv, "--help")) {
		usage(cmd);
		exit(0);
	}

	if (is_arg(argc, argv, "--version")) {
		printf("version: %s\n", pv_build_version);
		exit(0);
	}

	if (is_arg(argc, argv, "--manifest")) {
		printf("manifest: \n%s\n", pv_build_manifest);
		exit(0);
	}

	if (is_arg(argc, argv, "--config")) {
		pos++;
		if (pos >= argc) {
			usage(cmd);
			exit(1);
		}
		*config_path = argv[pos];
		pos++;
	}

	if (is_arg(argc, argv, "--cmdline")) {
		pos++;
		if (pos >= argc) {
			usage(cmd);
			exit(1);
		}
		*cmdline = argv[pos];
		pos++;
	}
}

#define SIZE_CMDLINE_BUF 1024

static int read_cmdline(const char *arg_cmdline)
{
	struct pantavisor *pv = pv_get_instance();
	char buf[SIZE_CMDLINE_BUF];
	int ret = -1, fd, bytes;

	if (arg_cmdline) {
		pv->cmdline = strdup(arg_cmdline);
		printf("DEBUG: cmdline loaded from arg: '%s'\n", pv->cmdline);
		return 0;
	}

	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0) {
		printf("ERROR: cannot open /proc/cmdline: %s", strerror(errno));
		return ret;
	}

	bytes = pv_filesystem_file_read_nointr(fd, buf, SIZE_CMDLINE_BUF);
	if (bytes < 0) {
		printf("ERROR: cannot read /proc/cmdline: %s", strerror(errno));
		goto out;
	}

	// remove trailing \n
	buf[bytes-1] = '\0';

	pv->cmdline = calloc(bytes, sizeof(char));
	if (!pv->cmdline) {
		printf("ERROR: cannot allocate cmdline: %s", strerror(errno));
		goto out;
	}

	strncpy(pv->cmdline, buf, bytes);
	printf("DEBUG: cmdline loaded from /proc/cmdline: '%s'\n", pv->cmdline);

	ret = 0;

out:
	close(fd);
	return ret;
}

int main(int argc, char *argv[])
{
	char *config_path = NULL, *cmdline = NULL;

	pv_pid = 0;
	shell_pid = 0;

	// extecuted as init
	if (getpid() == 1) {
		early_mounts();
		signal(SIGCHLD, signal_handler);
	}

	// get command argument options
	parse_options(argc, argv, &config_path, &cmdline);

	// init pv struct
	pv_init();

	// read /proc/cmdline if not injected from args
	if (read_cmdline(cmdline))
		exit(1);

	// init config
	if (pv_config_init(config_path))
		exit(1);

	// this might override the configuration
	parse_commands(argc, argv);

	// in case of standalone is set, we only start debugging tools up in main thread
	if ((pv_config_get_system_init_mode() == IM_STANDALONE) &&
		pv_config_get_debug_ssh()) {
		if (pv_config_get_debug_shell())
			debug_shell();
		debug_telnet();
		goto loop;
	}

	mount_cgroups();

	// executed from shell
	if (getpid() != 1) {
		// we are going to use this thread for pv
		pv_pid = getpid();
		pv_start();
		pv_stop();
		return 0;
	}

	// create pv thread
	pv_pid = fork();
	if (pv_pid > 0)
		goto loop;

	// these debugging tools will be children of the pv thread, so we can controll them
	if (pv_config_get_debug_ssh()) {
		if (pv_config_get_debug_shell())
			debug_shell();
		debug_telnet();
	}
	redirect_io();
	early_spawns();
	pv_start();
	pv_stop();

loop:
	redirect_io();
	for (;;)
		pause();

	return 0;
}
/*
 * The order of appearence is important here.
 * Make sure to list the initializer in the correct
 * order.
 */
struct pv_init *pv_init_tbl [] = {
	&pv_init_mount,
	&pv_init_creds,
	&ph_init_mount,
	&pv_init_bl,
	&pv_init_config_trail,
	&pv_init_log,
	&pv_init_storage,
	&pv_init_metadata,
	&pv_init_ctrl,
	&pv_init_network,
	&pv_init_volume,
	&pv_init_platform,
	&pv_init_pantavisor,
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
