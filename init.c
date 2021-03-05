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

#include <string.h>
#include <stdbool.h>
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
#include "tsh.h"
#include "pantavisor.h"
#include "version.h"
#include "utils.h"
#include "utils/list.h"
#include "pvlogger.h"
#include "platforms.h"
#include "state.h"

#define MODULE_NAME			"updater"
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
	sprintf(path, "/sys/fs/cgroup/%s", cgroup);
	mkdir(path, 0555);
	ret = mount("cgroup", path, "cgroup", 0, cgroup);
	if (ret < 0) {
		char *err = malloc(sizeof(char) * (strlen(path) + strlen("Could not mount cgroup %s") + 2));
		sprintf(err, "Could not mount cgroup %s", path);
		printf("ERROR: %s\n", err);
		return -1;
	}
	return 0;
}

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
static void debug_telnet()
{
	tsh_run("ifconfig lo up", 0, NULL);
	tsh_run("dropbear -p 0.0.0.0:8222 -n /pv/user-meta/pvr-sdk.authorized_keys -R -c /usr/bin/fallbear-cmd", 0, NULL);
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

	while (	(pid = waitpid(pv_pid, &wstatus, WNOHANG)) > 0) {
		if (pv_pid == 0)
			continue;

		pv_teardown(pv);

		if (WIFSIGNALED(wstatus) || WIFEXITED(wstatus)) {
			sync();
			sleep(10);
			reboot(LINUX_REBOOT_CMD_RESTART);
		}
	}
}

#ifdef PANTAVISOR_DEBUG
static void debug_shell()
{
	char c[64] = { 0 };
	int t = 5;
	int con_fd;

	con_fd = open("/dev/console", O_RDWR);
	if (!con_fd) {
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

#define PV_STANDALONE	(1 << 0)
#define	PV_DEBUG	(1 << 1)

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

static void parse_args(int argc, char *argv[], unsigned short *args)
{
	if (is_arg(argc, argv, "pv_standalone"))
		*args |= PV_STANDALONE;

	if (is_arg(argc, argv, "debug"))
		*args |= PV_DEBUG;

	// For now
	*args |= PV_DEBUG;
}

static void redirect_io()
{
	int nullfd, outfd;
	outfd = open("/dev/kmsg", O_RDWR | O_LARGEFILE);
	nullfd = open("/dev/null", O_RDWR | O_LARGEFILE);
	if (outfd) {
		dup2(outfd, fileno(stdout));
		dup2(outfd, fileno(stderr));
		dup2(nullfd, fileno(stdin));
	}
}

int main(int argc, char *argv[])
{
	pv_pid = 0;
	shell_pid = 0;

	unsigned short args = 0;
	parse_args(argc, argv, &args);

	// executed from shell
	if (getpid() != 1) {
		if (is_arg(argc, argv, "--version")) {
			printf("version: %s\n", pv_build_version);
			return 0;
		}
		if (is_arg(argc, argv, "--manifest")) {
			printf("manifest: \n%s\n", pv_build_manifest);
			return 0;
		}
		// we are going to use this thread for pv
		pv_pid = getpid();
		redirect_io();
		pantavisor_init();
		return 0;
	}

	// extecuted as init
	early_mounts();
	signal(SIGCHLD, signal_handler);

	// in case of standalone is set, we only start debugging tools up in main thread
	if ((args & PV_STANDALONE) && (args & PV_DEBUG)) {
		debug_shell();
		debug_telnet();
		goto loop;
	}

	// create pv thread
	pv_pid = fork();
	if (pv_pid > 0)
		goto loop;

	// these debugging tools will be children of the pv thread, so we can controll them
	if (args & PV_DEBUG) {
		debug_shell();
		debug_telnet();
	}
	redirect_io();
	pantavisor_init();

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
	&pv_init_config,
	&pv_init_mount,
	&pv_init_creds,
	&ph_init_mount,
	&pv_init_revision,
	&pv_init_config_trail,
	&pv_init_log,
	&pv_init_storage,
	&pv_init_metadata,
	&pv_init_cmd,
	&pv_init_network,
	&pv_init_platform,
	&pv_init_bl,
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
