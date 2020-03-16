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

#include <linux/reboot.h>

#define MODULE_NAME			"updater"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "tsh.h"
#include "pantavisor.h"
#include "version.h"
#include "init.h"
#include "utils/list.h"
#include <stdbool.h>

#define MAX_PROC_STATUS (10)
pid_t pv_pid;
pid_t shell_pid;

static int open_ns(int pid, const char *ns_proc_name)
{
	int fd;
	char path[MAXPATHLEN];
	snprintf(path, MAXPATHLEN, "/proc/%d/ns/%s", pid, ns_proc_name);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("failed to open %s", path);
		return -1;
	}
	return fd;
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
static void debug_telnet()
{
	tsh_run("ifconfig lo up", 0, NULL);
	tsh_run("telnetd -b 127.0.0.1 -l /bin/sh", 0, NULL);
	tsh_run("dropbear -E -p 0.0.0.0:8222 -n /pv/user-meta/pvr-sdk.authorized_keys -R -c /usr/bin/fallbear-cmd", 0, NULL);
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
		struct pv_platform *p = NULL;
		struct pv_log_info *item, *tmp;
		struct dl_list *head;
		bool found = false;

		/*
		 * See if the pid is one of the loggers
		 * */
		if (pv && pv->state) {
			p = pv->state->platforms;
		}
		while (p) {
			head = &p->logger_list;
			dl_list_for_each_safe(item, tmp, head,
					struct pv_log_info, next) {
				if (item->logger_pid == pid) {
					dl_list_del(&item->next);
					if (item->on_logger_closed) {
						item->on_logger_closed(item);
					}
					free(item);
					found = true;
				}
			}
			if (found)
				break;
			p = p->next;
		}
		// Check for pantavisor
		if (pid != pv_pid)
			continue;

		if (WIFSIGNALED(wstatus) || WIFEXITED(wstatus)) {
			sleep(10);
			sync();
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
		shell_pid = tsh_run("sh", 0, NULL);
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

int main(int argc, char *argv[])
{
	unsigned short args = 0;
	parse_args(argc, argv, &args);

	if (getpid() != 1) {
		if (is_arg(argc, argv, "--version")) {
			printf("version: %s\n", pv_build_version);
			return 0;
		}
		if (is_arg(argc, argv, "--manifest")) {
			printf("manifest: \n%s\n", pv_build_manifest);
			return 0;
		}
		pantavisor_init(false);
		return 0;
	}

	early_mounts();
	signal(SIGCHLD, signal_handler);

	if (args & PV_DEBUG) {
		debug_shell();
		debug_telnet();
	}

	// Run PV main loop
	if (!(args & PV_STANDALONE))
		pv_pid = pantavisor_init(true);

	// loop init
	for (;;)
		pause();

	return 0;
}
