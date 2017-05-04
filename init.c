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
#define sc_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "tsh.h"
#include "systemc.h"

pid_t sc_pid;
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

	ret = mount("none", "/sys/fs/cgroup", "cgroup", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /sys/fs/cgroup");

	mkdir("/sys/fs/cgroup/systemd", 0644);
	ret = mount("cgroup", "/sys/fs/cgroup/systemd", "cgroup", 0, "none,name=systemd");
	if (ret < 0)
		exit_error(errno, "Could not mount /sys/fs/cgroup/systemd");

	mkdir("/root", 0644);
	ret = mount("none", "/root", "tmpfs", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /root");

	return 0;
}

static void debug_telnet()
{
	tsh_run("ifconfig lo up");
	//tsh_run("ifconfig eth0 192.168.20.222");
	tsh_run("telnetd -l /bin/ash");
}

static void signal_handler(int signal)
{
	pid_t pid = 0;
	int wstatus;

	if (signal != SIGCHLD)
		return;

	while (pid == 0) {
		pid = waitpid(-1, &wstatus, WNOHANG | WUNTRACED);
	}

	// Check for systemc
	if (pid == sc_pid) {
		if (WIFSIGNALED(wstatus)) {
			sc_log(WARN, "restarting systemc");
			systemc_init();
		} else if (WIFEXITED(wstatus)) {
			sc_log(INFO, "clean exit from systemc, rebooting...");
			sleep(1);
			sync();
			reboot(LINUX_REBOOT_CMD_RESTART);
		}
	}

	if (pid == shell_pid) {
		sc_log(WARN, "reaped shell, restarting /bin/ash");
		shell_pid = tsh_run("ash");
	}
}

static void debug_shell()
{
	char c[64] = { 0 };
	int t = 3;
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
		shell_pid = tsh_run("ash");
}


int main(int argc, char *argv[])
{
	int debug = 1; // Read from cmdline

	early_mounts();

	signal(SIGCHLD, signal_handler);

	if (debug)
		debug_shell();
		debug_telnet();

	systemc_init();

	for (;;)
		pause();

	return 0;
}
