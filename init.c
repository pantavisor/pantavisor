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

	mkdir("/root", 0644);
	ret = mount("none", "/root", "tmpfs", 0, NULL);
	if (ret < 0)
		exit_error(errno, "Could not mount /root");

	return 0;
}

static void debug_init()
{
	tsh_run("ifconfig lo up");
	tsh_run("ifconfig eth0 192.168.53.76");
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

	printf("init: reaped pid=%d\n", pid);

	// Check for systemc
	if (pid == sc_pid) {
		if (WIFSIGNALED(wstatus)) {
			printf("init: restarting systemc...\n");
			systemc_init();
		} else if (WIFEXITED(wstatus)) {
			printf("init: clean exit from systemc, rebooting...\n");
			sleep(1);
			sync();
			reboot(LINUX_REBOOT_CMD_RESTART);
		} 
	}

	if (pid == shell_pid) {
		printf("init: reaped shell, restarting /bin/ash\n");
		shell_pid = tsh_run("ash");
	}
}

int main(int argc, char *argv[])
{
	int debug = 1; // Read from cmdline

	early_mounts();

	signal(SIGCHLD, signal_handler);

	systemc_init();

	if (debug)
		debug_init();

	// Spawn shell
	printf("Execing /bin/ash...");
	shell_pid = tsh_run("ash");

	for (;;)
		pause();

	return 0;
}
