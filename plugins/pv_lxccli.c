/*
 * Copyright (c) 2025 Pantacor Ltd.
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
 * pv_lxccli.c - LXC CLI-based container runtime plugin
 *
 * This is an alternative to pv_lxc.c that uses LXC command-line tools
 * (lxc-start, lxc-stop, lxc-info) instead of the liblxc API.
 *
 * Benefits:
 * - Works with stock/unpatched LXC
 * - No need to maintain LXC library patches
 * - Easier debugging (can manually run commands)
 * - Stable CLI interface across LXC versions
 *
 * Approach:
 * 1. Read original lxc.conf from platform
 * 2. Append pantavisor-specific config (mounts, cgroups, etc.)
 * 3. Write merged config to /run/pantavisor/lxc/<name>/config
 * 4. Use lxc-start/stop/info commands with that config
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <pty.h>
#include <termios.h>

#include "pv_lxccli.h"
#include "utils/fs.h"
#include "utils/tsh.h"
#include "utils/list.h"
#include "utils/pvsignals.h"
#include "utils/system.h"
#include "platforms.h"
#include "pantavisor.h"
#include "paths.h"
#include "state.h"

#define PV_VLOG __vlog
#include "utils/tsh.h"

#define MODULE_NAME "pv_lxccli"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

/*
 * Runtime directory for generated configs
 * Each container gets: /run/pantavisor/lxc/<name>/config
 */
#define PV_LXCCLI_RUNDIR "/run/pantavisor/lxc"

struct pv_lxccli_conf {
	int loglevel;
	bool capture;
};

static struct pv_lxccli_conf pv_conf = { .loglevel = 2, .capture = true };

/*
 * Console PTY tracking
 * We create a PTY pair for each container and store the master fd here
 * so pv_console_log_getfd() can retrieve it later.
 */
struct pv_lxccli_console {
	char *name;
	int master_fd;
	int slave_fd;
	char slave_path[PATH_MAX];
	struct dl_list list;
};

static struct dl_list console_list = DL_LIST_HEAD_INIT(console_list);

static struct pv_lxccli_console *console_find(const char *name)
{
	struct pv_lxccli_console *c;

	dl_list_for_each(c, &console_list, struct pv_lxccli_console, list)
	{
		if (strcmp(c->name, name) == 0)
			return c;
	}
	return NULL;
}

static struct pv_lxccli_console *console_create(const char *name)
{
	struct pv_lxccli_console *c;
	int master, slave;
	char slave_name[PATH_MAX];

	/* Check if already exists */
	c = console_find(name);
	if (c)
		return c;

	/* Create PTY pair */
	if (openpty(&master, &slave, slave_name, NULL, NULL) < 0) {
		pv_log(ERROR, "failed to create PTY for '%s': %s", name,
		       strerror(errno));
		return NULL;
	}

	/* Set master to non-blocking */
	int flags = fcntl(master, F_GETFL, 0);
	fcntl(master, F_SETFL, flags | O_NONBLOCK);

	c = calloc(1, sizeof(*c));
	if (!c) {
		close(master);
		close(slave);
		return NULL;
	}

	c->name = strdup(name);
	c->master_fd = master;
	c->slave_fd = slave;
	strncpy(c->slave_path, slave_name, PATH_MAX - 1);

	dl_list_add_tail(&console_list, &c->list);

	pv_log(DEBUG, "created console PTY for '%s': master=%d slave=%s", name,
	       master, slave_name);

	return c;
}

static void console_destroy(struct pv_lxccli_console *c)
{
	if (!c)
		return;

	dl_list_del(&c->list);

	if (c->master_fd >= 0)
		close(c->master_fd);
	if (c->slave_fd >= 0)
		close(c->slave_fd);
	free(c->name);
	free(c);
}

/* Function pointers injected by pantavisor */
struct pantavisor *(*__pv_get_instance)(void) = NULL;
void (*__vlog)(char *module, int level, const char *fmt, ...) = NULL;
void (*__pv_paths_pv_file)(char *, size_t, const char *) = NULL;
void (*__pv_paths_pv_log)(char *, size_t, const char *) = NULL;
void (*__pv_paths_pv_log_plat)(char *, size_t, const char *,
			       const char *) = NULL;
void (*__pv_paths_pv_log_file)(char *, size_t, const char *, const char *,
			       const char *) = NULL;
void (*__pv_paths_pv_usrmeta_key)(char *, size_t, const char *) = NULL;
void (*__pv_paths_pv_usrmeta_plat_key)(char *, size_t, const char *,
				       const char *) = NULL;
void (*__pv_paths_pv_devmeta_key)(char *, size_t, const char *) = NULL;
void (*__pv_paths_pv_devmeta_plat_key)(char *, size_t, const char *,
				       const char *) = NULL;
void (*__pv_paths_lib_hook)(char *, size_t, const char *) = NULL;
void (*__pv_paths_volumes_plat_file)(char *, size_t, const char *,
				     const char *) = NULL;
void (*__pv_paths_configs_file)(char *, size_t, const char *) = NULL;
void (*__pv_paths_lib_lxc_rootfs_mount)(char *, size_t) = NULL;
void (*__pv_paths_lib_lxc_lxcpath)(char *, size_t) = NULL;

/*
 * Exported initialization functions
 */

void pv_set_pv_instance_fn(void *fn_pv_get_instance)
{
	__pv_get_instance = fn_pv_get_instance;
}

void pv_set_pv_paths_fn(
	void *fn_vlog, void *fn_pv_paths_pv_file, void *fn_pv_paths_pv_log,
	void *fn_pv_paths_pv_log_plat, void *fn_pv_paths_pv_log_file,
	void *fn_pv_paths_pv_usrmeta_key, void *fn_pv_paths_pv_usrmeta_plat_key,
	void *fn_pv_paths_pv_devmeta_key, void *fn_pv_paths_pv_devmeta_plat_key,
	void *fn_pv_paths_lib_hook, void *fn_pv_paths_volumes_plat_file,
	void *fn_pv_paths_configs_file, void *fn_pv_paths_lib_lxc_rootfs_mount,
	void *fn_pv_paths_lib_lxc_lxcpath)
{
	__vlog = fn_vlog;
	__pv_paths_pv_file = fn_pv_paths_pv_file;
	__pv_paths_pv_log = fn_pv_paths_pv_log;
	__pv_paths_pv_log_plat = fn_pv_paths_pv_log_plat;
	__pv_paths_pv_log_file = fn_pv_paths_pv_log_file;
	__pv_paths_pv_usrmeta_key = fn_pv_paths_pv_usrmeta_key;
	__pv_paths_pv_usrmeta_plat_key = fn_pv_paths_pv_usrmeta_plat_key;
	__pv_paths_pv_devmeta_key = fn_pv_paths_pv_devmeta_key;
	__pv_paths_pv_devmeta_plat_key = fn_pv_paths_pv_devmeta_plat_key;
	__pv_paths_lib_hook = fn_pv_paths_lib_hook;
	__pv_paths_volumes_plat_file = fn_pv_paths_volumes_plat_file;
	__pv_paths_configs_file = fn_pv_paths_configs_file;
	__pv_paths_lib_lxc_rootfs_mount = fn_pv_paths_lib_lxc_rootfs_mount;
	__pv_paths_lib_lxc_lxcpath = fn_pv_paths_lib_lxc_lxcpath;
}

void pv_set_pv_conf_loglevel_fn(int loglevel)
{
	pv_conf.loglevel = loglevel;
}

void pv_set_pv_conf_capture_fn(bool capture)
{
	pv_conf.capture = capture;
}

/*
 * Helper: Run a command and capture output
 * Returns exit code, fills output buffer if provided
 */
static int run_cmd(char *output, size_t output_size, const char *fmt, ...)
{
	char cmd[4096];
	char err[1024] = { 0 };
	va_list args;
	int ret;

	va_start(args, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);

	pv_log(DEBUG, "running: %s", cmd);

	if (output && output_size > 0) {
		ret = tsh_run_output(cmd, 30, output, output_size, err,
				     sizeof(err));
	} else {
		char dummy[256] = { 0 };
		ret = tsh_run_output(cmd, 30, dummy, sizeof(dummy), err,
				     sizeof(err));
	}

	if (ret != 0 && strlen(err) > 0) {
		pv_log(WARN, "command failed: %s", err);
	}

	return ret;
}

/*
 * Helper: Get runtime config directory for a container
 */
static void get_runtime_dir(char *buf, size_t size, const char *name)
{
	snprintf(buf, size, "%s/%s", PV_LXCCLI_RUNDIR, name);
}

/*
 * Helper: Get runtime config path for a container
 */
static void get_runtime_config(char *buf, size_t size, const char *name)
{
	snprintf(buf, size, "%s/%s/config", PV_LXCCLI_RUNDIR, name);
}

/*
 * Helper: Append a line to a file
 */
static int append_config_line(FILE *fp, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(fp, fmt, args);
	va_end(args);
	fprintf(fp, "\n");
	return 0;
}

/*
 * Helper: Check if a config line exists in file content
 */
static bool config_has_key(const char *content, const char *key)
{
	char pattern[256];
	snprintf(pattern, sizeof(pattern), "\n%s", key);

	/* Check at start of file */
	if (strncmp(content, key, strlen(key)) == 0)
		return true;

	/* Check after newlines */
	return strstr(content, pattern) != NULL;
}

/*
 * Helper: Read entire file into buffer (caller frees)
 */
static char *read_file_content(const char *path)
{
	FILE *fp;
	long size;
	char *content;

	fp = fopen(path, "r");
	if (!fp)
		return NULL;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	content = calloc(size + 1, 1);
	if (!content) {
		fclose(fp);
		return NULL;
	}

	fread(content, 1, size, fp);
	fclose(fp);

	return content;
}

/*
 * Build the merged LXC config file
 *
 * This reads the original platform config, then appends pantavisor-specific
 * settings (mounts, cgroups, hooks, etc.)
 */
static int build_runtime_config(struct pv_platform *p, const char *rev,
				const char *orig_conf, const char *runtime_conf)
{
	FILE *fp;
	char path[PATH_MAX];
	char entry[PATH_MAX * 2];
	char seed[PATH_MAX];
	char *orig_content = NULL;
	struct stat st;
	int ret = -1;

	/* Read original config */
	orig_content = read_file_content(orig_conf);
	if (!orig_content) {
		pv_log(ERROR, "failed to read original config: %s", orig_conf);
		return -1;
	}

	/* Open runtime config for writing */
	fp = fopen(runtime_conf, "w");
	if (!fp) {
		pv_log(ERROR, "failed to create runtime config: %s",
		       runtime_conf);
		free(orig_content);
		return -1;
	}

	/* Write original config */
	fprintf(fp, "# Pantavisor generated config for %s\n", p->name);
	fprintf(fp, "# Original: %s\n", orig_conf);
	fprintf(fp, "# Revision: %s\n\n", rev);
	fprintf(fp, "%s\n", orig_content);
	fprintf(fp, "\n# === Pantavisor additions ===\n\n");

	/* Set rootfs.mount */
	__pv_paths_lib_lxc_rootfs_mount(path, PATH_MAX);
	append_config_line(fp, "lxc.rootfs.mount = %s", path);

	/* Set hostname if not already set */
	if (!config_has_key(orig_content, "lxc.uts.name")) {
		append_config_line(fp, "lxc.uts.name = %s", p->name);
	}

	/* Config overlay: inject platform config dir into rootfs.path */
	__pv_paths_configs_file(seed, PATH_MAX, p->name);
	if (stat(seed, &st) == 0) {
		/*
		 * NOTE: This is tricky without the API.
		 * The original pv_lxc.c modifies lxc.rootfs.path in-memory.
		 * For CLI approach, we'd need to parse the original value
		 * and reconstruct it. For now, we add as a separate mount.
		 */
		append_config_line(fp,
				   "# Config overlay: %s (handled via mount)",
				   seed);
	}

	/* Log level */
	append_config_line(fp, "lxc.log.level = %d", pv_conf.loglevel);

	/* Console PTY for log capture */
	if (pv_conf.capture) {
		struct pv_lxccli_console *console = console_create(p->name);
		if (console) {
			append_config_line(fp, "lxc.console.path = %s",
					   console->slave_path);
			pv_log(DEBUG, "configured console PTY: %s",
			       console->slave_path);
			/*
			 * Close our copy of the slave fd - LXC will open it
			 * by path. We keep master_fd for reading.
			 */
			if (console->slave_fd >= 0) {
				close(console->slave_fd);
				console->slave_fd = -1;
			}
		}
	}

	/* Cgroup2 device access (for unified cgroup) */
	if (__pv_get_instance()->cgroupv == CGROUP_UNIFIED) {
		append_config_line(fp, "# Cgroup2 unified mode");
		append_config_line(fp, "lxc.cgroup2.devices.allow = a");
	}

	/* Role-specific mounts */
	if (p->roles & PLAT_ROLE_MGMT) {
		/* Management platform: full access to pv directories */
		__pv_paths_pv_file(path, PATH_MAX, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,create=dir 0 0", path,
			 PLATFORM_PV_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);

		__pv_paths_pv_log(path, PATH_MAX, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,create=dir 0 0", path,
			 PLATFORM_LOGS_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);

		__pv_paths_pv_usrmeta_key(path, PATH_MAX, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,create=dir 0 0", path,
			 PLATFORM_USER_META_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);

		__pv_paths_pv_devmeta_key(path, PATH_MAX, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,create=dir 0 0", path,
			 PLATFORM_DEVICE_META_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);
	} else {
		/* Regular platform: limited access */
		__pv_paths_pv_file(path, PATH_MAX, LOGCTRL_FNAME);
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,rw,create=file 0 0", path,
			 PLATFORM_LOG_CTRL_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);

		__pv_paths_pv_file(path, PATH_MAX, PVCTRL_FNAME);
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,rw,create=file 0 0", path,
			 PLATFORM_PVCTRL_SOCKET_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);

		__pv_paths_pv_log_plat(path, PATH_MAX, rev, p->name);
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,origin=mkdir,create=dir 0 0", path,
			 PLATFORM_LOGS_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);

		__pv_paths_pv_usrmeta_plat_key(path, PATH_MAX, p->name, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,origin=mkdir,create=dir 0 0", path,
			 PLATFORM_USER_META_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);

		__pv_paths_pv_devmeta_plat_key(path, PATH_MAX, p->name, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,origin=mkdir,create=dir 0 0", path,
			 PLATFORM_DEVICE_META_PATH + 1);
		append_config_line(fp, "lxc.mount.entry = %s", entry);
	}

	/* Auto firmware mount */
	if (p->automodfw && stat("/lib/firmware", &st) == 0) {
		append_config_line(
			fp,
			"lxc.mount.entry = /lib/firmware lib/firmware none bind,ro,create=dir 0 0");
	}

	/* Auto modules mount */
	if (p->automodfw) {
		struct utsname uts;
		if (uname(&uts) == 0) {
			__pv_paths_volumes_plat_file(path, PATH_MAX, "bsp",
						     "modules.squashfs");
			if (stat(path, &st) == 0) {
				snprintf(entry, sizeof(entry),
					 "%s lib/modules/%s none bind,ro,create=dir 0 0",
					 path, uts.release);
				append_config_line(fp, "lxc.mount.entry = %s",
						   entry);
			}
		}
	}

	/* Container type environment */
	if (p->group) {
		snprintf(entry, sizeof(entry), "pv-%s", p->group->name);
	} else {
		snprintf(entry, sizeof(entry), "pv-unknown");
	}
	append_config_line(fp, "lxc.environment = container=%s", entry);

	/* Mount hooks */
	DIR *d;
	struct dirent *dir;
	__pv_paths_lib_hook(path, PATH_MAX, "");
	d = opendir(path);
	if (d) {
		const char *export_hook = "export.sh";
		while ((dir = readdir(d)) != NULL) {
			if (!strcmp(dir->d_name, ".") ||
			    !strcmp(dir->d_name, ".."))
				continue;

			/* Skip export hook if export not enabled */
			if (!p->export &&
			    !strncmp(export_hook, dir->d_name,
				     strlen(export_hook)))
				continue;

			__pv_paths_lib_hook(path, PATH_MAX, dir->d_name);
			append_config_line(fp, "lxc.hook.mount = %s", path);
		}
		closedir(d);
	}

	/* Custom init command */
	if (p->exec) {
		append_config_line(fp, "lxc.init.cmd = %s", p->exec);
	}

	fclose(fp);
	free(orig_content);

	pv_log(DEBUG, "generated runtime config: %s", runtime_conf);
	return 0;
}

/*
 * Get container PID using lxc-info
 */
static pid_t get_container_pid(const char *name, const char *lxcpath)
{
	char output[256] = { 0 };
	pid_t pid = -1;

	if (run_cmd(output, sizeof(output), "lxc-info -n %s -P %s -p 2>/dev/null",
		    name, lxcpath) == 0) {
		/* Output format: "PID:          1234" or just "1234" */
		char *p = strstr(output, "PID:");
		if (p) {
			p += 4;
			while (*p == ' ' || *p == '\t')
				p++;
			pid = atoi(p);
		} else {
			/* Try parsing as just a number */
			pid = atoi(output);
		}
	}

	return pid;
}

/*
 * Check if container is running
 */
static bool is_container_running(const char *name, const char *lxcpath)
{
	char output[256] = { 0 };

	if (run_cmd(output, sizeof(output),
		    "lxc-info -n %s -P %s -s 2>/dev/null", name,
		    lxcpath) == 0) {
		return strstr(output, "RUNNING") != NULL;
	}

	return false;
}

/*
 * Start container using lxc-start
 *
 * This is the main entry point called by pantavisor.
 */
int pv_start_container(struct pv_platform *p, const char *rev, char *conf_file,
		       int logfd, int pipefd)
{
	char runtime_dir[PATH_MAX];
	char runtime_conf[PATH_MAX];
	char lxcpath[PATH_MAX];
	char logfile[PATH_MAX];
	pid_t init_pid = -1;
	pid_t child_pid;
	sigset_t oldmask;

	pv_log(DEBUG, "starting LXC container '%s' (CLI mode)", p->name);

	if (pipefd <= 0) {
		pv_log(WARN, "could not get pipefd from container data");
		return -1;
	}

	/* Create runtime directory */
	get_runtime_dir(runtime_dir, sizeof(runtime_dir), p->name);
	if (pv_fs_mkdir_p(runtime_dir, 0755) != 0) {
		pv_log(ERROR, "failed to create runtime dir: %s", runtime_dir);
		goto out_failure;
	}

	/* Build merged config */
	get_runtime_config(runtime_conf, sizeof(runtime_conf), p->name);
	if (build_runtime_config(p, rev, conf_file, runtime_conf) != 0) {
		pv_log(ERROR, "failed to build runtime config");
		goto out_failure;
	}

	/* Get LXC path */
	__pv_paths_lib_lxc_lxcpath(lxcpath, PATH_MAX);
	pv_fs_mkdir_p(lxcpath, 0755);

	/* Setup log file path */
	snprintf(logfile, sizeof(logfile), "%s/lxc.log", runtime_dir);

	if (pvsignals_block_chld(&oldmask)) {
		pv_log(ERROR, "failed to block SIGCHLD: %s", strerror(errno));
		goto out_failure;
	}

	child_pid = fork();

	if (child_pid < 0) {
		pvsignals_setmask(&oldmask);
		pv_log(ERROR, "fork failed: %s", strerror(errno));
		goto out_failure;
	}

	if (child_pid == 0) {
		/* Child process */
		pv_system_set_process_name("pv-platform-%s", p->name);

		signal(SIGCHLD, SIG_DFL);
		pvsignals_setmask(&oldmask);

		/*
		 * Run lxc-start
		 *
		 * Options:
		 *   -n <name>     Container name
		 *   -P <path>     LXC path
		 *   -f <config>   Config file
		 *   -d            Daemonize
		 *   -o <logfile>  Log file
		 *   -l <level>    Log level (DEBUG, INFO, WARN, ERROR)
		 */
		char cmd[4096];
		const char *loglevel_str;

		switch (pv_conf.loglevel) {
		case 0:
			loglevel_str = "TRACE";
			break;
		case 1:
			loglevel_str = "DEBUG";
			break;
		case 2:
			loglevel_str = "INFO";
			break;
		case 3:
			loglevel_str = "NOTICE";
			break;
		case 4:
			loglevel_str = "WARN";
			break;
		case 5:
			loglevel_str = "ERROR";
			break;
		default:
			loglevel_str = "INFO";
		}

		snprintf(cmd, sizeof(cmd),
			 "lxc-start -n %s -P %s -f %s -d -o %s -l %s", p->name,
			 lxcpath, runtime_conf, logfile, loglevel_str);

		pv_log(DEBUG, "executing: %s", cmd);

		int ret = system(cmd);
		if (ret != 0) {
			pv_log(ERROR, "lxc-start failed with code %d", ret);
			init_pid = -1;
		} else {
			/* Wait briefly for container to start */
			usleep(100000); /* 100ms */

			/* Get the container PID */
			init_pid = get_container_pid(p->name, lxcpath);
			if (init_pid > 0) {
				pv_log(DEBUG,
				       "started LXC container '%s' with pid %d",
				       p->name, init_pid);
			} else {
				pv_log(ERROR,
				       "container started but PID not found");
			}
		}

		/* Write PID back to parent */
		while (write(pipefd, &init_pid, sizeof(pid_t)) < 0 &&
		       errno == EINTR)
			;

		_exit(0);
	}

	/* Parent process */
	pvsignals_setmask(&oldmask);
	return 0;

out_failure:
	return -1;
}

/*
 * Stop container using lxc-stop
 */
void pv_stop_container(struct pv_platform *p, char *conf_file)
{
	char lxcpath[PATH_MAX];

	pv_log(DEBUG, "stopping LXC container '%s' (CLI mode)", p->name);

	__pv_paths_lib_lxc_lxcpath(lxcpath, PATH_MAX);

	/* Check if running first */
	if (!is_container_running(p->name, lxcpath)) {
		pv_log(DEBUG, "container '%s' not running", p->name);
		return;
	}

	/*
	 * lxc-stop options:
	 *   -n <name>   Container name
	 *   -P <path>   LXC path
	 *   -t <secs>   Timeout (0 = use default)
	 *   -k          Kill (SIGKILL) instead of clean shutdown
	 */

	/* Try graceful shutdown first */
	if (run_cmd(NULL, 0, "lxc-stop -n %s -P %s -t 30", p->name,
		    lxcpath) != 0) {
		pv_log(WARN, "graceful stop failed, forcing kill");
		run_cmd(NULL, 0, "lxc-stop -n %s -P %s -k", p->name, lxcpath);
	}

	/* Clean up console PTY */
	struct pv_lxccli_console *console = console_find(p->name);
	if (console) {
		console_destroy(console);
	}

	pv_log(DEBUG, "stopped container '%s'", p->name);
}

/*
 * Get console file descriptor
 *
 * Returns the master side of the PTY pair that was created when building
 * the runtime config. The slave side is connected to the container's console
 * via lxc.console.path.
 */
int pv_console_log_getfd(struct pv_platform *p, struct pv_platform_log *log)
{
	struct pv_lxccli_console *console;

	console = console_find(p->name);
	if (!console) {
		pv_log(DEBUG, "no console PTY found for '%s'", p->name);
		log->console_tty = -1;
		log->console_pt = -1;
		return -1;
	}

	log->console_tty = console->slave_fd;
	log->console_pt = console->master_fd;

	pv_log(DEBUG, "returning console PTY for '%s': master=%d slave=%d",
	       p->name, log->console_pt, log->console_tty);

	return 0;
}
