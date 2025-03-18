/*
 * Copyright (c) 2017-2023 Pantacor Ltd.
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
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <lxc/lxccontainer.h>
#include <lxc/pv_export.h>
#include <limits.h>
#include <unistd.h>
#include <stdbool.h>

#include "utils/fs.h"
#include "pv_lxc.h"
#include "utils/list.h"
#include "pvlogger.h"
#include "state.h"
#include "platforms.h"
#include "paths.h"
#include "utils/pvsignals.h"
#include "utils/system.h"

#define PV_VLOG __vlog
#include "utils/tsh.h"

#define MODULE_NAME "pv_lxc"
#define pv_log(level, msg, ...) __vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pv_lxc_conf {
	int loglevel;
	bool capture;
};

static struct pv_lxc_conf pv_conf = { .loglevel = 2, .capture = true };

static struct lxc_log pv_lxc_log = { .level = "DEBUG",
				     .prefix = "init",
				     .name = NULL,
				     .lxcpath = NULL,
				     .file = NULL,
				     .quiet = false };

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

static void pv_free_lxc_log(struct pv_log_info *pv_log_i)
{
	free_member(pv_log_i, name);
	free_member(pv_log_i, logfile);
}

static int pv_setup_lxc_log(struct pv_log_info *pv_log_i, const char *plat_name,
			    struct lxc_container *c, const char *key)
{
	char logfile[PATH_MAX] = { 0 };
	char default_prefix[PATH_MAX] = { 0 };

	c->get_config_item(c, key, logfile, PATH_MAX);
	/*
	 * Anything under the revision directory will
	 * automatically be picked up by pusher service.
	 * So no need to create a pvlogger process if the
	 * log files are created in the revision directory.
	 */
	__pv_paths_pv_log(default_prefix, PATH_MAX,
			  __pv_get_instance()->state->rev);
	/*
	 * If lxc.log.file or lxc.console.logfile isn't set or
	 * it has the same location from where PH helper can post
	 * it then we don't require a pvlogger in such a case.
	 */
	if (!strlen(logfile) ||
	    strncmp(default_prefix, logfile, strlen(default_prefix)) == 0)
		return -1;

	pv_log_i->logfile = strdup(logfile);
	/*
	 * This is the default truncate size.
	 * Caller can change this before logging starts.
	 */
	pv_log_i->truncate_size = (2 * 1024 * 1024);
	return 0;
}

static void pv_setup_lxc_container_cgroup(struct lxc_container *c)
{
	// only for cgroup unified
	if (__pv_get_instance()->cgroupv != CGROUP_UNIFIED)
		return;

	// XXX: this might change with LXC 5.0, as we might be able to support the original lxc.conf

	char value[PATH_MAX];

	// remove all ilegacy cgroup allow and deny config
	while (c->get_config_item(c, "lxc.cgroup.devices.allow", value,
				  PATH_MAX) > 0) {
		c->set_config_item(c, "lxc.cgroup.devices.allow", NULL);
	}
	while (c->get_config_item(c, "lxc.cgroup.devices.deny", value,
				  PATH_MAX) > 0) {
		c->set_config_item(c, "lxc.cgroup.devices.deny", NULL);
	}

	// substitute it with cgroup2 allow a
	c->set_config_item(c, "lxc.cgroup2.devices.allow", "a");
}

static char *inschr(char *path, int n, char chr, char *seed)
{
	int sl = strlen(seed);
	int pl = strlen(path);
	// does not fit in?
	if (pl + sl + 2 >= n)
		return NULL;

	char *i = strchr(path, chr);
	if (!i)
		return NULL;
	char *tn = strdup(i);
	// we count the new : here
	int tnl = strlen(tn);

	// move last part to the new place
	memcpy(i + sl + 1, tn, tnl);
	free(tn);

	// insert seed
	memcpy(i + 1, seed, sl);

	// mark the end, after length of original+seed+':'
	*(path + pl + sl + 1) = 0;

	return path;
}

static void pv_setup_lxc_container(struct lxc_container *c,
				   struct pv_platform *p, const char *rev)
{
	int fd, ret;
	struct utsname uts;
	struct stat st;
	char tmp_cmd[] = "/tmp/cmdline-XXXXXX";
	char path[PATH_MAX], entry[PATH_MAX * 2], seed[PATH_MAX];
	char log_level[32];
	c->want_daemonize(c, true);
	c->want_close_all_fds(c, true);
	__pv_paths_lib_lxc_rootfs_mount(path, PATH_MAX);
	c->set_config_item(c, "lxc.rootfs.mount", path);
	if (!c->get_config_item(c, "lxc.uts.name", NULL, 0)) {
		c->set_config_item(c, "lxc.uts.name", p->name);
	}
	pv_log(DEBUG, "checking lxc.rootfs.mount for auto creation 1 %s",
	       p->name);

	__pv_paths_configs_file(seed, PATH_MAX, p->name);

	// setting lxc.rootfs.path strips the bdev_type from the value
	// so we have to add it here first
	c->get_config_item(c, "lxc.rootfs.bdev_type", path, PATH_MAX);
	ret = strlen(path);
	path[ret] = ':';
	path[ret + 1] = 0;
	c->get_config_item(c, "lxc.rootfs.path", path + strlen(path),
			   PATH_MAX - strlen(path) - 1);

	ret = stat(seed, &st);
	if (!ret && !inschr(path, PATH_MAX, ':', seed)) {
		pv_log(WARN,
		       "failed to setup configoverlay in lxc.rootfs.path %s + %s",
		       path, seed);
	} else if (!ret) {
		pv_log(WARN, "setup config overlay in lxc.rootfs.path %s + %s",
		       path, seed);
		c->set_config_item(c, "lxc.rootfs.path", path);
	} else {
		pv_log(DEBUG,
		       "config overlay does not exist; not changing rootfs.path %s",
		       path);
	}

	if (c->get_config_item(c, "lxc.log.level", NULL, 0)) {
		snprintf(log_level, sizeof(log_level), "%d", pv_conf.loglevel);
		c->set_config_item(c, "lxc.log.level", log_level);
	}
	pv_setup_lxc_container_cgroup(c);
	// role specific lxc config
	if (p->roles & PLAT_ROLE_MGMT) {
		__pv_paths_pv_file(path, PATH_MAX, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,create=dir 0 0", path,
			 PLATFORM_PV_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);

		__pv_paths_pv_log(path, PATH_MAX, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,create=dir 0 0", path,
			 PLATFORM_LOGS_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);

		__pv_paths_pv_usrmeta_key(path, PATH_MAX, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,create=dir 0 0", path,
			 PLATFORM_USER_META_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);

		__pv_paths_pv_devmeta_key(path, PATH_MAX, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,create=dir 0 0", path,
			 PLATFORM_DEVICE_META_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);
	} else {
		__pv_paths_pv_file(path, PATH_MAX, LOGCTRL_FNAME);
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,rw,create=file 0 0", path,
			 PLATFORM_LOG_CTRL_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);

		__pv_paths_pv_file(path, PATH_MAX, PVCTRL_FNAME);
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,rw,create=file 0 0", path,
			 PLATFORM_PVCTRL_SOCKET_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);

		__pv_paths_pv_log_plat(path, PATH_MAX, rev, p->name);
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,origin=mkdir,create=dir 0 0", path,
			 PLATFORM_LOGS_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);

		__pv_paths_pv_usrmeta_plat_key(path, PATH_MAX, p->name, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,origin=mkdir,create=dir 0 0", path,
			 PLATFORM_USER_META_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);

		__pv_paths_pv_devmeta_plat_key(path, PATH_MAX, p->name, "");
		snprintf(entry, sizeof(entry),
			 "%s %s none bind,ro,origin=mkdir,create=dir 0 0", path,
			 PLATFORM_DEVICE_META_PATH + 1);
		c->set_config_item(c, "lxc.mount.entry", entry);
	}
	if (p->automodfw && stat("/lib/firmware", &st) == 0)
		c->set_config_item(c, "lxc.mount.entry",
				   "/lib/firmware"
				   " lib/firmware none bind,ro,create=dir"
				   " 0 0");
	ret = uname(&uts);
	// FIXME: Implement modules volume and use that instead
	if (p->automodfw && !ret) {
		__pv_paths_volumes_plat_file(path, PATH_MAX, "bsp",
					     "modules.squashfs");
		if (stat(path, &st) == 0) {
			sprintf(entry,
				"%s "
				"lib/modules/%s "
				"none bind,ro,create=dir 0 0",
				path, uts.release);
			c->set_config_item(c, "lxc.mount.entry", entry);
		}
	}
	// Strip consoles from kernel cmdline
	mkstemp(tmp_cmd);
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd >= 0) {
		char *buf = calloc(1024, sizeof(char));
		char *new = calloc(1024, sizeof(char));
		read(fd, buf, 1024);
		char *tok = strtok(buf, " ");
		while (tok) {
			if (strncmp("console=", tok, 8) == 0) {
				tok = strtok(NULL, " ");
				continue;
			}
			strcat(new, tok);
			strcat(new, " ");
			tok = strtok(NULL, " ");
		}
		close(fd);
		fd = open(tmp_cmd, O_CREAT | O_RDWR | O_SYNC, 0644);
		if (fd >= 0) {
			write(fd, new, strlen(new));
			close(fd);
		}
		free(new);
		free(buf);
	}
	// override container=lxc environment of pid 1
	if (p->group)
		sprintf(entry, "pv-%s", p->group->name);
	else
		sprintf(entry, "pv-unknown");
	c->set_container_type(c, entry);

	/*
	 * Enable mount hooks
	 */
	DIR *d;
	struct dirent *dir;
	__pv_paths_lib_hook(path, PATH_MAX, "");
	d = opendir(path);
	if (!d)
		return;

	const char *export_hook = "export.sh";

	while ((dir = readdir(d)) != NULL) {
		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
			continue;

		if (!p->export &&
		    !strncmp(export_hook, dir->d_name, strlen(export_hook)))
			continue;

		__pv_paths_lib_hook(path, PATH_MAX, dir->d_name);
		c->set_config_item(c, "lxc.hook.mount", path);
	}
	closedir(d);
}

static void pv_setup_default_log(struct pv_platform *p, struct lxc_container *c,
				 const char *logger_key)
{
	struct pv_logger_config *item_config;
	struct dl_list *config_head = &p->logger_configs;
	bool found = false;

	/*
	 * Check for logger_key as console and if terminal
	 * was requested in the lxc.conf.
	 * We don't require to add the lxc console config otherwise
	 * that would also start logger on non-existent file resulting
	 * in unnecessary logger messages.
	 */
	if (strncmp("console", logger_key, strlen("console")) == 0) {
		char *console_path = calloc(PATH_MAX, sizeof(char));
		bool do_nothing = false;

		if (console_path) {
			c->get_config_item(c, "lxc.console.path", console_path,
					   PATH_MAX);
			if (strlen(console_path) &&
			    strcmp("none", console_path) == 0) {
				do_nothing = true;
			}
			free(console_path);
			if (do_nothing)
				return;
		}
	}
	dl_list_for_each(item_config, config_head, struct pv_logger_config,
			 item_list)
	{
		int i = 0;
		found = false;
		while (item_config->pair[i][0]) {
			if (!strncmp(item_config->pair[i][0], logger_key,
				     strlen(logger_key))) {
				found = true;
				break;
			}
			i++;
		}
		if (found)
			break;
	}
	/*
	 * Add a new logger_config item
	 */
	if (!found) {
		struct pv_logger_config *new_config =
			(struct pv_logger_config *)calloc(1,
							  sizeof(*new_config));
		const int config_count = 2;
		int j = 0;

		if (!new_config)
			return;
		new_config->pair = (const char ***)calloc(2, sizeof(char *));
		if (!new_config->pair)
			goto out_config;

		for (j = 0; j < config_count; j++) {
			new_config->pair[j] =
				(const char **)calloc(2, sizeof(char *));
			if (!new_config->pair[j])
				goto out_pair;
		}

		new_config->pair[0][0] = strdup(logger_key);
		new_config->pair[0][1] = strdup("enable");
		dl_list_add(&p->logger_configs, &new_config->item_list);
		return;
	out_pair:
		while (j) {
			j--;
			free(new_config->pair[j]);
		}
	out_config:
		free(new_config);
	}
}

void *pv_start_container(struct pv_platform *p, const char *rev,
			 char *conf_file, int logfd, void *data)
{
	int err;
	struct lxc_container *c;
	char *dname;
	char path[PATH_MAX];
	int pipefd[2];
	pid_t child_pid = -1;
	sigset_t oldmask;
	// Go to LXC config dir for platform
	dname = strdup(conf_file);
	dname = dirname(dname);
	chdir(dname);
	free(dname);
	__pv_paths_lib_lxc_lxcpath(path, PATH_MAX);
	pv_fs_mkdir_p(path, 0755);

	pv_log(DEBUG, "starting LXC container '%s'", p->name);

	c = lxc_container_new(p->name, path);
	if (!c) {
		pv_log(DEBUG, "starting LXC container failed '%s'", p->name);
		goto out_failure;
	}
	c->clear_config(c);
	/*
	 * For returning back the
	 * container_pid to pv parent
	 * process.
	 */
	if (pipe(pipefd))
		goto out_failure;

	if (pvsignals_block_chld(&oldmask)) {
		pv_log(ERROR,
		       "failed to block SIGCHLD for starting pantavisor: ",
		       strerror(errno));
		goto out_failure;
	}

	child_pid = fork();

	if (child_pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		if (pvsignals_setmask(&oldmask)) {
			pv_log(ERROR,
			       "Unable to reset sigmask of pantavisor fork in failed fork: %s",
			       strerror(errno));
		}
		goto out_failure;
	}

	else if (child_pid) { /*Parent*/
		if (pvsignals_setmask(&oldmask)) {
			pv_log(ERROR,
			       "Unable to reset sigmask of pantavisor fork in parent: %s",
			       strerror(errno));
			goto out_failure;
		}

		pid_t container_pid = -1;
		/*Parent would read*/
		close(pipefd[1]);
		while (read(pipefd[0], &container_pid, sizeof(container_pid)) <
			       0 &&
		       errno == EINTR)
			;

		if (container_pid <= 0)
			goto out_failure;

		*((pid_t *)data) = container_pid;
		close(pipefd[0]);
	} else { /* Child process */

		close(pipefd[0]);
		*((pid_t *)data) = -1;

		signal(SIGCHLD, SIG_DFL);
		if (pvsignals_setmask(&oldmask)) {
			*((pid_t *)data) = -2;
			pv_log(ERROR,
			       "Unable to reset sigmask of pantavisor fork in child %s",
			       strerror(errno));
			goto out_container_init;
		}

		/*
		 * We need this for getting the revision..
		 */
		*((pid_t *)data) = -3;
		if (!__pv_get_instance)
			goto out_container_init;

		if (pv_conf.capture) {
			lxc_log_init(&pv_lxc_log);
			lxc_log_set_alternative_output(logfd);
		}
		__pv_paths_lib_lxc_lxcpath(path, PATH_MAX);

		c = lxc_container_new(p->name, path);

		*((pid_t *)data) = -4;
		if (!c) {
			pv_log(ERROR, "failed to create container struct");
			goto out_container_init;
		}
		c->clear_config(c);
		/*
		 * Load config later which allows us to
		 * override the log file configured by default.
		 */
		*((pid_t *)data) = -5;
		if (!c->load_config(c, conf_file)) {
			lxc_container_put(c);
			pv_log(DEBUG, "load config failed %s", c->name);
			goto out_container_init;
		}

		pv_setup_lxc_container(c, p, rev);
		if (p->exec)
			c->set_config_item(c, "lxc.init.cmd", p->exec);

		c->save_config(c, NULL);

		err = c->start(c, 0, NULL) ? 0 : 1;

		chdir("/");
		if (err && (c->error_num != 1)) {
			lxc_container_put(c);
			c = NULL;
		}

		*((pid_t *)data) = -6;
		if (c)
			*((pid_t *)data) = c->init_pid(c);
	out_container_init:
		while (write(pipefd[1], data, sizeof(pid_t)) < 0 &&
		       errno == EINTR)
			;
		_exit(0);
	}
	/*
	 * Parent loads the config after container is setup.
	 * This is just required to stop container and get
	 * any config items required in the parent.
	 */
	if (!c->load_config(c, conf_file))
		goto out_failure;

	pv_setup_lxc_container(c, p, rev); /*Do we need this?*/

	if (!pv_conf.capture)
		goto out_success;

out_success:
	chdir("/");
	return (void *)c;
out_failure:
	chdir("/");
	if (c) {
		c->shutdown(c, 0);
		lxc_container_put(c);
	}
	return NULL;
}

// cannot fail if data is valid
void *pv_stop_container(struct pv_platform *p, char *conf_file, void *data)
{
	bool s;
	struct lxc_container *c = (struct lxc_container *)data;

	pv_log(DEBUG, "stopping LXC container '%s'", p->name);

	if (!data)
		return NULL;

	s = c->shutdown(c, 0);

	// unref
	lxc_container_put(c);

	return NULL;
}

int pv_console_log_getfd(struct pv_platform_log *log, void *data)
{
	if (!data)
		return -1;

	struct lxc_container *c = (struct lxc_container *)data;

	int tty = 0;
	log->console_tty = c->console_getfd(c, &tty, &log->console_pt);
	int flags = fcntl(log->console_pt, F_GETFL, 0);
	fcntl(log->console_pt, F_SETFL, flags | O_NONBLOCK);

	return (log->console_pt < 0 || log->console_tty < 0) ? -1 : 0;
}