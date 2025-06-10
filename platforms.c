/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <linux/limits.h>

#include <sched.h>

#include "platforms.h"
#include "paths.h"
#include "wdt.h"
#include "drivers.h"
#include "pvlogger.h"
#include "init.h"
#include "state.h"
#include "parser/parser.h"
#include "logserver/logserver.h"
#include "utils/list.h"
#include "utils/json.h"
#include "utils/str.h"
#include "utils/fs.h"
#include "utils/pvsignals.h"
#include "utils/tsh.h"
#include "utils/system.h"

#define MODULE_NAME "platforms"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define PV_PLATFORM_LXC_LOG "lxc/lxc.log"
#define PV_PLATFORM_LXC_CONSOLE_LOG "lxc/console.log"

static const char *syslog[][2] = { { "file", "/var/log/syslog" },
				   { "truncate", "true" },
				   { "maxsize", "2097152" },
				   { "name", NULL },
				   { NULL, NULL }

};

static const char *messages[][2] = { { "file", "/var/log/messages" },
				     { "truncate", "true" },
				     { "maxsize", "2097152" },
				     { "name", NULL },
				     { NULL, NULL } };
static struct pv_logger_config plat_logger_config_syslog = {
	.static_pair = syslog,
	.pair = NULL,
};

static struct pv_logger_config plat_logger_config_messages = {
	.static_pair = messages,
	.pair = NULL,
};

struct pv_cont_ctrl {
	char *type;
	void (*set_loglevel)(int loglevel);
	void (*set_capture)(bool capture);
	int (*start)(struct pv_platform *p, const char *rev, char *conf_file,
		     int logfd, int pipefd);
	void (*stop)(struct pv_platform *p, char *conf_file);
	int (*get_console_fd)(struct pv_platform *p,
			      struct pv_platform_log *log);
};

enum {
	PV_CONT_LXC,
	PV_CONT_RUNC,
	//	PV_CONT_DOCKER,
	PV_CONT_MAX
};

struct pv_cont_ctrl cont_ctrl[PV_CONT_MAX] = {
	{ "lxc", NULL, NULL, NULL, NULL, NULL },
	{ "runc", NULL, NULL, NULL, NULL, NULL },
	//	{ "docker", start_docker_platform, stop_docker_platform }
};

const char *pv_platform_status_string(plat_status_t status)
{
	switch (status) {
	case PLAT_NONE:
		return "NONE";
	case PLAT_INSTALLED:
		return "INSTALLED";
	case PLAT_MOUNTED:
		return "MOUNTED";
	case PLAT_BLOCKED:
		return "BLOCKED";
	case PLAT_STARTING:
		return "STARTING";
	case PLAT_STARTED:
		return "STARTED";
	case PLAT_READY:
		return "READY";
	case PLAT_STOPPING:
		return "STOPPING";
	case PLAT_STOPPED:
		return "STOPPED";
	default:
		return "UNKNOWN";
	}

	return "UNKNOWN";
}

static void pv_platform_log_timer_status(struct pv_platform *p)
{
	struct timer_state tstate = timer_current_state(&p->timer_status_goal);
	if (pv_platform_check_goal(p) == PLAT_GOAL_ACHIEVED) {
		if (!tstate.fin) {
			pv_log(INFO,
			       "platform '%s' reached its status goal; took %d secs; %d secs till timeout (of %d)",
			       p->name,
			       p->group->default_status_goal_timeout -
				       tstate.sec,
			       tstate.sec,
			       p->group->default_status_goal_timeout)
		} else {
			pv_log(INFO,
			       "platform '%s' reached its status goal; took %d secs; %d secs over timeout (of %d)",
			       p->name,
			       p->group->default_status_goal_timeout +
				       tstate.sec,
			       tstate.sec,
			       p->group->default_status_goal_timeout);
		}
	}
}

static void pv_platform_set_status(struct pv_platform *p, plat_status_t status)
{
	if (p->status.current == status)
		return;

	p->status.current = status;
	pv_log(INFO, "platform '%s' status is now %s", p->name,
	       pv_platform_status_string(status));
	pv_platform_log_timer_status(p);

	pv_group_eval_status(p->group);
}

struct pv_platform *pv_platform_add(struct pv_state *s, char *name)
{
	struct pv_platform *p = calloc(1, sizeof(struct pv_platform));

	if (p) {
		p->name = strdup(name);
		p->init_pid = -1;
		p->automodfw = true;
		p->log.console_tty = -1;
		p->log.console_pt = -1;
		p->log.lxc_pipe[0] = -1;
		p->log.lxc_pipe[1] = -1;
		p->status.current = PLAT_NONE;
		p->status.goal = PLAT_NONE;
		p->roles = PLAT_ROLE_MGMT;
		p->restart_policy = RESTART_NONE;
		p->updated = false;
		p->state = s;
		p->export = false;
		p->pipefd[0] = -1;
		p->pipefd[1] = -1;
		p->pipefd_listener.fd = -1;
		p->pipefd_listener.ev = NULL;
		dl_list_init(&p->drivers);
		dl_list_init(&p->logger_list);
		dl_list_init(&p->logger_configs);
		dl_list_init(&p->list);
		dl_list_add_tail(&s->platforms, &p->list);
	}

	return p;
}

static void pv_platform_empty_logger_list(struct pv_platform *p)
{
	int num_loggers = 0;
	struct pv_log_info *l, *tmp;
	struct dl_list *logger_list = &p->logger_list;

	dl_list_for_each_safe(l, tmp, logger_list, struct pv_log_info, next)
	{
		pv_log(DEBUG, "removing logger %s", l->name);
		dl_list_del(&l->next);
		pv_log_info_free(l);
		num_loggers++;
	}

	pv_log(INFO, "removed %d loggers", num_loggers);
}

static void pv_platform_empty_logger_configs(struct pv_platform *p)
{
	int num_logger_configs = 0;
	struct pv_logger_config *l, *tmp;
	struct dl_list *logger_configs = &p->logger_configs;

	dl_list_for_each_safe(l, tmp, logger_configs, struct pv_logger_config,
			      item_list)
	{
		dl_list_del(&l->item_list);
		pv_logger_config_free(l);
		num_logger_configs++;
	}

	pv_log(INFO, "removed %d logger configs", num_logger_configs);
}

void pv_platform_free(struct pv_platform *p)
{
	char **c;
	struct pv_platform_driver *d, *tmp;

	if (p->name)
		free(p->name);
	if (p->type)
		free(p->type);

	c = p->configs;
	if (c) {
		while (*c) {
			free(*c);
			c++;
		}
		free(p->configs);
	}

	dl_list_for_each_safe(d, tmp, &p->drivers, struct pv_platform_driver,
			      list)
	{
		free(d->match);
		free(d);
	}

	dl_list_empty(&p->drivers);

	if (p->exec)
		free(p->exec);

	pv_platform_empty_logger_list(p);
	pv_platform_empty_logger_configs(p);

	free(p);
}

void pv_platform_add_driver(struct pv_platform *p, plat_driver_t type,
			    char *value)
{
	struct pv_platform_driver *d =
		calloc(1, sizeof(struct pv_platform_driver));

	if (d) {
		d->type = type;
		d->match = strdup(value);
		dl_list_init(&d->list);
		dl_list_add_tail(&p->drivers, &d->list);
	}
}

static const char *pv_platforms_role_str(roles_mask_t role)
{
	switch (role) {
	case PLAT_ROLE_MGMT:
		return "mgmt";
	default:
		return "unknown";
	}

	return "unknown";
}

const char *pv_platforms_restart_policy_str(restart_policy_t policy)
{
	switch (policy) {
	case RESTART_SYSTEM:
		return "system";
	case RESTART_CONTAINER:
		return "container";
	default:
		return "unknown";
	}

	return "unknown";
}

void pv_platform_add_json(struct pv_json_ser *js, struct pv_platform *p)
{
	char *group = NULL;
	const char *status = pv_platform_status_string(p->status.current);
	const char *status_goal = pv_platform_status_string(p->status.goal);
	int i;

	if (p->group)
		group = p->group->name;

	pv_json_ser_object(js);
	{
		pv_json_ser_key(js, "name");
		pv_json_ser_string(js, p->name);
		pv_json_ser_key(js, "group");
		pv_json_ser_string(js, group);
		pv_json_ser_key(js, "status");
		pv_json_ser_string(js, status);
		pv_json_ser_key(js, "status_goal");
		pv_json_ser_string(js, status_goal);
		pv_json_ser_key(js, "restart_policy");
		pv_json_ser_string(
			js, pv_platforms_restart_policy_str(p->restart_policy));
		pv_json_ser_key(js, "roles");
		pv_json_ser_array(js);
		{
			if (!p->roles)
				goto close_roles;

			if (p->roles >= PLAT_ROLE_SIZE) {
				pv_json_ser_string(js, "unknown");
				goto close_roles;
			}

			for (i = 0; i < PLAT_ROLE_SIZE; i++) {
				if (pv_platform_has_role(p, i))
					pv_json_ser_string(
						js, pv_platforms_role_str(i));
			}
		close_roles:
			pv_json_ser_array_pop(js);
		}

		pv_json_ser_object_pop(js);
	}
}

void pv_platforms_empty(struct pv_state *s)
{
	int num_plats = 0;
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = &s->platforms;

	dl_list_for_each_safe(p, tmp, platforms, struct pv_platform, list)
	{
		pv_log(DEBUG, "removing platform %s", p->name);
		dl_list_del(&p->list);
		pv_platform_free(p);
		num_plats++;
	}

	pv_log(INFO, "removed %d platforms", num_plats);
}

void pv_platforms_remove_not_installed(struct pv_state *s)
{
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = &s->platforms;

	dl_list_for_each_safe(p, tmp, platforms, struct pv_platform, list)
	{
		if (p->status.current != PLAT_NONE)
			continue;

		dl_list_del(&p->list);
		pv_platform_free(p);
	}
}

static struct pv_cont_ctrl *_pv_platforms_get_ctrl(char *type)
{
	int i;

	for (i = 0; i < PV_CONT_MAX; i++)
		if (strcmp(cont_ctrl[i].type, type) == 0)
			return &cont_ctrl[i];

	return NULL;
}

static int load_pv_plugin(struct pv_cont_ctrl *c)
{
	char path[PATH_MAX];
	void *lib;

	pv_paths_lib_plugin(path, PATH_MAX, c->type);
	lib = dlopen(path, RTLD_NOW);
	if (!lib) {
		pv_log(ERROR, "unable to load %s: %s", path, dlerror());
		return 0;
	}

	pv_log(DEBUG, "loaded %s @%p", path, lib);

	// static engines have to define c->start and c->end
	if (c->start == NULL)
		c->start = dlsym(lib, "pv_start_container");

	if (c->stop == NULL)
		c->stop = dlsym(lib, "pv_stop_container");

	if (c->start == NULL || c->stop == NULL)
		return 0;

	if (!c->set_loglevel) {
		c->set_loglevel = dlsym(lib, "pv_set_pv_conf_loglevel_fn");
		if (!c->set_loglevel)
			pv_log(WARN,
			       "could not locate symbol 'pv_set_pv_conf_loglevel_fn");
	}

	if (!c->set_capture) {
		c->set_capture = dlsym(lib, "pv_set_pv_conf_capture_fn");
		if (!c->set_capture)
			pv_log(WARN,
			       "could not locate symbol 'pv_set_pv_conf_capture_fn'");
	}

	if (c->get_console_fd == NULL) {
		c->get_console_fd = dlsym(lib, "pv_console_log_getfd");
		if (c->get_console_fd == NULL)
			pv_log(WARN,
			       "could not locate symbol 'pv_console_log_getfd'");
	}

	void (*__pv_get_instance)(void *) = dlsym(lib, "pv_set_pv_instance_fn");
	if (__pv_get_instance)
		__pv_get_instance(pv_get_instance);
	else
		pv_log(ERROR, "Couldn't locate symbol pv_set_pv_instance_fn");

	void (*__pv_paths)(void *, void *, void *, void *, void *, void *,
			   void *, void *, void *, void *, void *, void *,
			   void *, void *) = dlsym(lib, "pv_set_pv_paths_fn");
	if (__pv_paths)
		__pv_paths(__log, pv_paths_pv_file, pv_paths_pv_log,
			   pv_paths_pv_log_plat, pv_paths_pv_log_file,
			   pv_paths_pv_usrmeta_key,
			   pv_paths_pv_usrmeta_plat_key,
			   pv_paths_pv_devmeta_key,
			   pv_paths_pv_devmeta_plat_key, pv_paths_lib_hook,
			   pv_paths_volumes_plat_file, pv_paths_configs_file,
			   pv_paths_lib_lxc_rootfs_mount,
			   pv_paths_lib_lxc_lxcpath);
	else
		pv_log(ERROR, "Couldn't locate symbol pv_set_pv_paths_fn");

	return 1;
}

// this should construct the table dynamically
int pv_platforms_init_ctrl()
{
	int loaded = 0;

	// try to find plugins for all registered types
	for (int i = 0; i < PV_CONT_MAX; i++)
		loaded += load_pv_plugin(&cont_ctrl[i]);

	pv_log(DEBUG, "loaded %d plugins correctly", loaded);

	return loaded;
}

static int __start_pvlogger_for_platform(struct pv_platform *platform,
					 struct pv_log_info *log_info)
{
	/*
	 * fork, and set the mount namespace for
	 * pv_logger.
	 * */
	pid_t container_pid = platform->init_pid;
	sigset_t oldmask;

	if (!log_info)
		return -1;

	if (pvsignals_block_chld(&oldmask)) {
		pv_log(ERROR, "failed to block SIGCHLD for starting pvlogger: ",
		       strerror(errno));
		return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (!pid) {
		pv_system_set_process_name("pv-logger-%s", platform->name);
		char namespace[64];
		int ns_fd = -1;

		signal(SIGCHLD, SIG_DFL);
		if (pvsignals_setmask(&oldmask)) {
			pv_log(ERROR,
			       "Unable to reset sigmask in pvloggger child: %s",
			       strerror(errno));
			_exit(-1);
		}
		/*
		 * lxc_logger will not move
		 * into mount namespace of platform.
		 * */
		if (!log_info->islxc) {
			SNPRINTF_WTRUNC(namespace, sizeof(namespace),
					"/proc/%d/ns/mnt", container_pid);
			pv_log(DEBUG, "Opening file %s", namespace);
			ns_fd = open(namespace, 0);
			if (ns_fd < 0) {
				pv_log(ERROR,
				       "Unable to open namespace file: %s",
				       strerror(errno));
				_exit(-1);
			}
			if (setns(ns_fd, 0)) {
				perror("Unable to set Mount namespace\n");
				_exit(-1);
			}
		}
		start_pvlogger(log_info, (log_info->islxc ? log_info->name :
							    platform->name));
		_exit(0);
	}
	log_info->logger_pid = pid;
	if (pvsignals_setmask(&oldmask)) {
		pv_log(ERROR, "Unable to reset sigmask in pvloggger parent %s",
		       strerror(errno));
		return -1;
	}
	return pid;
}

static void pv_setup_platform_log(struct pv_log_info *info,
				  struct pv_logger_config *logger_config)
{
	const char *logfile = NULL;

	if (!info)
		return;
	/*
	 * We would read the config data from platform,
	 * and set this up.
	 * */
	logfile = pv_log_get_config_item(
		logger_config,
		"file"); /*Defaults to /var/log/messages in pvlogger*/
	info->logfile = (logfile ? strdup(logfile) : NULL);
}

static struct pv_log_info *
pv_add_platform_logger(struct pv_platform *platform,
		       struct pv_logger_config *logger_config)
{
	struct pv_log_info *log_info = NULL;

	log_info = pv_new_log(false, logger_config, platform->name);
	if (log_info) {
		pv_setup_platform_log(log_info, logger_config);
		dl_list_init(&log_info->next);
		dl_list_add(&platform->logger_list, &log_info->next);
	}
	return log_info;
}

void pv_platforms_add_all_loggers(struct pv_state *s)
{
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = NULL, *configs = NULL;
	struct pv_logger_config *item_config, *tmp_config;
	bool plat_needs_default_logger;

	platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp, platforms, struct pv_platform, list)
	{
		configs = &p->logger_configs;
		plat_needs_default_logger = true;
		/*
		 * First add all the loggers in the list.
		 * This will probably in a loop on the platform
		 * config data.
		 * */
		dl_list_for_each_safe(item_config, tmp_config, configs,
				      struct pv_logger_config, item_list)
		{
			if (pv_add_platform_logger(p, item_config))
				plat_needs_default_logger = false;
			/*
			 * logger config item isn't required anymore
			 * */
			dl_list_del(&item_config->item_list);
			pv_logger_config_free(item_config);
		}

		if (plat_needs_default_logger) {
			char logger_name[64] = { 0 };
			/*
			 * The name key is at index 3
			 * */
			SNPRINTF_WTRUNC(logger_name, sizeof(logger_name),
					"%s-pvlogger-syslog", p->name);
			plat_logger_config_syslog.static_pair[3][1] =
				logger_name;
			pv_add_platform_logger(p, &plat_logger_config_syslog);
			SNPRINTF_WTRUNC(logger_name, sizeof(logger_name),
					"%s-pvlogger-messages", p->name);
			plat_logger_config_messages.static_pair[3][1] =
				logger_name;
			pv_add_platform_logger(p, &plat_logger_config_messages);
		}
	}
}

static int start_pvlogger_for_platform(struct pv_platform *platform)
{
	struct pv_log_info *log_info = NULL, *tmp;
	struct dl_list *loggers = &platform->logger_list;
	pid_t logger_pid = -1;

	/*
	 * This includes the ones for lxc.
	 * */
	dl_list_for_each_safe(log_info, tmp, loggers, struct pv_log_info, next)
	{
		log_info->platform = platform;
		logger_pid = __start_pvlogger_for_platform(platform, log_info);
		/*
		 * So this logger didn't succeeded,
		 * */
		if (logger_pid < 0) {
			pv_log(WARN, "Logger %s was not started",
			       (log_info->name ? log_info->name : "pvlogger"));
		} else {
			pv_log(DEBUG,
			       "started pv_logger for platform %s"
			       "(name=%s) with pid = %d",
			       platform->name, log_info->name, logger_pid);
		}
	}

	return logger_pid;
}

void pv_platform_unload_drivers(struct pv_platform *p, char *namematch,
				plat_driver_t typematch)
{
	struct pv_platform_driver *d, *tmp;

	if (dl_list_empty(&p->drivers)) {
		pv_log(DEBUG, "no drivers for platform '%s'", p->name);
		return;
	}

	dl_list_for_each_safe(d, tmp, &p->drivers, struct pv_platform_driver,
			      list)
	{
		if (!(d->type & typematch))
			continue;

		// namematch NULL means: all drivers of platform
		if (namematch && strcmp(namematch, d->match))
			continue;

		if (pv_drivers_state(d->match) == MOD_LOADED) {
			int n = pv_drivers_unload(d->match);
			pv_log(DEBUG, "unloaded %d drivers", n);
		}
	}
}

int pv_platform_load_drivers(struct pv_platform *p, char *namematch,
			     plat_driver_t typematch)
{
	struct pv_platform_driver *d, *tmp;

	if (dl_list_empty(&p->drivers)) {
		pv_log(DEBUG, "no drivers for platform '%s'", p->name);
		return 0;
	}

	dl_list_for_each_safe(d, tmp, &p->drivers, struct pv_platform_driver,
			      list)
	{
		if (!(d->type & typematch))
			continue;

		// namematch NULL means: all drivers of platform
		if (namematch && strcmp(namematch, d->match))
			continue;

		switch (d->type) {
		case DRIVER_REQUIRED:
			if (pv_drivers_load(d->match) < 0) {
				pv_log(ERROR,
				       "unable to load required driver '%s'",
				       d->match);
				return -1;
			}
			break;
		case DRIVER_OPTIONAL:
			pv_drivers_load(d->match);
			break;
		case DRIVER_MANUAL:
			if (pv_drivers_load(d->match) < 0) {
				pv_log(ERROR,
				       "unable to load manual driver '%s'",
				       d->match);
				return -1;
			}
			break;
		}
		pv_log(DEBUG, "plat=%s type=%d, loaded=%s, match='%s'", p->name,
		       d->type, pv_drivers_state_str(d->match), d->match);
	}

	return 0;
}

static void pv_platform_remove_config_overlay(const char *plat)
{
	char path[PATH_MAX];
	pv_paths_configs_file(path, PATH_MAX, plat);
	pv_fs_path_remove(path, true);
}

static int pv_platform_setup_config_overlay(const char *plat)
{
	struct pantavisor *pv = pv_get_instance();
	char srcpath[PATH_MAX];
	pv_paths_storage_trail_config_file(srcpath, PATH_MAX, pv->state->rev,
					   plat);
	if (!pv_fs_path_exist(srcpath))
		return 0;

	char dstpath[PATH_MAX];
	pv_paths_configs_file(dstpath, PATH_MAX, plat);
	pv_fs_path_remove(dstpath, true);
	pv_fs_mkdir_p(dstpath, 0755);

	char cmd[PATH_MAX];
	SNPRINTF_WTRUNC(cmd, sizeof(cmd), "/bin/cp -aL %s/* %s/", srcpath,
			dstpath);
	pv_log(INFO, "setting up '%s' config overlay: %s", plat, cmd);

	system(cmd);

	return 0;
}

static void pv_platform_subscribe_fd(int fd, const char *plat, const char *src)
{
	if (fd < 0) {
		pv_log(WARN, "could not subscribe %s:%s (fd = %d)", plat, src,
		       fd);
		return;
	}
	if (pv_logserver_subscribe_fd(fd, plat, src, INFO) < 0)
		pv_log(WARN,
		       "could not subscribe %s:%s (fd = %d) logserver return < 0",
		       plat, src, fd);
	pv_log(DEBUG, "platform subscribed %s:%s (fd = %d)", plat, src, fd);
}

static void _read_platform_pipefd_cb(int fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_read_platform_pipefd_cb);

	const struct pv_cont_ctrl *ctrl;
	struct pv_platform *p = (struct pv_platform *)arg;
	if (!p) {
		pv_log(WARN, "could not get platform struct from event arg");
		return;
	}

	while (read(p->pipefd[0], &p->init_pid, sizeof(pid_t)) < 0 &&
	       errno == EINTR)
		;
	close(p->pipefd[0]);
	p->pipefd[0] = -1;
	pv_event_socket_ignore(&p->pipefd_listener);

	if (p->init_pid <= 0) {
		pv_log(WARN, "could not start platform '%s'", p->name);
		pv_platform_set_status(p, PLAT_STOPPED);
		return;
	}

	if (pv_config_get_bool(PV_LOG_LOGGERS))
		if (start_pvlogger_for_platform(p) < 0)
			pv_log(ERROR,
			       "could not start pv_logger for platform %s",
			       p->name);

	ctrl = _pv_platforms_get_ctrl(p->type);
	if (ctrl->get_console_fd(p, &p->log) == -1) {
		pv_log(WARN, "could not get a valid console log fd for %s",
		       p->name);
	} else {
		pv_platform_subscribe_fd(p->log.console_pt, p->name,
					 PV_PLATFORM_LXC_CONSOLE_LOG);
	}

	pv_log(DEBUG, "started platform '%s' with pid %d", p->name,
	       p->init_pid);
	pv_platform_set_status(p, PLAT_STARTED);
}

int pv_platform_start(struct pv_platform *p)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_state *s = pv->state;
	char path[PATH_MAX], filename[PATH_MAX];
	const struct pv_cont_ctrl *ctrl;
	char **c = p->configs;

	if (!p->group) {
		pv_log(ERROR, "platform '%s' does not belong to any group",
		       p->name);
		return -1;
	}

	pv_wdt_kick();

	if (pv_platform_setup_config_overlay(p->name)) {
		pv_log(ERROR, "platform '%s' config overlay failed", p->name);
		return -1;
	}

	if (pv_state_spec(pv->state) == SPEC_SYSTEM1)
		SNPRINTF_WTRUNC(filename, PATH_MAX, "%s/%s", p->name, *c);
	else
		SNPRINTF_WTRUNC(filename, PATH_MAX, "%s", *c);

	if (pipe2(p->log.lxc_pipe, O_NONBLOCK | O_CLOEXEC) != 0) {
		pv_log(WARN, "could not create the log pipe: %s(%d)",
		       strerror(errno), errno);
	} else {
		pv_platform_subscribe_fd(p->log.lxc_pipe[0], p->name,
					 PV_PLATFORM_LXC_LOG);
	}

	ctrl = _pv_platforms_get_ctrl(p->type);

	// update plugin with current config
	ctrl->set_loglevel(pv_config_get_int(PV_LXC_LOG_LEVEL));
	ctrl->set_capture(pv_config_get_bool(PV_LOG_CAPTURE));

	pv_paths_storage_trail_file(path, PATH_MAX, s->rev, filename);

	// to be able to receive pid from lxc fork
	if (pipe2(p->pipefd, O_NONBLOCK | O_CLOEXEC)) {
		pv_log(ERROR, "could not create pipe for platform '%s",
		       p->name);
		pv_platform_stop(p);
		return -1;
	}
	pv_event_socket_listen(&p->pipefd_listener, p->pipefd[0],
			       _read_platform_pipefd_cb, (void *)p);

	pv_log(DEBUG, "setting status goal timer of %d secs for platform '%s'",
	       p->group->default_status_goal_timeout, p->name);
	timer_start(&p->timer_status_goal,
		    p->group->default_status_goal_timeout, 0, RELATIV_TIMER);

	pv_log(DEBUG, "starting platform '%s'", p->name);

	if (ctrl->start(p, s->rev, path, p->log.lxc_pipe[1], p->pipefd[1])) {
		pv_log(ERROR, "could not start platform '%s'", p->name);
		return -1;
	}
	close(p->pipefd[1]);
	p->pipefd[1] = -1;

	pv_platform_set_status(p, PLAT_STARTING);

	return 0;
}

static int pv_platform_stop_loggers(struct pv_platform *p)
{
	int num_loggers = 0, exited = 0;
	struct pv_log_info *l, *tmp;
	struct dl_list *logger_list = &p->logger_list;

	pv_log(DEBUG, "stopping loggers attached to platform %s", p->name);

	// send SIGTERM to logger attached to platform
	dl_list_for_each_safe(l, tmp, logger_list, struct pv_log_info, next)
	{
		if (l->logger_pid > 0) {
			kill(l->logger_pid, SIGTERM);
			pv_log(DEBUG, "sent SIGTERM to logger '%s' with pid %d",
			       l->name, l->logger_pid);
			num_loggers++;
		}
	}

	// check logger processes have ended
	for (int i = 0; i < 5; i++) {
		exited = 0;
		logger_list = &p->logger_list;
		dl_list_for_each_safe(l, tmp, logger_list, struct pv_log_info,
				      next)
		{
			if (kill(l->logger_pid, 0))
				exited++;
		}
		if (exited == num_loggers)
			break;
		sleep(1);
	}

	// force kill logger processes
	if (exited != num_loggers) {
		logger_list = &p->logger_list;
		dl_list_for_each_safe(l, tmp, logger_list, struct pv_log_info,
				      next)
		{
			if (!kill(l->logger_pid, 0)) {
				kill(l->logger_pid, SIGKILL);
				pv_log(WARN,
				       "sent SIGKILL to logger '%s' with pid %d",
				       l->name, l->logger_pid);
			}
		}
	}

	return num_loggers;
}

static void pv_platform_close_logs_fd(struct pv_platform *p)
{
	pv_logserver_unsubscribe_fd(p->name, PV_PLATFORM_LXC_CONSOLE_LOG);
	pv_logserver_unsubscribe_fd(p->name, PV_PLATFORM_LXC_LOG);

	if (p->log.console_tty > -1) {
		close(p->log.console_tty);
		p->log.console_tty = -1;
	}

	if (p->log.console_pt > -1) {
		close(p->log.console_pt);
		p->log.console_pt = -1;
	}

	if (p->log.lxc_pipe[0] > -1) {
		close(p->log.lxc_pipe[0]);
		p->log.lxc_pipe[0] = -1;
	}

	if (p->log.lxc_pipe[1] > -1) {
		close(p->log.lxc_pipe[1]);
		p->log.lxc_pipe[1] = -1;
	}
}

int pv_platform_stop(struct pv_platform *p)
{
	const struct pv_cont_ctrl *ctrl;

	pv_platform_stop_loggers(p);
	pv_platform_close_logs_fd(p);

	if (p->pipefd[0] > -1)
		close(p->pipefd[0]);
	if (p->pipefd[1] > -1)
		close(p->pipefd[1]);
	pv_event_socket_ignore(&p->pipefd_listener);

	if (p->init_pid <= 0)
		return -1;

	pv_log(DEBUG, "leniently stopping platform '%s'", p->name);
	ctrl = _pv_platforms_get_ctrl(p->type);
	ctrl->stop(p, NULL);
	pv_platform_set_status(p, PLAT_STOPPING);

	pv_platform_remove_config_overlay(p->name);

	return 0;
}

void pv_platform_force_stop(struct pv_platform *p)
{
	pv_log(DEBUG, "force stopping platform '%s'", p->name);
	pv_platform_set_status(p, PLAT_STOPPED);
	pv_cgroup_destroy(p->name);

	if (p->init_pid <= 0)
		return;

	kill(p->init_pid, SIGKILL);
}

void pv_platform_set_installed(struct pv_platform *p)
{
	pv_platform_set_status(p, PLAT_INSTALLED);
}

void pv_platform_set_mounted(struct pv_platform *p)
{
	pv_platform_set_status(p, PLAT_MOUNTED);
}

void pv_platform_set_blocked(struct pv_platform *p)
{
	pv_platform_set_status(p, PLAT_BLOCKED);
}

int pv_platform_set_ready(struct pv_platform *p)
{
	if (p->status.goal != PLAT_READY)
		return -1;

	pv_platform_set_status(p, PLAT_READY);
	return 0;
}

void pv_platform_set_updated(struct pv_platform *p)
{
	p->updated = true;
}

bool pv_platform_check_running(struct pv_platform *p)
{
	bool running;

	if (p->init_pid <= 0)
		return false;

	running = !kill(p->init_pid, 0);
	if (!running) {
		if ((p->status.current != PLAT_STOPPED) &&
		    (p->status.current != PLAT_STARTING)) {
			pv_platform_set_status(p, PLAT_STOPPED);
		}
	}

	return running;
}

bool pv_platform_is_installed(struct pv_platform *p)
{
	return (p->status.current == PLAT_INSTALLED);
}

bool pv_platform_is_blocked(struct pv_platform *p)
{
	return (p->status.current == PLAT_BLOCKED);
}

bool pv_platform_is_starting(struct pv_platform *p)
{
	return (p->status.current == PLAT_STARTING);
}

bool pv_platform_is_started(struct pv_platform *p)
{
	return (p->status.current == PLAT_STARTED);
}

bool pv_platform_is_ready(struct pv_platform *p)
{
	return (p->status.current == PLAT_READY);
}

bool pv_platform_is_stopping(struct pv_platform *p)
{
	return (p->status.current == PLAT_STOPPING);
}

bool pv_platform_is_stopped(struct pv_platform *p)
{
	return (p->status.current == PLAT_STOPPED);
}

bool pv_platform_is_updated(struct pv_platform *p)
{
	return p->updated;
}

void pv_platform_set_status_goal(struct pv_platform *p, plat_status_t goal)
{
	p->status.goal = goal;
}

plat_goal_state_t pv_platform_check_goal(struct pv_platform *p)
{
	if (p->status.current == p->status.goal)
		return PLAT_GOAL_ACHIEVED;
	else if (p->status.current < PLAT_STARTING)
		return PLAT_GOAL_UNACHIEVED;
	else if (p->status.current >= p->status.goal)
		return PLAT_GOAL_NONE;

	struct timer_state tstate = timer_current_state(&p->timer_status_goal);
	if (tstate.fin) {
		pv_log(ERROR,
		       "platform '%s' status goal timed out after waiting for more than %d secs",
		       p->name, p->group->default_status_goal_timeout);
		return PLAT_GOAL_TIMEDOUT;
	}

	return PLAT_GOAL_UNACHIEVED;
}

void pv_platform_set_restart_policy(struct pv_platform *p,
				    restart_policy_t policy)
{
	p->restart_policy = policy;
}

void pv_platform_set_role(struct pv_platform *p, roles_mask_t role)
{
	p->roles |= role;
}

void pv_platform_unset_role(struct pv_platform *p, roles_mask_t role)
{
	p->roles &= ~role;
}

bool pv_platform_has_role(struct pv_platform *p, roles_mask_t role)
{
	return p->roles & role;
}

static int pv_platforms_early_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;

	pv = pv_get_instance();
	// init platform controllers
	if (!pv_platforms_init_ctrl()) {
		pv_log(ERROR, "unable to load any container runtime plugin");
		return -1;
	}
	return 0;
}

struct pv_init pv_init_platform = {
	.init_fn = pv_platforms_early_init,
	.flags = 0,
};

struct pv_platform_ref *pv_platform_ref_new(struct pv_platform *p)
{
	struct pv_platform_ref *pr;

	pr = calloc(1, sizeof(struct pv_platform_ref));
	if (pr) {
		pr->ref = p;
	}

	return pr;
}

void pv_platform_ref_free(struct pv_platform_ref *pr)
{
	free(pr);
}
