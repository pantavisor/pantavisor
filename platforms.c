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

#ifndef _GNU_SOURCE
int setns(int nsfd, int nstype);
#else
#include <sched.h>
#endif

#include "parser/parser.h"
#include "wdt.h"
#include "platforms.h"
#include "pvlogger.h"
#include "utils/list.h"
#include "utils/fs.h"
#include "utils/str.h"
#include "init.h"
#include "state.h"

#define MODULE_NAME             "platforms"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

const int MAX_RUNLEVEL = 3;

static const char *syslog[][2] = {
		{"file", "/var/log/syslog"},
		{"truncate", "true"},
		{"maxsize", "2097152"},
		{"name", NULL},
		{NULL, NULL}

};

static const char *messages[][2] = {
		{"file", "/var/log/messages"},
		{"truncate", "true"},
		{"maxsize", "2097152"},
		{"name", NULL},
		{NULL, NULL}
};
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
	void* (*start)(struct pv_platform *p, const char *rev, char *conf_file, void *data);
	void* (*stop)(struct pv_platform *p, char *conf_file, void *data);
};

enum {
	PV_CONT_LXC,
//	PV_CONT_DOCKER,
	PV_CONT_MAX
};

struct pv_cont_ctrl cont_ctrl[PV_CONT_MAX] = {
	{ "lxc", NULL, NULL },
//	{ "docker", start_docker_platform, stop_docker_platform }
};

struct pv_platform* pv_platform_add(struct pv_state *s, char *name)
{
	struct pv_platform *p = calloc(1, sizeof(struct pv_platform));

	if (p) {
		p->name = strdup(name);
		p->status = PLAT_NONE;
		p->runlevel = -1;
		p->updated = false;
		p->mgmt = true;
		dl_list_init(&p->logger_list);
		dl_list_init(&p->logger_configs);
		dl_list_init(&p->list);
		dl_list_add_tail(&s->platforms, &p->list);
	}

	return p;
}

struct pv_platform* pv_platform_get_by_name(struct pv_state *s, const char *name)
{

	struct pv_platform *p, *tmp;
	struct dl_list *platforms = &s->platforms;

	dl_list_for_each_safe(p, tmp, platforms,
			struct pv_platform, list) {
		if (!strcmp(p->name, name))
			return p;
	}
	return NULL;
}

static void pv_platform_empty_logger_list(struct pv_platform *p)
{
	int num_loggers = 0;
	struct pv_log_info *l, *tmp;
	struct dl_list *logger_list = &p->logger_list;

	dl_list_for_each_safe(l, tmp, logger_list,
		struct pv_log_info, next) {
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

	dl_list_for_each_safe(l, tmp, logger_configs,
		struct pv_logger_config, item_list) {
		dl_list_del(&l->item_list);
		pv_logger_config_free(l);
		num_logger_configs++;
	}

	pv_log(INFO, "removed %d logger configs", num_logger_configs);
}

void pv_platform_free(struct pv_platform *p)
{
	char **c;

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
	}

	if (p->exec)
		free(p->exec);
	if (p->data)
		free(p->data);

	pv_platform_empty_logger_list(p);
	pv_platform_empty_logger_configs(p);

	free(p);
}

void pv_platforms_empty(struct pv_state *s)
{
	int num_plats = 0;
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = &s->platforms;

	dl_list_for_each_safe(p, tmp, platforms,
		struct pv_platform, list) {
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

	dl_list_for_each_safe(p, tmp, platforms,
		struct pv_platform, list) {
		if (p->status == PLAT_INSTALLED)
			continue;

		dl_list_del(&p->list);
		pv_platform_free(p);
	}
}

static struct pv_cont_ctrl* _pv_platforms_get_ctrl(char *type)
{
	int i;

	for (i = 0; i < PV_CONT_MAX; i++)
		if (strcmp(cont_ctrl[i].type, type) == 0)
			return &cont_ctrl[i];

	return NULL;
}

static int load_pv_plugin(struct pv_cont_ctrl *c)
{
	char lib_path[PATH_MAX];
	void *lib;

	SNPRINTF_WTRUNC(lib_path, sizeof (lib_path), "/lib/pv_%s.so", c->type);

	lib = dlopen(lib_path, RTLD_NOW);
	if (!lib) {
		pv_log(ERROR, "unable to load %s: %s", lib_path, dlerror());
		return 0;
	}

	pv_log(DEBUG, "loaded %s @%p", lib_path, lib);

	// static engines have to define c->start and c->end
	if (c->start == NULL)
		c->start = dlsym(lib, "pv_start_container");

	if (c->stop == NULL)
		c->stop = dlsym(lib, "pv_stop_container");

	if (c->start == NULL || c->stop == NULL)
		return 0;

	void (*__pv_new_log)(void*) = dlsym(lib, "pv_set_new_log_fn");
	if (__pv_new_log)
		__pv_new_log(pv_new_log);
	else
		pv_log(ERROR, "Couldn't locate symbol pv_set_new_log_fn");

	void (*__pv_get_instance)(void*) = dlsym(lib, "pv_set_pv_instance_fn");
	if (__pv_get_instance)
		__pv_get_instance(pv_get_instance);
	else
		pv_log(ERROR, "Couldn't locate symbol pv_set_pv_instance_fn");
	return 1;
}

// this should construct the table dynamically
int pv_platforms_init_ctrl(struct pantavisor *pv)
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
	int container_pid = platform->init_pid;

	if (!log_info)
		return -1;

	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (!pid) {
		char namespace [64];
		int ns_fd = -1;
		/*
		 * lxc_logger will not move
		 * into mount namespace of platform.
		 * */
		if (!log_info->islxc) {
			SNPRINTF_WTRUNC(namespace,sizeof(namespace), "/proc/%d/ns/mnt",
					container_pid);
			pv_log(DEBUG, "Opening file %s",namespace);
			ns_fd = open(namespace, 0);
			if (ns_fd < 0) {
				pv_log(ERROR, "Unable to open namespace file: %s", strerror(errno));
				_exit(-1);
			}
			if (setns(ns_fd, 0)) {
				perror("Unable to set Mount namespace\n");
				_exit(-1);
			}
		}
		start_pvlogger(log_info, (log_info->islxc ? log_info->name
				 		: platform->name)
				);
		_exit(0);
	}
	log_info->logger_pid = pid;
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
	logfile = pv_log_get_config_item(logger_config, "file"); /*Defaults to /var/log/messages in pvlogger*/
	info->logfile = (logfile ? strdup(logfile) : NULL);
}

static struct pv_log_info* pv_add_platform_logger(struct pv_platform *platform,
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
	dl_list_for_each_safe(p, tmp, platforms,
		struct pv_platform, list) {
		configs = &p->logger_configs;
		plat_needs_default_logger = true;
		/*
		 * First add all the loggers in the list.
		 * This will probably in a loop on the platform
		 * config data.
		 * */
		dl_list_for_each_safe(item_config, tmp_config, configs,
				struct pv_logger_config, item_list) {
			if (pv_add_platform_logger(p, item_config))
				plat_needs_default_logger = false;
			/*
			 * logger config item isn't required anymore
			 * */
			dl_list_del(&item_config->item_list);
			pv_logger_config_free(item_config);
		}

		if (plat_needs_default_logger) {
			char logger_name[32] = {0};
			/*
			 * The name key is at index 3
			 * */
			SNPRINTF_WTRUNC(logger_name, sizeof(logger_name), "%s-pvlogger-syslog",
					p->name);
			plat_logger_config_syslog.static_pair[3][1] = logger_name;
			pv_add_platform_logger(p, &plat_logger_config_syslog);
			SNPRINTF_WTRUNC(logger_name, sizeof(logger_name), "%s-pvlogger-messages",
					p->name);
			plat_logger_config_messages.static_pair[3][1] = logger_name;
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
	dl_list_for_each_safe(log_info, tmp, loggers,
				struct pv_log_info, next) {
		log_info->platform = platform;
		logger_pid =
			__start_pvlogger_for_platform(platform, log_info);
		/*
		 * So this logger didn't succeeded,
		 * */
		if (logger_pid < 0) {
			pv_log(WARN, "Logger %s was not started",
				(log_info->name ? log_info->name : "pvlogger")
				);
		} else {
			pv_log(DEBUG, "started pv_logger for platform %s"
				"(name=%s) with pid = %d", platform->name,
				log_info->name, logger_pid);
		}
	}

	return logger_pid;
}

static int pv_platforms_start_platform(struct pantavisor *pv, struct pv_platform *p)
{
	struct pv_state *s = pv->state;
	pid_t pid = -1;
	char conf_path[PATH_MAX];
	const struct pv_cont_ctrl *ctrl;
	void *data;
	char **c = p->configs;
	char prefix[PATH_MAX] = { 0 };

	pv_wdt_kick(pv);

	if (pv_state_spec(pv->state) == SPEC_SYSTEM1) {
		SNPRINTF_WTRUNC(prefix, sizeof (prefix), "%s/", p->name);
	}

	SNPRINTF_WTRUNC(conf_path, sizeof (conf_path),
			"%s/trails/%s/%s%s", pv_config_get_storage_mntpoint(), s->rev,
			prefix, *c);

	// Get type controller
	ctrl = _pv_platforms_get_ctrl(p->type);

	// Start the platform
	data = ctrl->start(p, s->rev, conf_path, (void *) &pid);

	if (!data) {
		pv_log(ERROR, "error starting platform: \"%s\"",
			p->name);
		return -1;
	}

	pv_log(DEBUG, "started platform: \"%s\" (data=%p), init_pid=%d",
		p->name, data, pid);

	p->data = data;
	p->init_pid = pid;

	if (pid > 0)
		p->status = PLAT_STARTED;
	else
		return -1;

	return 0;
}

int pv_platforms_start(struct pantavisor *pv, int runlevel)
{
	int num_plats = 0;
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = NULL;

	// Iterate between runlevel plats and lowest priority plats
	for (int i = runlevel; i <= MAX_RUNLEVEL; i++) {
		if (i > RUNLEVEL_DATA) {
			pv_log(DEBUG, "starting platforms with runlevel %d", i);
		} else {
			pv_log(DEBUG, "skipping platforms with runlevel data %d", i);
			continue;
		}
		// Iterate over all plats from state
		platforms = &pv->state->platforms;
		dl_list_for_each_safe(p, tmp, platforms,
				struct pv_platform, list) {
			// Ignore platforms from other runlevels and platforms already started
			if ((p->runlevel != i) || (p->status == PLAT_STARTED))
				continue;

			if (pv_platforms_start_platform(pv, p))
				return -1;

			num_plats++;
		}
	}

	pv_log(INFO, "started %d platforms", num_plats);

	pv_log(DEBUG, "starting all platforms pv loggers");

	platforms = &pv->state->platforms;

	if (!pv_config_get_log_loggers())
		goto out;

	dl_list_for_each_safe(p, tmp, platforms,
		struct pv_platform, list) {
		if (start_pvlogger_for_platform(p) < 0)
			pv_log(ERROR, "Could not start pv_logger for platform %s",p->name);
	}

out:
	return num_plats;
}

static void pv_platforms_force_kill(struct pantavisor *pv, int runlevel)
{
	int num_plats = 0;
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = NULL;

	// Iterate between lowest priority plats and runlevel plats
	for (int i = MAX_RUNLEVEL; i >= runlevel; i--) {
		pv_log(DEBUG, "force killing platforms with runlevel %d", i);
		// Iterate over all plats from state
		platforms = &pv->state->platforms;
		dl_list_for_each_safe(p, tmp, platforms,
				struct pv_platform, list) {
			// Ignore platforms from other runlevels
			if (p->runlevel != i)
				continue;

			// Ignore non updated apps if update runlevel is app
			if ((runlevel == RUNLEVEL_APP) &&
				(p->runlevel == RUNLEVEL_APP) &&
				!p->updated)
				continue;

			if (!kill(p->init_pid, 0)) {
				pv_log(INFO, "sending SIGKILL to unresponsive platform '%s'", p->name);
				kill(p->init_pid, SIGKILL);
				num_plats++;
			}
		}
	}

	if (num_plats)
		pv_log(INFO, "force killed %d platforms", num_plats);
}

static int pv_platform_stop_loggers(struct pv_platform *p)
{
	int num_loggers = 0, exited = 0;
	struct pv_log_info *l, *tmp;
	struct dl_list *logger_list = &p->logger_list;

	pv_log(DEBUG, "stopping loggers attached to platform %s", p->name);

	// send SIGTERM to logger attached to platform
	dl_list_for_each_safe(l, tmp, logger_list,
		struct pv_log_info, next) {
		if (l->logger_pid > 0) {
			kill(l->logger_pid, SIGTERM);
			pv_log(DEBUG, "sent SIGTERM to logger '%s' with pid %d", l->name, l->logger_pid);
			num_loggers++;
		}
	}

	// check logger processes have ended
	for (int i = 0; i < 5; i++) {
		exited = 0;
		logger_list = &p->logger_list;
		dl_list_for_each_safe(l, tmp, logger_list,
			struct pv_log_info, next) {
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
		dl_list_for_each_safe(l, tmp, logger_list,
			struct pv_log_info, next) {
			if (!kill(l->logger_pid, 0)) {
				kill(l->logger_pid, SIGKILL);
				pv_log(WARN, "sent SIGKILL to logger '%s' with pid %d", l->name, l->logger_pid);
			}
		}
	}

	return num_loggers;
}

int pv_platforms_stop(struct pantavisor *pv, int runlevel)
{
	int num_loggers = 0, num_plats = 0, exited = 0;
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = &pv->state->platforms;
	const struct pv_cont_ctrl *ctrl;

	pv_log(DEBUG, "stopping all platforms pv loggers");

	dl_list_for_each_safe(p, tmp, platforms,
		struct pv_platform, list) {
		num_loggers += pv_platform_stop_loggers(p);
	}

	if (num_loggers)
		pv_log(INFO, "stopped %d platform loggers", num_loggers);

	// Iterate between lowest priority plats and runlevel plats
	for (int i = MAX_RUNLEVEL; i >= runlevel; i--) {
		pv_log(DEBUG, "stopping platforms with runlevel %d", i);
		// Iterate over all plats from state
		platforms = &pv->state->platforms;
		dl_list_for_each_safe(p, tmp, platforms,
			struct pv_platform, list) {
			// Start platforms in this runlevel only
			if (p->runlevel != i)
				continue;

			// Ignore non updated apps if update runlevel is app
			if ((runlevel == RUNLEVEL_APP) &&
				(p->runlevel == RUNLEVEL_APP) &&
				!p->updated)
				continue;

			// Stop plats that have been started
			if ((p->status == PLAT_STARTED) && (p->init_pid > 0)) {
				ctrl = _pv_platforms_get_ctrl(p->type);
				ctrl->stop(p, NULL, p->data);
				p->status = PLAT_STOPPED;
				p->data = NULL;
				pv_log(DEBUG, "sent SIGTERM to platform '%s'", p->name);
				num_plats++;
			}
		}
	}

	if (num_plats)
		pv_log(INFO, "leniently stopped %d platforms", num_plats);

	// Check all plats in runlevel and lower priority have been stopped
	for (int i = 0; i < 5; i++) {
		exited = pv_platforms_check_exited(pv, runlevel);
		if (exited == num_plats)
			break;
		pv_log(WARN, "only %d out of %d platforms exited. Sleeping 1 second to check again...", exited, num_plats);
		sleep(1);
	}

	// Kill all plats in runlevel and lower priority
	if (exited != num_plats)
		pv_platforms_force_kill(pv, runlevel);

	return num_plats;
}

int pv_platforms_check_exited(struct pantavisor *pv, int runlevel)
{
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = NULL;
	int exited = 0;

	// Iterate between lowest priority plats and runlevel plats
	for (int i = MAX_RUNLEVEL; i >= runlevel; i--) {
		// Iterate over all plats from state
		platforms = &pv->state->platforms;
		dl_list_for_each_safe(p, tmp, platforms,
	            struct pv_platform, list) {
			// Check platforms in this runlevel only
			if (p->runlevel != i)
				continue;

			// Ignore non updated apps if update runlevel is app
			if ((runlevel == RUNLEVEL_APP) &&
				(p->runlevel == RUNLEVEL_APP) &&
				!p->updated)
				continue;

			if (kill(p->init_pid, 0)) {
				pv_log(DEBUG, "platform exited: %s", p->name);
				exited++;
			}
		}
	}

	return exited;
}

static int pv_platforms_early_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;

	pv = pv_get_instance();
	// init platform controllers
	if (!pv_platforms_init_ctrl(pv)) {
		pv_log(ERROR, "unable to load any container runtime plugin");
		return -1;
	}
	return 0;
}

struct pv_init pv_init_platform = {
	.init_fn = pv_platforms_early_init,
	.flags = 0,
};
