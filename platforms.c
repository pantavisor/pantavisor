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
#include "init.h"
#include "state.h"
#include "utils/list.h"
#include "utils/fs.h"
#include "utils/str.h"

#define MODULE_NAME             "platforms"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

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
		p->mgmt = true;
		p->updated = false;
		dl_list_init(&p->condition_refs);
		dl_list_init(&p->logger_list);
		dl_list_init(&p->logger_configs);
		dl_list_init(&p->list);
		dl_list_add_tail(&s->platforms, &p->list);
	}

	return p;
}

static void pv_platform_empty_condition_refs(struct pv_platform *p)
{
	int num_conditions = 0;
	struct pv_condition_ref *cr, *tmp;
	struct dl_list *condition_refs = &p->condition_refs;

	// Iterate over all condition references from platforms
	dl_list_for_each_safe(cr, tmp, condition_refs,
			struct pv_condition_ref, list) {
		dl_list_del(&cr->list);
		pv_condition_ref_free(cr);
		num_conditions++;
	}

	pv_log(INFO, "removed %g condition references", num_conditions);
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

	pv_platform_empty_condition_refs(p);
	pv_platform_empty_logger_list(p);
	pv_platform_empty_logger_configs(p);

	free(p);
}

void pv_platform_add_condition(struct pv_platform *p, struct pv_condition *c)
{
	struct pv_condition_ref *cr;

	pv_log(DEBUG, "adding condition reference %s to platform", c->key);

	cr = pv_condition_ref_new(c);
	if (cr) {
		dl_list_init(&cr->list);
		dl_list_add_tail(&p->condition_refs, &cr->list);
	}
}

static const char* pv_platform_status_string(plat_status_t status)
{
	switch(status) {
		case PLAT_NONE: return "NONE";
		case PLAT_DATA: return "DATA";
		case PLAT_READY: return "READY";
		case PLAT_BLOCKED: return "BLOCKED";
		case PLAT_STARTING: return "STARTING";
		case PLAT_STARTED: return "STARTED";
		case PLAT_STOPPING: return "STOPPING";
		case PLAT_STOPPED: return "STOPPED";
		default: return "UNKNOWN";
	}

	return "UNKNOWN";
}

char* pv_platform_get_json(struct pv_platform *p)
{
	int len, line_len;
	char *json, *group = NULL, *line;
	const char *status = pv_platform_status_string(p->status);
	struct pv_condition_ref *cr, *tmp;

	if (p->group)
		group = p->group->name;

	len = strlen(p->name) +
		strlen(group) +
		strlen(status) +
		strlen("{\"name\":\"\",\"group\":\"\",\"status\":\"\",\"conditions\":[");
	json = calloc(1, (len + 1) * sizeof(char*));
	snprintf(json, len + 1, "{\"name\":\"%s\",\"group\":\"%s\",\"status\":\"%s\",\"conditions\":[",
		p->name, group, status);

	if (!p->group || dl_list_empty(&p->group->condition_refs))
		goto plats;

	dl_list_for_each_safe(cr, tmp, &p->group->condition_refs,
			struct pv_condition_ref, list) {
		if (!cr->ref)
			continue;

		line = pv_condition_get_json(cr->ref);
		line_len = strlen(line) + 1;
		json = realloc(json, len + line_len + 1);
		snprintf(&json[len], line_len + 1, "%s,", line);
		len += line_len;
		free(line);
	}

	// remove ,
	len--;

plats:
	if (dl_list_empty(&p->condition_refs))
		goto close;

	// recover ,
	len++;

	dl_list_for_each_safe(cr, tmp, &p->condition_refs,
			struct pv_condition_ref, list) {
		if (!cr->ref)
			continue;

		line = pv_condition_get_json(cr->ref);
		line_len = strlen(line) + 1;
		json = realloc(json, len + line_len + 1);
		snprintf(&json[len], line_len + 1, "%s,", line);
		len += line_len;
		free(line);
	}

	// remove ,
	len--;

close:
	// close json
	len += 3;
	json = realloc(json, len);
	json[len-3] = ']';
	json[len-2] = '}';
	json[len-1] = '\0';

	return json;
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
		if (p->status != PLAT_NONE)
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

int pv_platform_start(struct pv_platform *p)
{
	struct pantavisor *pv = pv_get_instance();
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

	pv_log(DEBUG, "starting platform \'%s\' with pid %d", p->name, pid);

	p->data = data;
	p->init_pid = pid;

	if (pid <= 0)
		return -1;

	p->status = PLAT_STARTING;

	if (pv_config_get_log_loggers())
		if (start_pvlogger_for_platform(p) < 0)
			pv_log(ERROR, "Could not start pv_logger for platform %s", p->name);

	return 0;
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

int pv_platform_stop(struct pv_platform *p)
{
	const struct pv_cont_ctrl *ctrl;

	pv_platform_stop_loggers(p);

	if (p->init_pid <= 0)
		return -1;

	pv_log(DEBUG, "leniently stopping platform '%s'", p->name);
	ctrl = _pv_platforms_get_ctrl(p->type);
	ctrl->stop(p, NULL, p->data);
	p->data = NULL;
	p->status = PLAT_STOPPING;

	return 0;
}

void pv_platform_force_stop(struct pv_platform *p)
{
	pv_log(DEBUG, "force stopping platform '%s'", p->name);
	kill(p->init_pid, SIGKILL);
	p->status = PLAT_STOPPED;
}

void pv_platform_set_ready(struct pv_platform *p)
{
	p->status = PLAT_READY;

	if (p->group &&
		pv_str_matches(p->group->name, strlen(p->group->name), "data", strlen("data")))
		p->status = PLAT_DATA;
}

void pv_platform_set_blocked(struct pv_platform *p)
{
	p->status = PLAT_BLOCKED;
}

void pv_platform_set_updated(struct pv_platform *p)
{
	p->updated = true;
}

int pv_platform_check_running(struct pv_platform *p)
{
	bool running;

	running = !kill(p->init_pid, 0);
	if (running) {
		if ((p->status != PLAT_STARTED) && (p->status != PLAT_STOPPING)) {
			pv_log(DEBUG, "platform %s started", p->name);
			p->status = PLAT_STARTED;
		}
	} else {
		if ((p->status != PLAT_STOPPED) && (p->status != PLAT_STARTING)) {
			pv_log(DEBUG, "platform %s stopped", p->name);
			p->status = PLAT_STOPPED;
		}
	}

	return running;
}

bool pv_platform_check_conditions(struct pv_platform *p)
{
	struct pv_condition_ref *cr, *tmp;

	if (p->group || dl_list_empty(&p->group->condition_refs))
		goto plat;

	dl_list_for_each_safe(cr, tmp, &p->group->condition_refs,
			struct pv_condition_ref, list) {
		if (cr->ref && !pv_condition_check(cr->ref))
			return false;
	}

plat:
	if (dl_list_empty(&p->condition_refs))
		goto out;

	dl_list_for_each_safe(cr, tmp, &p->condition_refs,
			struct pv_condition_ref, list) {
		if (cr->ref && !pv_condition_check(cr->ref))
			return false;
	}

out:
	return true;
}

bool pv_platform_is_ready(struct pv_platform *p)
{
	return (p->status == PLAT_READY);
}

bool pv_platform_is_blocked(struct pv_platform *p)
{
	return (p->status == PLAT_BLOCKED);
}

bool pv_platform_is_starting(struct pv_platform *p)
{
	return (p->status == PLAT_STARTING);
}

bool pv_platform_is_started(struct pv_platform *p)
{
	return (p->status == PLAT_STARTED);
}

bool pv_platform_is_stopping(struct pv_platform *p)
{
	return (p->status == PLAT_STOPPING);
}

bool pv_platform_is_stopped(struct pv_platform *p)
{
	return (p->status == PLAT_STOPPED);
}

bool pv_platform_is_updated(struct pv_platform *p)
{
	return p->updated;
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
