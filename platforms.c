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

#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>

#define MODULE_NAME             "platforms"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "platforms.h"

struct pv_cont_ctrl {
	char *type;
	void* (*start)(char *name, char *conf_file, void *data);
	void* (*stop)(char *name, char *conf_file, void *data);
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
	struct pv_platform *this = calloc(1, sizeof(struct pv_platform));
	struct pv_platform *add = s->platforms;

	while (add && add->next) {
		add = add->next;
	}

	if (!add) {
		s->platforms = add = this;
	} else {
		add->next = this;
	}

	this->name = name;
	this->done = false;

	return this;
}

struct pv_platform* pv_platform_get_by_name(struct pv_state *s, char *name)
{
	struct pv_platform *p = s->platforms;

	if (name == NULL)
		return NULL;

	while (p) {
		if (!strcmp(name, p->name))
			return p;
		p = p->next;
	}

	return NULL;
}

struct pv_platform* pv_platform_get_by_data(struct pv_state *s, void *data)
{
	struct pv_platform *p = s->platforms;

	if (data == NULL)
		return NULL;

	while (p) {
		if (p->data == data)
			return p;
		p = p->next;
	}

	return NULL;
}

void pv_platforms_remove_all(struct pv_state *s)
{
	struct pv_platform *p = s->platforms;
	struct pv_platform *t;
	char **c;

	while (p) {
		if (p->name)
			free(p->name);
		if (p->type)
			free(p->type);
		if (p->exec)
			free(p->exec);

		c = p->configs;
		while (*c) {
			free(*c);
			c++;
		}
		t = p->next;
		free(p);
		p = t;
	}

	s->platforms = NULL;
}

void pv_platforms_remove_not_done(struct pv_state *s)
{
	struct pv_platform *p = s->platforms;
	struct pv_platform *prev = p;
	char **c;

	while (p) {
		if (p->done) {
			prev = p;
			p = p->next;
			continue;
		}
		if (p->name)
			free(p->name);
		if (p->type)
			free(p->type);
		if (p->exec)
			free(p->exec);

		c = p->configs;
		while (c && *c) {
			free(*c);
			c++;
		}
		if (s->platforms == p)
			s->platforms = p->next;
		else
			prev->next = p->next;
		free(p);
		break;
	}
}

void pv_platforms_remove_by_data(struct pv_state *s, void *data)
{
	struct pv_platform *p = s->platforms;
	struct pv_platform *prev = p;
	char **c;

	while (p) {
		if (p->data != data) {
			prev = p;
			p = p->next;
			continue;
		}
		if (p->name)
			free(p->name);
		if (p->type)
			free(p->type);
		if (p->exec)
			free(p->exec);

		c = p->configs;
		while (*c) {
			free(*c);
			c++;
		}
		if (s->platforms == p)
			s->platforms = p->next;
		else
			prev->next = p->next;
		free(p);
		break;
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

	sprintf(lib_path, "/lib/pv_%s.so", c->type);

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

// Iterate list of platforms from state
// Do setup (chdir to config dir, etc)
// Setup logging, channels, etc
// start_by_type (fetch start function (i.e. start_lxc_platform)
// store per-platform (void*) type object to underlying impl (lxc, docker)
int pv_platforms_start_all(struct pantavisor *pv)
{
	int num_plats = 0;
	struct pv_state *s = pv->state;
	struct pv_platform *p = s->platforms;

	if (!p) {
		pv_log(ERROR, "no platforms available");
		return -1;
	}

	while (p) {
		pid_t pid = -1;
		char conf_path[PATH_MAX];
		const struct pv_cont_ctrl *ctrl;
		void *data;
		char **c = p->configs;

		sprintf(conf_path, "%s/trails/%d/%s",
			pv->config->storage.mntpoint, s->rev, *c);

		// Get type controller
		ctrl = _pv_platforms_get_ctrl(p->type);

		// Start the platform
		data = ctrl->start(p->name, conf_path, (void *) &pid);

		if (!data) {
			pv_log(ERROR, "error starting platform: \"%s\"",
				p->name);
			return -1;
		}

		pv_log(INFO, "started platform: \"%s\" (data=%p), init_pid=%d",
			p->name, data, pid);

		// FIXME: arbitrary delay between plats
		sleep(7);

		p->data = data;
		p->init_pid = pid;
		p->running = true;
		num_plats++;

		p = p->next;
	}

	return num_plats;
}

// Iterate all underlying impl objects, stop one by one
// Cannot fail, force stop and/or kill if necessary
int pv_platforms_stop_all(struct pantavisor *pv)
{
	int num_plats = 0;
	struct pv_state *s = pv->state;
	struct pv_platform *p = s->platforms;
	const struct pv_cont_ctrl *ctrl;

	while (p) {
		ctrl = _pv_platforms_get_ctrl(p->type);
		ctrl->stop(NULL, NULL, p->data);
		p->running = false;
		pv_log(INFO, "stopped platform '%s'", p->name);
		num_plats++;
		p = p->next;
	}

	pv_platforms_remove_all(s);

	pv_log(INFO, "stopped %d platforms", num_plats);

	return num_plats;
}

int pv_platforms_check_exited(struct pantavisor *pv)
{
	struct pv_state *s = pv->state;
	struct pv_platform *p = s->platforms;

	while (p) {
		if (!kill(p->init_pid, 0)) {
			p = p->next;
			continue;
		}
		pv_log(WARN, "platform '%s' exited", p->name);
		return -1;
	}

	return 0;
}
