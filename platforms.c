#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "lxc.h"

#define MODULE_NAME             "platforms"
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "platforms.h"

struct sc_cont_ctrl {
	char *type;
	void* (*start)(char *name, char *conf_file, void *data);
	void* (*stop)(char *name, char *conf_file, void *data);
};

enum {
	SC_CONT_LXC,
	SC_CONT_DOCKER,
	SC_CONT_MAX
};

const struct sc_cont_ctrl cont_ctrl[SC_CONT_MAX] = {
	{ "lxc", start_lxc_container, stop_lxc_container },
//	{ "docker", start_docker_platform, stop_docker_platform }
};

struct sc_platform* sc_platform_add(struct sc_state *s, char *name)
{
	struct sc_platform *this = calloc(1, sizeof(struct sc_platform));
	struct sc_platform *add = s->platforms;

	while (add && add->next) {
		add = add->next;
	}

	if (!add) {
		s->platforms = add = this;
	} else {
		add->next = this;
	}

	this->name = name;

	return this;
}

struct sc_platform* sc_platform_get_by_name(struct sc_state *s, char *name)
{
	struct sc_platform *p = s->platforms;

	if (name == NULL)
		return NULL;

	while (p) {
		if (!strcmp(name, p->name))
			return p;
		p = p->next;
	}
	
	return NULL;
}

struct sc_platform* sc_platform_get_by_data(struct sc_state *s, void *data)
{
	struct sc_platform *p = s->platforms;

	if (data == NULL)
		return NULL;

	while (p) {
		if (p->data == data)
			return p;
		p = p->next;
	}
	
	return NULL;
}

void sc_platforms_remove_all(struct sc_state *s)
{
	struct sc_platform *p = s->platforms;
	struct sc_platform *t;
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

void sc_platforms_remove_by_data(struct sc_state *s, void *data)
{
	struct sc_platform *p = s->platforms;
	struct sc_platform *prev = p;
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

static const struct sc_cont_ctrl* _sc_platforms_get_ctrl(char *type)
{
	int i;

	for (i = 0; i < SC_CONT_MAX; i++)
		if (strcmp(cont_ctrl[i].type, type) == 0)
			return &cont_ctrl[i];

	return NULL;
}

// Iterate list of platforms from state
// Do setup (chdir to config dir, etc)
// Setup logging, channels, etc
// start_by_type (fetch start function (i.e. start_lxc_platform)
// store per-platform (void*) type object to underlying impl (lxc, docker)
int sc_platforms_start_all(struct systemc *sc)
{
	int num_plats = 0;
	struct sc_state *s = sc->state;
	struct sc_platform *p = s->platforms;

	if (!p) {
		sc_log(ERROR, "no platforms available");
		return -1;
	}

	while (p) {
		char conf_path[PATH_MAX];
		const struct sc_cont_ctrl *ctrl;
		void *data;
		char **c = p->configs;

		sprintf(conf_path, "%s/trails/%d/%s",
			sc->config->storage.mntpoint, s->rev, *c);

		// Get type controller
		ctrl = _sc_platforms_get_ctrl(p->type);	

		// Start the platform
		data = ctrl->start(p->name, conf_path, NULL);

		if (!data) {
			sc_log(ERROR, "error starting platform: \"%s\"",
				p->name);
			return -1;
		}

		sc_log(INFO, "started platform platform: \"%s\" (data=0x%p)",
			p->name, data);

		// FIXME: arbitrary delay between plats
		sleep(7);

		p->data = data;
		p->running = true;
		num_plats++;

		p = p->next;
	}

	return num_plats;
}

// Iterate all underlying impl objects, stop one by one
// Cannot fail, force stop and/or kill if necessary
int sc_platforms_stop_all(struct systemc *sc)
{
	int num_plats = 0;
	struct sc_state *s = sc->state;
	struct sc_platform *p = s->platforms;
	const struct sc_cont_ctrl *ctrl;

	while (p) {
		ctrl = _sc_platforms_get_ctrl(p->type);
		ctrl->stop(NULL, NULL, p->data);
		num_plats++;
		p = p->next;
	}

	sc_platforms_remove_all(s);

	sc_log(INFO, "stopped %d platforms", num_plats);

	return num_plats;
}
