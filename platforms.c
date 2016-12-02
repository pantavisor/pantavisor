#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <linux/limits.h>

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

struct sc_platform {
	void *data;
	char *type;
	struct sc_platform *next;
};

static struct sc_platform *head = 0;
static struct sc_platform *last;

static struct sc_platform* _sc_platforms_add(void *data, char *type)
{
	struct sc_platform *this = (struct sc_platform*) malloc(sizeof(struct sc_platform));

	if (!this) {
		sc_log(ERROR, "cannot allocate new platform\n");
		return NULL;
	}

	if ((strcmp(type, "") == 0) || !data) {
		free(this);
		return NULL;
	}

	if (!head)
		head = this;
	else
		last->next = this;

	this->data = data;
	this->type = strdup(type);
	this->next = NULL;
	last = this;	

	return this;
}

static struct sc_platform* _sc_platform_by_data(void *data)
{
	struct sc_platform *curr;

	if (data == NULL)
		return NULL;

	for (curr = head; curr != NULL; curr = curr->next)
		if (curr->data == data)
			return curr;

	return NULL;
}

static void _sc_platforms_remove_all(void)
{
	struct sc_platform *curr;

	for (curr = head; curr != NULL; curr = curr->next) {
		free(curr->type);
		free(curr);
	}

	head = NULL;
	last = NULL;
}

static void _sc_platforms_remove(void *data)
{
	struct sc_platform *curr;
	struct sc_platform *prev;

	if (data == NULL)
		return;

	for (curr = prev = head; curr != NULL; curr = curr->next) {
		if (curr->data == data) {
			free(curr->type);
			if (curr == head)
				head = curr->next;
			else
				prev->next = curr->next;
			free(curr);
			return;
		}
		prev = curr;
	}

	last = prev;
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
	systemc_platform **platforms;

	if (sc->state->platformsv) {
		platforms = sc->state->platformsv;
	} else {
		sc_log(ERROR, "no platforms available");
		return -1;
	}

	while (*platforms) {
		char conf_path[PATH_MAX];
		const struct sc_cont_ctrl *ctrl;
		void *data;
		systemc_object **config;

		config = (*platforms)->configs;
		sprintf(conf_path, "%s/trails/%d/platforms/%s/configs/%s",
			sc->config->storage.mntpoint, sc->state->rev,
			(*platforms)->name, (*config)->filename);

		// Get type controller
		ctrl = _sc_platforms_get_ctrl((*platforms)->type);	

		// Start the platform
		data = ctrl->start((*platforms)->name, conf_path, NULL);

		if (!data) {
			sc_log(ERROR, "error starting platform: \"%s\"",
				(*platforms)->name);
			return -1;
		}
		
		sc_log(INFO, "started platform platform: \"%s\" (data=0x%p)",
			(*platforms)->name, data);

		_sc_platforms_add(data, (*platforms)->type);
		num_plats++;

		platforms++;
	}
	
	return num_plats;
}

// Iterate all underlying impl objects, stop one by one
// Cannot fail, force stop and/or kill if necessary
int sc_platforms_stop_all(struct systemc *sc)
{
	int num_plats = 0;
	struct sc_platform *curr;
	const struct sc_cont_ctrl *ctrl;

	for (curr = head; curr != NULL; curr = curr->next) {
		ctrl = _sc_platforms_get_ctrl(curr->type);
		ctrl->stop(NULL, NULL, curr->data);
		num_plats++;
	}

	_sc_platforms_remove_all();

	sc_log(INFO, "stopped %d platforms", num_plats);

	return num_plats;
}
