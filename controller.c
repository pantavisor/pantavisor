#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

#include <linux/limits.h>

#include "log.h"
#include "systemc.h"
#include "loop.h"
#include "platforms.h"

#include "controller.h"

// SystemC controller

#define CONFIG_FILENAME		"/systemc/device.config"
#define CMDLINE_OFFSET		7

static int counter;

typedef enum {
	STATE_INIT,
	STATE_RUN,
	STATE_WAIT,
	STATE_UPDATE,
	STATE_ROLLBACK,
	STATE_REBOOT,
	STATE_ERROR,
	STATE_EXIT,
	MAX_STATES
} sc_state_t;

typedef sc_state_t sc_state_func_t(struct systemc *sc);

static int sc_step_get_prev(struct systemc *sc)
{
	if (!sc)
		return -1;

	if (sc->state)
		return (sc->state->rev - 1);

	return -1;
}

static sc_state_t _sc_init(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	int fd, ret, bytes;
	int step_rev = -1;
	int step_try = 0;
	char *buf;
	char *token;
	struct systemc_config *c;

	//sc->trail = sc_trail_new();
        c = malloc(sizeof(struct systemc_config));

        if (config_from_file(CONFIG_FILENAME, c) < 0)
                exit_error(errno, "Unable to parse config");

        printf("c->storage.path = '%s'\n", c->storage.path);
        printf("c->storage.fstype = '%s'\n", c->storage.fstype);
        printf("c->storage.opts = '%s'\n", c->storage.opts);
        printf("c->storage.mntpoint = '%s'\n", c->storage.mntpoint);

	// Create storage mountpoint and mount device
        mkdir_p(c->storage.mntpoint, 0644);
        ret = mount(c->storage.path, c->storage.mntpoint, c->storage.fstype, 0, NULL);
        if (ret < 0)
                exit_error(errno, "Could not mount trails storage");

	// Set config
	sc->config = c;

	// Get current step revision from cmdline
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -1;

	buf = malloc(sizeof(char) * 1024);
	bytes = read(fd, buf, sizeof(char)*1024);
	close(fd);

	token = strtok(buf, " ");
	while (token) {
		if (strncmp("sc_rev=", token, CMDLINE_OFFSET) == 0)
			step_rev = atoi(token + CMDLINE_OFFSET);
		else if (strncmp("sc_try=", token, CMDLINE_OFFSET) == 0)
			step_try = atoi(token + CMDLINE_OFFSET);
		token = strtok(NULL, " ");
	}
	free(buf);

	// Get current from disk if not specified in command line
	if (step_rev < 0) {
		sc->state = sc_get_current_state(sc);
		if (sc->state)
			return STATE_RUN;
	}

	// If no current link, find latest
	if (step_rev < 0) {
		struct dirent **dirs;
		char basedir[PATH_MAX];

		sprintf(basedir, "%s/trails/", sc->config->storage.mntpoint);

		int n = scandir(basedir, &dirs, NULL, alphasort);
		while (n--) {
			char *tmp = dirs[n]->d_name;

			while (*tmp && isdigit(*tmp))
				tmp++;

			if(tmp[0] != '\0')
				continue;

			printf("SYSTEMC: Default to newest step_rev: '%s'\n", dirs[n]->d_name);
			step_rev = atoi(dirs[n]->d_name);
			break;
		}
	}

	sc->state = sc_get_state(sc, step_rev);

	if (!sc->state) {
		printf("SYSTEMC: Invalid state requested, please reconfigure\n");
		return STATE_ERROR;
	}

	counter = 0;

        return STATE_RUN;
}

static sc_state_t _sc_run(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	int ret;

	if (sc_mount_volumes(sc) < 0)
		return STATE_ROLLBACK;

	ret = sc_platforms_start_all(sc);

	if (ret < 0) {
		printf("SYSTEMC: Error starting platforms\n");
		return STATE_ERROR;
	}

	//if (sc->steps->current->try)
	//	sc_commit_state(sc);

	printf("SYSTEMC: Started %d platforms\n", ret);
	
	return STATE_UPDATE;
}

static sc_state_t _sc_wait(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	sleep(5);
	counter++;

	return STATE_UPDATE;
}

static sc_state_t _sc_update(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);

	if (counter == 5)
		return STATE_ROLLBACK;

	return STATE_WAIT;
}

static sc_state_t _sc_rollback(struct systemc *sc)
{
	int ret;
	int rev = sc->state->rev;

	counter = 0;
	
	printf("%s():%d\n", __func__, __LINE__);
	
	ret = sc_platforms_stop_all(sc);

	if (ret < 0)
		return STATE_ERROR;

	if (rev == 0) {
		printf("SYSTEMC: At factory step, cannot roll back -- starting\n");
		return STATE_RUN;
	}

	trail_state_free(sc->state);
	sc->state = sc_get_state(sc, rev - 1);

	if (sc->state)
		printf("SYSTEMC: Loaded previous step %d\n", rev - 1);
	
	return STATE_RUN;
}

static sc_state_t _sc_reboot(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	return STATE_EXIT;
}

static sc_state_t _sc_error(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	sleep(1);
	return STATE_ERROR;
}

sc_state_func_t* const state_table[MAX_STATES] = {
	_sc_init,
	_sc_run,
	_sc_wait,
	_sc_update,
	_sc_rollback,
	_sc_reboot,
	_sc_error,
	NULL
};

static sc_state_t _sc_run_state(sc_state_t state, struct systemc *sc)
{
	return state_table[state](sc);
}

int sc_controller_start(struct systemc *sc)
{
	sc_state_t state = STATE_INIT;
 
	while (1) {
		printf("Going to state = %d\n", state);
		state = _sc_run_state(state, sc);

		if (state == STATE_EXIT)
			return 0;
	}
}
