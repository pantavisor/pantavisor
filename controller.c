#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"
#include "systemc.h"
#include "loop.h"

#include "controller.h"

// SystemC controller

#define CONFIG_FILENAME		"/factory/device.config"

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

static struct tstep *steps_init()
{
	struct tstep *steps = malloc(sizeof(struct tstep));

	// FIXME: Initialize linked list of tsteps

	return steps;
}

static sc_state_t _sc_init(struct systemc *sc)
{
        int ret;
	struct systemc_config *c;

	sc->steps = steps_init();
        c = malloc(sizeof(struct systemc_config));

        ret = config_from_file(CONFIG_FILENAME, c);
        if (ret < 0)
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

	// Get state 0
	sc->state = sc_get_state(sc, 0);

        return STATE_RUN;
}

static sc_state_t _sc_run(struct systemc *sc)
{
	sc_mount_volumes(sc);

	if (sc_start_platforms(sc) < 0)
		return STATE_ROLLBACK;

	//if (sc->steps->current->try)
	//	sc_commit_state(sc);

	return STATE_UPDATE;
}

static sc_state_t _sc_wait(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	sleep(5);
	return STATE_UPDATE;
}

static sc_state_t _sc_update(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
	return STATE_WAIT;
}

static sc_state_t _sc_rollback(struct systemc *sc)
{
	printf("%s():%d\n", __func__, __LINE__);
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
