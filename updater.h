#ifndef SC_UPDATER_H
#define SC_UPDATER_H

#include "systemc.h"
#include <trest.h>

#define DEVICE_TRAIL_ENDPOINT_FMT "/api/trails/%s/steps"
#define DEVICE_STEP_ENDPOINT_FMT "/api/trails/%s/steps/%d"

struct trail_remote {
	trest_ptr client;
	char *endpoint;
	systemc_state *pending;
};

int sc_trail_update_start(struct systemc *sc);
int sc_trail_update_finish(struct systemc *sc);
int sc_trail_update_install(struct systemc *sc);
int sc_trail_check_for_updates(struct systemc *sc);
int sc_trail_do_single_update(struct systemc *sc);
void sc_trail_remote_destroy(struct systemc *sc);

#endif
