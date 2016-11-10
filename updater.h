#ifndef SC_UPDATER_H
#define SC_UPDATER_H

#include "systemc.h"
#include <trest.h>

#define DEVICE_TRAIL_ENDPOINT_FMT "/api/trails/%s/steps"

struct trail_remote {
	trest_ptr client;
	char *endpoint;
};

int sc_trail_check_for_updates(struct systemc *sc);
int sc_trail_do_update(struct systemc *sc);
void sc_trail_remote_destroy(struct systemc *sc);

#endif
