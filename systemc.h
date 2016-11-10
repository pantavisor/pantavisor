#ifndef SC_SYSTEMC_H
#define SC_SYSTEMC_H

#include <trail.h>
#include "config.h"

// systemc.h

struct trail_remote;

struct systemc {
	struct systemc_config *config;
	systemc_state *state;
	struct tstep *steps;
	struct trail_remote *remote;
};

void sc_destroy(struct systemc *sc);
systemc_state* sc_get_state(struct systemc *sc, int current);
systemc_state *sc_get_current_state(struct systemc *sc);
int sc_volumes_mount(struct systemc *sc);
int sc_volumes_unmount(struct systemc *sc);
int sc_start_platforms(struct systemc *sc);
int systemc_init(void);

#endif
