#ifndef SC_SYSTEMC_H
#define SC_SYSTEMC_H

#include <trail.h>
#include "config.h"

// systemc.h

struct trail_remote;

enum update_state {
	UPDATE_QUEUED,
	UPDATE_DONE,
	UPDATE_TRY,
	UPDATE_FAILED,
};

struct sc_update {
	systemc_state *pending;
	char *endpoint;
	enum update_state status;
};

struct systemc {
	struct systemc_config *config;
	systemc_state *state;
	struct trail_remote *remote;
	struct sc_update *update;
	char *step;
};

void sc_destroy(struct systemc *sc);
void sc_release_state(struct systemc *sc);
systemc_state* sc_parse_state_from_buf(struct systemc *sc, char *buf);
systemc_state* sc_get_state(struct systemc *sc, int current);
systemc_state *sc_get_current_state(struct systemc *sc);
int sc_volumes_mount(struct systemc *sc);
int sc_volumes_unmount(struct systemc *sc);
int sc_start_platforms(struct systemc *sc);
int systemc_init(void);

#endif
