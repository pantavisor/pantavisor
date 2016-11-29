#ifndef SC_SYSTEMC_H
#define SC_SYSTEMC_H

#include <trail.h>
#include "config.h"

// systemc.h

struct trail_remote;

enum update_state {
	UPDATE_QUEUED,
	UPDATE_DOWNLOADED,
	UPDATE_INSTALLED,
	UPDATE_TRY,
	UPDATE_REBOOT,
	UPDATE_DONE,
	UPDATE_FAILED,
};

struct trail_object {
	char *id;
	char *objpath;
	char *relpath;
	char *geturl;
	struct trail_object *next;
};

struct trail_step {
	char *json;
	systemc_state *state;
};

struct sc_update {
	enum update_state status;
	char *endpoint;
	int need_reboot;
	struct trail_step *pending;
	struct trail_object **objects;
};

struct systemc {
	int last;
	char *step;
	struct systemc_config *config;
	struct trail_remote *remote;
	struct sc_update *update;
	systemc_state *state;
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
