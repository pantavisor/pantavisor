#ifndef SC_UPDATER_H
#define SC_UPDATER_H

#include "systemc.h"
#include <trest.h>

#define DEVICE_TRAIL_ENDPOINT_FMT "/api/trails/%s/steps"
#define DEVICE_STEP_ENDPOINT_FMT "/api/trails/%s/steps/%d/progress"
#define DEVICE_STEP_STATUS_FMT "{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d }"

#define TRAIL_OBJPATH_FMT	"%s/objects/%s"
#define TRAIL_KERNEL_FMT	"%s/trails/%d/%s"
#define TRAIL_VOLUMES_FMT	"%s/trails/%d/volumes/%s"
#define TRAIL_SYSTEMC_FMT	"%s/trails/%d/systemc/%s"
#define TRAIL_PLAT_CFG_FMT	"%s/trails/%d/platforms/%s/configs/%s"

#define TRAIL_OBJECT_DL_FMT	"/api/objects/%s"

struct trail_remote {
	trest_ptr client;
	char *endpoint;
	struct trail_step *pending;
};

int sc_trail_update_start(struct systemc *sc);
int sc_trail_update_finish(struct systemc *sc);
int sc_trail_update_install(struct systemc *sc);
int sc_trail_check_for_updates(struct systemc *sc);
int sc_trail_do_single_update(struct systemc *sc);
void sc_trail_remote_destroy(struct systemc *sc);

#endif
