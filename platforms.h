#ifndef SC_PLATFORMS_H
#define SC_PLATFORMS_H

#include <stdbool.h>

#include "systemc.h"

struct sc_platform* sc_platform_add(struct sc_state *s, char *name);
struct sc_platform* sc_platform_remove(struct sc_state *s, char *name);
void sc_platforms_remove_all(struct sc_state *s);
void sc_platforms_remove_by_data(struct sc_state *s, void *data);
struct sc_platform* sc_platform_get_by_name(struct sc_state *s, char *name);
struct sc_platform* sc_platform_get_by_data(struct sc_state *s, void *data);
int sc_platforms_start_all(struct systemc *sc);
int sc_platforms_stop_all(struct systemc *sc);

#endif
