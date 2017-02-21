#ifndef SC_OBJECTS_H
#define SC_OBJECTS_H

#define OBJPATH_FMT	"%s/objects/%s"
#define RELPATH_FMT	"%s/trails/%d/%s"

#include "systemc.h"

struct sc_object* sc_objects_add(struct sc_state *s, char *filename, char *id, char *c);
struct sc_object* sc_objects_get_by_name(struct sc_state *s, char *name);
void sc_objects_remove_all(struct sc_state *s);

#endif // SC_OBJECTS_H
