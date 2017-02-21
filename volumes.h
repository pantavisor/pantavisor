#ifndef SC_VOLUMES_H
#define SC_VOLUMES_H

struct sc_volume* sc_volume_get_by_name(struct sc_state *s, char *name);
void sc_volume_remove(struct sc_state *s, char *name);
struct sc_volume* sc_volume_add(struct sc_state *s, char *name);
int sc_volumes_mount(struct systemc *sc);
int sc_volumes_unmount(struct systemc *sc);

#endif // SC_VOLUMES_H
