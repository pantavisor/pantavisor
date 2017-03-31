#ifndef SC_PANTAHUB_H
#define SC_PANTAHUB_H

int sc_ph_is_available(struct systemc *sc);
int sc_ph_device_exists(struct systemc *sc);
int sc_ph_register_self(struct systemc *sc);
const char** sc_ph_get_certs(struct systemc *sc);
int sc_ph_device_is_owned(struct systemc *sc, char **c);
void sc_ph_release_client(struct systemc *sc);
void sc_ph_update_hint_file(struct systemc *sc, char *c);

#endif
