#ifndef SC_BOOTLOADER_H
#define SC_BOOTLOADER_H

#include "systemc.h"

int sc_bl_install_kernel(struct systemc *sc, char *obj);
int sc_bl_pvk_get_rev(struct systemc *sc, int bank);
int sc_bl_set_try(struct systemc *sc, int rev);
void sc_bl_set_current(struct systemc *sc, int rev);
int sc_bl_get_current(struct systemc *sc);
int sc_bl_get_update(struct systemc *sc, int *update);
int sc_bl_clear_update(struct systemc *sc);
int sc_bl_get_try(struct systemc *sc);

#endif
