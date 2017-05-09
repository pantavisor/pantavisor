/*
 * Copyright (c) 2017 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef SC_BOOTLOADER_H
#define SC_BOOTLOADER_H

#include "systemc.h"

int sc_bl_pvk_get_bank(struct systemc *sc);
int sc_bl_install_kernel(struct systemc *sc, char *obj);
int sc_bl_pvk_get_rev(struct systemc *sc, int bank);
int sc_bl_set_try(struct systemc *sc, int rev);
void sc_bl_set_current(struct systemc *sc, int rev);
int sc_bl_get_current(struct systemc *sc);
int sc_bl_get_update(struct systemc *sc, int *update);
int sc_bl_clear_update(struct systemc *sc);
int sc_bl_get_try(struct systemc *sc);

#endif
