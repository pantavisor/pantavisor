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
#ifndef SC_PLATFORMS_H
#define SC_PLATFORMS_H

#include <stdbool.h>

#include "systemc.h"

int sc_platforms_init_ctrl(struct systemc *sc);
struct sc_platform* sc_platform_add(struct sc_state *s, char *name);
struct sc_platform* sc_platform_remove(struct sc_state *s, char *name);
void sc_platforms_remove_all(struct sc_state *s);
void sc_platforms_remove_not_done(struct sc_state *s);
void sc_platforms_remove_by_data(struct sc_state *s, void *data);
struct sc_platform* sc_platform_get_by_name(struct sc_state *s, char *name);
struct sc_platform* sc_platform_get_by_data(struct sc_state *s, void *data);
int sc_platforms_start_all(struct systemc *sc);
int sc_platforms_stop_all(struct systemc *sc);

#endif
