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
#ifndef PV_PLATFORMS_H
#define PV_PLATFORMS_H

#include <stdbool.h>

#include "pantavisor.h"

int pv_platforms_init_ctrl(struct pantavisor *pv);
struct pv_platform* pv_platform_add(struct pv_state *s, char *name);
struct pv_platform* pv_platform_remove(struct pv_state *s, char *name);
void pv_platforms_remove(struct pv_state *s, component_runlevel_t runlevel);
void pv_platforms_remove_not_done(struct pv_state *s);
struct pv_platform* pv_platform_get_by_name(struct pv_state *s, char *name);
struct pv_platform* pv_platform_get_by_data(struct pv_state *s, void *data);
static void pv_platforms_force_kill(struct pantavisor *pv, component_runlevel_t runlevel);
int pv_platforms_start(struct pantavisor *pv, component_runlevel_t runlevel);
int pv_platforms_stop(struct pantavisor *pv, component_runlevel_t runlevel);
int pv_platforms_check_exited(struct pantavisor *pv, component_runlevel_t runlevel);

#endif
