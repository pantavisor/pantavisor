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
#ifndef SC_UPDATER_H
#define SC_UPDATER_H

#include "systemc.h"
#include <trest.h>

#define DEVICE_TRAIL_ENDPOINT_FMT "/trails/%s/steps"
#define DEVICE_STEP_ENDPOINT_FMT "/trails/%s/steps/%d/progress"
#define DEVICE_STEP_STATUS_FMT "{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d }"

#define TRAIL_OBJECT_DL_FMT	"/objects/%s"

struct trail_remote {
	trest_ptr client;
	char *endpoint;
	struct sc_state *pending;
};

int sc_trail_update_start(struct systemc *sc, int offline);
int sc_trail_update_finish(struct systemc *sc);
int sc_trail_update_install(struct systemc *sc);
int sc_trail_check_for_updates(struct systemc *sc);
int sc_trail_do_single_update(struct systemc *sc);
void sc_trail_remote_destroy(struct systemc *sc);

void sc_bl_set_current(struct systemc *sc, int rev);
int sc_bl_get_update(struct systemc *sc, int *update);
int sc_bl_clear_update(struct systemc *sc);

#endif
