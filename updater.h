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
#ifndef PV_UPDATER_H
#define PV_UPDATER_H

#include "pantavisor.h"
#include <trest.h>

#define DEVICE_TRAIL_ENDPOINT_FMT "/trails/%s/steps"
#define DEVICE_STEP_ENDPOINT_FMT "/trails/%s/steps/%d/progress"
#define DEVICE_STEP_STATUS_FMT "{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d }"

#define TRAIL_OBJECT_DL_FMT	"/objects/%s"

#define VOLATILE_TMP_OBJ_PATH "/tmp/object-XXXXXX"
#define MMC_TMP_OBJ_FMT "%s.tmp"

struct trail_remote {
	trest_ptr client;
	char *endpoint;
	struct pv_state *pending;
};

int pv_update_start(struct pantavisor *pv, int offline);
int pv_update_set_status(struct pantavisor *pv, enum update_state status);
int pv_update_finish(struct pantavisor *pv);
int pv_update_install(struct pantavisor *pv);
int pv_check_for_updates(struct pantavisor *pv);
int pv_do_single_update(struct pantavisor *pv);
void pv_remote_destroy(struct pantavisor *pv);

int pv_bl_set_current(struct pantavisor *pv, int rev);
int pv_bl_get_update(struct pantavisor *pv, int *update);
int pv_bl_clear_update(struct pantavisor *pv);

#endif
