/*
 * Copyright (c) 2025 Pantacor Ltd.
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
#ifndef PV_PANTAHUB_STRUCT_H
#define PV_PANTAHUB_STRUCT_H

#include "event/event_periodic.h"

typedef enum {
	PH_STATE_INIT,
	PH_STATE_REGISTER,
	PH_STATE_CLAIM,
	PH_STATE_SYNC,
	PH_STATE_LOGIN,
	PH_STATE_WAIT_HUB,
	PH_STATE_REPORT,
	PH_STATE_IDLE,
	PH_STATE_PREP_DOWNLOAD,
	PH_STATE_DOWNLOAD,
	PH_STATE_MAX
} ph_state_t;

struct pv_pantahub {
	ph_state_t state;
	struct pv_event_periodic evaluate_timer;
	struct pv_event_periodic request_timer;
	struct pv_event_periodic usrmeta_timer;
	struct pv_event_periodic devmeta_timer;
};

#endif
