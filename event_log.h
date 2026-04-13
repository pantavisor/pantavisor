/*
 * Copyright (c) 2025-2026 Pantacor Ltd.
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
#ifndef PV_EVENT_LOG_H
#define PV_EVENT_LOG_H

#include <time.h>

#include "utils/json.h"

#define PV_EVENT_RING_SIZE 128

typedef enum {
	PV_EVENT_TYPE_SYSTEM,
	PV_EVENT_TYPE_PLATFORM,
	PV_EVENT_TYPE_UPDATE,
	PV_EVENT_TYPE_PANTAHUB
} pv_event_type_t;

struct pv_event {
	time_t ts;
	pv_event_type_t type;
	char src[64];
	char event[32];
	char detail[128];
};

struct pv_event_log {
	struct pv_event entries[PV_EVENT_RING_SIZE];
	int head;
	int count;
};

void pv_event_log_init(void);
void pv_event_log_push(pv_event_type_t type, const char *src, const char *event,
		       const char *detail);
void pv_event_log_serialize(struct pv_json_ser *js);

#endif
