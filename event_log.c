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

#include <string.h>
#include <time.h>

#include "event_log.h"
#include "config.h"

#define MODULE_NAME "event_log"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

static struct pv_event_log event_log;

static const char *_event_type_str(pv_event_type_t type)
{
	switch (type) {
	case PV_EVENT_TYPE_SYSTEM:
		return "system";
	case PV_EVENT_TYPE_PLATFORM:
		return "platform";
	case PV_EVENT_TYPE_UPDATE:
		return "update";
	case PV_EVENT_TYPE_PANTAHUB:
		return "pantahub";
	default:
		return "unknown";
	}
}

void pv_event_log_init(void)
{
	memset(&event_log, 0, sizeof(event_log));
}

void pv_event_log_push(pv_event_type_t type, const char *src, const char *event,
		       const char *detail)
{
	struct pv_event *e;

	if (!pv_config_get_bool(PV_LOG_EVENTS))
		return;

	/* emit a synthetic wrapped event on first overflow */
	if (event_log.count == PV_EVENT_RING_SIZE && event_log.head == 0) {
		e = &event_log.entries[event_log.head];
		e->ts = time(NULL);
		e->type = PV_EVENT_TYPE_SYSTEM;
		snprintf(e->src, sizeof(e->src), "event_log");
		snprintf(e->event, sizeof(e->event), "wrapped");
		snprintf(e->detail, sizeof(e->detail),
			 "ring buffer overflow, oldest events lost");
		event_log.head = (event_log.head + 1) % PV_EVENT_RING_SIZE;
		event_log.count++;
	}

	e = &event_log.entries[event_log.head];
	e->ts = time(NULL);
	e->type = type;
	snprintf(e->src, sizeof(e->src), "%s", src ? src : "");
	snprintf(e->event, sizeof(e->event), "%s", event ? event : "");
	snprintf(e->detail, sizeof(e->detail), "%s", detail ? detail : "");

	event_log.head = (event_log.head + 1) % PV_EVENT_RING_SIZE;
	if (event_log.count < PV_EVENT_RING_SIZE)
		event_log.count++;

	pv_log(DEBUG, "event: type=%s src=%s event=%s detail=%s",
	       _event_type_str(type), src ? src : "", event ? event : "",
	       detail ? detail : "");
}

void pv_event_log_serialize(struct pv_json_ser *js)
{
	int i, idx, n;

	if (!pv_config_get_bool(PV_LOG_EVENTS))
		return;

	if (event_log.count == 0)
		return;

	pv_json_ser_key(js, "events");
	pv_json_ser_array(js);

	n = (event_log.count < PV_EVENT_RING_SIZE) ? event_log.count :
						     PV_EVENT_RING_SIZE;

	/* start from oldest entry in the ring */
	int start;
	if (event_log.count <= PV_EVENT_RING_SIZE)
		start = 0;
	else
		start = event_log.head;

	for (i = 0; i < n; i++) {
		idx = (start + i) % PV_EVENT_RING_SIZE;
		struct pv_event *e = &event_log.entries[idx];

		pv_json_ser_object(js);
		{
			pv_json_ser_key(js, "ts");
			pv_json_ser_number(js, (double)e->ts);
			pv_json_ser_key(js, "type");
			pv_json_ser_string(js, _event_type_str(e->type));
			pv_json_ser_key(js, "src");
			pv_json_ser_string(js, e->src);
			pv_json_ser_key(js, "event");
			pv_json_ser_string(js, e->event);
			if (e->detail[0] != '\0') {
				pv_json_ser_key(js, "detail");
				pv_json_ser_string(js, e->detail);
			}
			pv_json_ser_object_pop(js);
		}
	}

	pv_json_ser_array_pop(js);
}
