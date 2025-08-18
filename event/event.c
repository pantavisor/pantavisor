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

#include <string.h>

#include "event.h"

#define MODULE_NAME "event"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static struct event_base *base = NULL;

static void _event_log_cb(int severity, const char *msg)
{
	if (!msg)
		return;

	enum log_level level = DEBUG;
	switch (severity) {
	case EVENT_LOG_DEBUG:
	case EVENT_LOG_MSG:
		level = DEBUG;
		break;
	case EVENT_LOG_WARN:
		level = WARN;
		break;
	case EVENT_LOG_ERR:
		level = ERROR;
		break;
	default:
		pv_log(WARN, "unknown libevent log level %d", severity);
	}

	pv_log(level, "%s", msg);
}

static void _event_fatal_cb(int err)
{
	pv_log(ERROR, "libevent fatal error %d", err);
}

int pv_event_base_init()
{
	if (base)
		return 0;

	event_set_log_callback(_event_log_cb);
	event_set_fatal_callback(_event_fatal_cb);

	if (pv_config_get_bool(PV_LIBEVENT_DEBUG_MODE)) {
		pv_log(DEBUG, "libevent debug mode enabled");
		event_enable_debug_logging(EVENT_DBG_ALL);
		event_enable_debug_mode();
	}

	pv_log(DEBUG, "initializing event base");

	base = event_base_new();
	if (!base) {
		pv_log(ERROR, "could not init event base: %s", strerror(errno));
		return -1;
	}

	pv_log(DEBUG, "event base initialized");

	return 0;
}

void pv_event_base_close()
{
	pv_log(DEBUG, "freeing event base");

	if (base) {
		event_base_free(base);
		base = NULL;
	}
	libevent_global_shutdown();

	pv_log(DEBUG, "event base freed");
}

void pv_event_base_loop()
{
	if (!base)
		return;

	pv_log(INFO, "event base will start processing events");
	event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY);
}

void pv_event_base_loopbreak()
{
	if (!base)
		return;

	pv_log(INFO, "event base will stop processing events");
	event_base_loopbreak(base);
}

void pv_event_one_shot(event_callback_fn cb)
{
	if (!base)
		return;

	struct timeval when = { 0, 0 };
	event_base_once(base, -1, EV_TIMEOUT, cb, NULL, &when);

	pv_log(DEBUG, "add event: type='one shot' cb=%p", (void *)cb);
}

struct event_base *pv_event_get_base()
{
	return base;
}
