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
#include "pantahub/pantahub_timer.h"

#define MODULE_NAME "pantahub_timer"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

void pv_pantahub_timer_run(event_timer_t *timer, struct event_base *base,
			   int next_interval, event_callback_fn cb)
{
	if (!timer || !base)
		return;

	if (timer->ev && (next_interval == timer->interval))
		return;

	if (timer->ev) {
		event_del(timer->ev);
		event_free(timer->ev);
	}

	timer->ev = event_new(base, -1, EV_PERSIST, cb, base);
	if (!timer->ev) {
		pv_log(ERROR, "could not create event");
		return;
	}

	timer->interval = next_interval;
	struct timeval time = { timer->interval, 0 };
	if (event_add(timer->ev, &time) < 0) {
		pv_log(ERROR, "could not add usrmeta event");
		return;
	}
}

void pv_pantahub_timer_close(event_timer_t *timer)
{
	if (!timer)
		return;

	if (timer->ev) {
		event_del(timer->ev);
		event_free(timer->ev);
	}
}
