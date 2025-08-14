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

#include "event_timer.h"

#include "event.h"

#define MODULE_NAME "event_timer"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

void pv_event_timer_run(event_timer_t *timer, int next_interval,
			event_callback_fn cb)
{
	if (!timer || !pv_event_get_base())
		return;

	if (timer->ev && (next_interval == timer->interval))
		return;

	if (timer->ev) {
		event_del(timer->ev);
		event_free(timer->ev);
	}

	timer->ev = event_new(pv_event_get_base(), -1, EV_PERSIST, cb, NULL);
	if (!timer->ev) {
		pv_log(ERROR, "could not create timer event");
		return;
	}

	struct timeval time = { next_interval, 0 };
	if (event_add(timer->ev, &time) < 0) {
		pv_log(ERROR, "could not add timer event");
		return;
	}
	timer->interval = next_interval;

	pv_log(DEBUG, "add event: type='timer' cb=%p interval=%d", (void *)cb,
	       next_interval);
}

void pv_event_timer_close(event_timer_t *timer)
{
	if (!timer)
		return;

	pv_log(DEBUG, "closing timer event with interval %d s",
	       timer->interval);

	if (timer->ev) {
		event_del(timer->ev);
		event_free(timer->ev);
	}
	timer->ev = NULL;
}
