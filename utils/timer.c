/*
 * Copyright (c) 2021-2023 Pantacor Ltd.
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

#include <sys/param.h>

#include "timer.h"

static clockid_t timer_type_clockid(timer_type_t type)
{
	switch (type) {
	case RELATIV_TIMER:
		return CLOCK_MONOTONIC;
	case ABSOLUTE_TIMER:
		return CLOCK_REALTIME;
	}

	return 0;
}

static int get_current_time(timer_type_t type, struct timespec *current_time)
{
	return clock_gettime(timer_type_clockid(type), current_time);
}

uint64_t timer_get_current_time_sec(timer_type_t type)
{
	struct timespec now;
	get_current_time(type, &now);
	return now.tv_sec;
}

struct timer_state timer_current_state(struct timer *t)
{
	struct timespec now;
	struct timer_state tstate;

	get_current_time(t->type, &now);

	tstate.fin = (now.tv_sec > t->timeout.tv_sec) ||
		     (now.tv_sec == t->timeout.tv_sec &&
		      now.tv_nsec >= t->timeout.tv_nsec);

	// time_t's signess is implementation dependent. So we handle it tv_sec and tv_nsec as unsigned
	if (tstate.fin) {
		if (now.tv_nsec < t->timeout.tv_nsec) {
			tstate.nsec = t->timeout.tv_nsec - now.tv_nsec;
			tstate.sec = now.tv_sec - t->timeout.tv_sec - 1;
		} else {
			tstate.nsec = now.tv_nsec - t->timeout.tv_nsec;
			tstate.sec = now.tv_sec - t->timeout.tv_sec;
		}
	} else {
		if (now.tv_nsec > t->timeout.tv_nsec) {
			tstate.nsec = now.tv_nsec - t->timeout.tv_nsec;
			tstate.sec = t->timeout.tv_sec - now.tv_sec - 1;
		} else {
			tstate.nsec = t->timeout.tv_nsec - now.tv_nsec;
			tstate.sec = t->timeout.tv_sec - now.tv_sec;
		}
	}

	return tstate;
}

int timer_start(struct timer *t, time_t sec, long nsec, timer_type_t type)
{
	struct timespec now;

	t->type = type;
	if (type == RELATIV_TIMER) {
		get_current_time(t->type, &now);

		t->timeout.tv_sec = now.tv_sec + sec;
		t->timeout.tv_nsec = now.tv_nsec + nsec;
	} else {
		t->timeout.tv_sec = sec;
		t->timeout.tv_nsec = nsec;
	}

	return 1;
}
void timer_stop(struct timer *t)
{
	if (!t)
		return;

	t->timeout.tv_sec = 0;
	t->timeout.tv_nsec = 0;
}