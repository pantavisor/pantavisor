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

#ifndef TIMER_H
#define TIMER_H

#include <time.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum { RELATIV_TIMER, ABSOLUTE_TIMER } timer_type_t;

uint64_t timer_get_current_time_sec(timer_type_t type);

struct timer {
	timer_type_t type;
	struct timespec timeout;
};

/*
 * time, sec and nsec are always positive. When the timer has finished (fin = true),
 * time, sec and nsec hold the time passed since the timer has finished. Otherwise,
 * time, sec and nsce hold the time left on the timer.
 */
struct timer_state {
	bool fin;
	union {
		struct timespec time;
		struct {
			time_t sec;
			long nsec;
		};
	};
};

int timer_start(struct timer *t, time_t sec, long nsec, timer_type_t type);
struct timer_state timer_current_state(struct timer *t);

#endif // TIMER_H
