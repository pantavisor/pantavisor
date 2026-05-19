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
#ifndef PV_EVENT_H
#define PV_EVENT_H

#include <event2/event.h>

// Event priorities — lower number fires first.
// Must match PV_EVENT_PRIORITY_COUNT passed to event_base_priority_init().
// With COUNT=4 the libevent default for new events is 4/2=2 (CTRL).
#define PV_EVENT_PRIORITY_HIGH 0 // reserved — available for future use
#define PV_EVENT_PRIORITY_DEFAULT 1 // state machine, hub API, general events
#define PV_EVENT_PRIORITY_CTRL 2 // ctrl non-file-transfer (libevent default)
#define PV_EVENT_PRIORITY_LOW 3 // bulk transfers (hub downloads, ctrl objects)
#define PV_EVENT_PRIORITY_COUNT 4

int pv_event_base_init(void);
void pv_event_base_close(void);

void pv_event_base_loop(void);
void pv_event_base_loopbreak(void);

void pv_event_timeout(int timeout, event_callback_fn cb);
void pv_event_one_shot(event_callback_fn cb);

// do not use outside event/
struct event_base *pv_event_get_base(void);

#endif
