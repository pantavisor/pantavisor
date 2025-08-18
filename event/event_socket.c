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

#include "event_socket.h"

#include "event.h"

#define MODULE_NAME "event_socket"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

void pv_event_socket_listen(event_socket_t *listener, evutil_socket_t fd,
			    event_callback_fn cb)
{
	if (!listener || !pv_event_get_base())
		return;

	if (listener->ev)
		return;

	listener->ev = event_new(pv_event_get_base(), fd, EV_READ | EV_PERSIST,
				 cb, NULL);

	if (!listener->ev)
		return;

	event_add(listener->ev, NULL);
	listener->fd = fd;

	pv_log(DEBUG, "add event: type='listener' cb=%p fd=%d", (void *)cb, fd);
}

void pv_event_socket_ignore(event_socket_t *listener)
{
	if (!listener)
		return;

	if (!listener->ev)
		return;

	pv_log(DEBUG, "stop listening event to socket fd %d", listener->fd);

	event_free(listener->ev);
	listener->ev = NULL;
}
