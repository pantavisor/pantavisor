/*
 * Copyright (c) 2026 Pantacor Ltd.
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
#ifndef PV_AGENT_CTRL_CLIENT_H
#define PV_AGENT_CTRL_CLIENT_H

#include <event2/event.h>

/* Default pv-ctrl socket path (accessible from management container) */
#define PV_CTRL_SOCKET "/pantavisor/pv-ctrl"

/*
 * Callback type for ctrl_request results.
 * status: HTTP status code (200, 404, etc.) or -1 on connection error
 * body: response body (may be NULL on error), caller must NOT free
 * body_len: length of body
 * ctx: user context passed to ctrl_request
 */
typedef void (*ctrl_response_cb)(int status, const char *body, size_t body_len,
				 void *ctx);

/*
 * Send an async HTTP request to pv-ctrl via Unix socket.
 * Pattern: bufferevent connect, send HTTP/1.0, parse response, call cb.
 *
 * base: libevent event base
 * method: HTTP method ("GET", "PUT", etc.)
 * path: API path (e.g. "/containers")
 * body: request body (NULL for GET)
 * body_len: length of body
 * cb: callback to invoke with response
 * ctx: user context for callback
 *
 * Returns 0 on success (connection initiated), -1 on failure.
 */
int ctrl_request(struct event_base *base, const char *method, const char *path,
		 const char *body, size_t body_len, ctrl_response_cb cb,
		 void *ctx);

#endif /* PV_AGENT_CTRL_CLIENT_H */
