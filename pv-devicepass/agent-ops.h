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
#ifndef PV_AGENT_OPS_H
#define PV_AGENT_OPS_H

#include <stddef.h>
#include <event2/event.h>

/*
 * Generic result callback — used by both HTTP and tunnel callers.
 * status: HTTP status code (200, 404, etc.) or negative on error
 * body: response body (JSON), caller must NOT free
 * body_len: length of body
 * caller_ctx: opaque context passed through from dispatch
 */
typedef void (*op_result_cb)(int status, const char *body, size_t body_len,
			     void *caller_ctx);

/*
 * Dispatch a request to the appropriate operation handler.
 *
 * method: "GET", "PUT", etc.
 * path: "/containers", "/skills", "/services/foo/bar", etc.
 * body/body_len: request body (NULL/0 for GET)
 * cb: called with result
 * caller_ctx: opaque context passed to cb
 *
 * Returns 0 on success (operation initiated), -1 on dispatch failure.
 */
int agent_op_dispatch(struct event_base *base, const char *method,
		      const char *path, const char *body, size_t body_len,
		      op_result_cb cb, void *caller_ctx);

#endif /* PV_AGENT_OPS_H */
