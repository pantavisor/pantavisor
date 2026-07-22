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
#ifndef PV_EVENT_REST_H
#define PV_EVENT_REST_H

#include <event2/event.h>
#include <event2/http.h>

int pv_event_rest_init(void);
void pv_event_rest_cleanup(void);

// out_req, when non-NULL, receives the request handle on success (untouched
// on failure); NULL-tolerant for callers that never need to cancel
int pv_event_rest_send_by_components(
	enum evhttp_cmd_type op, const char *host, int port,
	const char *endpoint, const char *token, const char *body,
	void (*chunk_cb)(struct evhttp_request *, void *),
	void (*done_cb)(struct evhttp_request *, void *), void *ctx,
	struct evhttp_request **out_req, size_t rate_limit_bytes_per_sec);
int pv_event_rest_send_by_url(enum evhttp_cmd_type op, const char *url,
			      void (*chunk_cb)(struct evhttp_request *, void *),
			      void (*done_cb)(struct evhttp_request *, void *),
			      void *ctx, struct evhttp_request **out_req,
			      size_t rate_limit_bytes_per_sec);

// drops any download pacer for req, then evhttp_cancel_request()s it
void pv_event_rest_cancel_request(struct evhttp_request *req);

int pv_event_rest_recv_buffer(struct evhttp_request *req, char **buf,
			      size_t max_len);

int pv_event_rest_recv_chunk_path(struct evhttp_request *req, const char *path,
				  size_t *written);
int pv_event_rest_recv_done_path(struct evhttp_request *req, const char *path,
				 size_t *written);

#endif
