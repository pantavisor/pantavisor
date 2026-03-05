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

/*
 * pv-ctrl Unix socket client.
 * Pattern copied from pantavisor/xconnect/main.c fetch_graph()/ctrl_read_cb()/ctrl_event_cb().
 * Each request creates a bufferevent, sends HTTP/1.0, parses response with picohttpparser.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <picohttpparser.h>

#include "ctrl-client.h"

struct ctrl_ctx {
	ctrl_response_cb cb;
	void *user_ctx;
	char *accum;
	size_t accum_len;
};

static void ctrl_read_cb(struct bufferevent *bev, void *arg)
{
	struct ctrl_ctx *ctx = arg;
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t chunk_len = evbuffer_get_length(input);

	/* Accumulate data — pv-ctrl sends full response then closes */
	char *new_accum = realloc(ctx->accum, ctx->accum_len + chunk_len + 1);
	if (!new_accum) {
		fprintf(stderr, "ctrl-client: realloc failed\n");
		return;
	}
	ctx->accum = new_accum;
	evbuffer_remove(input, ctx->accum + ctx->accum_len, chunk_len);
	ctx->accum_len += chunk_len;
	ctx->accum[ctx->accum_len] = '\0';
}

static void ctrl_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct ctrl_ctx *ctx = arg;

	if (events & BEV_EVENT_CONNECTED) {
		/* Connection established — request already queued in output buffer */
		return;
	}

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		if (events & BEV_EVENT_ERROR && !ctx->accum_len) {
			fprintf(stderr, "ctrl-client: connection error: %s\n",
				strerror(errno));
			if (ctx->cb)
				ctx->cb(-1, NULL, 0, ctx->user_ctx);
			goto cleanup;
		}

		/* Parse the accumulated HTTP response */
		if (ctx->accum && ctx->accum_len > 0) {
			const char *msg;
			int minor_version, status;
			struct phr_header headers[64];
			size_t msg_len, num_headers = 64;

			int pret = phr_parse_response(ctx->accum,
						      ctx->accum_len,
						      &minor_version, &status,
						      &msg, &msg_len, headers,
						      &num_headers, 0);

			if (pret > 0 && ctx->cb) {
				ctx->cb(status, ctx->accum + pret,
					ctx->accum_len - pret, ctx->user_ctx);
			} else if (ctx->cb) {
				fprintf(stderr,
					"ctrl-client: parse error pret=%d\n",
					pret);
				ctx->cb(-1, NULL, 0, ctx->user_ctx);
			}
		} else if (ctx->cb) {
			ctx->cb(-1, NULL, 0, ctx->user_ctx);
		}

	cleanup:
		bufferevent_free(bev);
		free(ctx->accum);
		free(ctx);
	}
}

int ctrl_request(struct event_base *base, const char *method, const char *path,
		 const char *body, size_t body_len, ctrl_response_cb cb,
		 void *ctx)
{
	struct ctrl_ctx *cctx = calloc(1, sizeof(*cctx));
	if (!cctx)
		return -1;

	cctx->cb = cb;
	cctx->user_ctx = ctx;

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, PV_CTRL_SOCKET, sizeof(sun.sun_path) - 1);

	struct bufferevent *bev =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		free(cctx);
		return -1;
	}

	bufferevent_setcb(bev, ctrl_read_cb, NULL, ctrl_event_cb, cctx);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	/* Queue the HTTP request in the output buffer before connect */
	struct evbuffer *out = bufferevent_get_output(bev);
	if (body && body_len > 0) {
		evbuffer_add_printf(
			out,
			"%s %s HTTP/1.0\r\n"
			"Host: localhost\r\n"
			"Content-Type: application/json\r\n"
			"Content-Length: %zu\r\n"
			"\r\n",
			method, path, body_len);
		evbuffer_add(out, body, body_len);
	} else {
		evbuffer_add_printf(out,
				    "%s %s HTTP/1.0\r\n"
				    "Host: localhost\r\n"
				    "\r\n",
				    method, path);
	}

	if (bufferevent_socket_connect(bev, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		fprintf(stderr, "ctrl-client: connect failed: %s\n",
			strerror(errno));
		bufferevent_free(bev);
		free(cctx);
		return -1;
	}

	return 0;
}
