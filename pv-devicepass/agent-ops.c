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
 * Transport-agnostic operation dispatch for pv-devicepass.
 * Each operation is a thin wrapper around ctrl_request or local data,
 * callable from both HTTP handlers and the tunnel client.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/buffer.h>

#include "agent-ops.h"
#include "ctrl-client.h"
#include "proxy.h"

/* --- ctrl relay: adapts ctrl_response_cb to op_result_cb --- */

struct ctrl_relay {
	op_result_cb cb;
	void *caller_ctx;
};

static void ctrl_to_op_cb(int status, const char *body, size_t body_len,
			   void *ctx)
{
	struct ctrl_relay *relay = ctx;

	if (status < 0)
		relay->cb(502, "{\"error\":\"pv-ctrl unavailable\"}", 30,
			  relay->caller_ctx);
	else
		relay->cb(status, body, body_len, relay->caller_ctx);

	free(relay);
}

/* --- Individual operations --- */

static int op_get_containers(struct event_base *base, op_result_cb cb,
			     void *ctx)
{
	struct ctrl_relay *relay = calloc(1, sizeof(*relay));
	if (!relay)
		return -1;
	relay->cb = cb;
	relay->caller_ctx = ctx;

	if (ctrl_request(base, "GET", "/containers", NULL, 0, ctrl_to_op_cb,
			 relay) < 0) {
		cb(502, "{\"error\":\"pv-ctrl unavailable\"}", 30, ctx);
		free(relay);
	}
	return 0;
}

static int op_get_status(struct event_base *base, op_result_cb cb, void *ctx)
{
	struct ctrl_relay *relay = calloc(1, sizeof(*relay));
	if (!relay)
		return -1;
	relay->cb = cb;
	relay->caller_ctx = ctx;

	if (ctrl_request(base, "GET", "/buildinfo", NULL, 0, ctrl_to_op_cb,
			 relay) < 0) {
		cb(502, "{\"error\":\"pv-ctrl unavailable\"}", 30, ctx);
		free(relay);
	}
	return 0;
}

static int op_get_daemons(struct event_base *base, op_result_cb cb, void *ctx)
{
	struct ctrl_relay *relay = calloc(1, sizeof(*relay));
	if (!relay)
		return -1;
	relay->cb = cb;
	relay->caller_ctx = ctx;

	if (ctrl_request(base, "GET", "/daemons", NULL, 0, ctrl_to_op_cb,
			 relay) < 0) {
		cb(502, "{\"error\":\"pv-ctrl unavailable\"}", 30, ctx);
		free(relay);
	}
	return 0;
}

static int op_put_container(struct event_base *base, const char *name,
			    const char *body, size_t body_len, op_result_cb cb,
			    void *ctx)
{
	char ctrl_path[512];
	snprintf(ctrl_path, sizeof(ctrl_path), "/containers/%s", name);

	struct ctrl_relay *relay = calloc(1, sizeof(*relay));
	if (!relay)
		return -1;
	relay->cb = cb;
	relay->caller_ctx = ctx;

	if (ctrl_request(base, "PUT", ctrl_path, body, body_len, ctrl_to_op_cb,
			 relay) < 0) {
		cb(502, "{\"error\":\"pv-ctrl unavailable\"}", 30, ctx);
		free(relay);
	}
	return 0;
}

static int op_get_skills(op_result_cb cb, void *ctx)
{
	/* Build JSON from global routing table */
	struct evbuffer *buf = evbuffer_new();
	if (!buf) {
		cb(500, "{\"error\":\"internal error\"}", 25, ctx);
		return 0;
	}

	evbuffer_add_printf(buf, "[");
	int first = 1;
	struct service_route *r;
	for (r = g_routes; r; r = r->next) {
		evbuffer_add_printf(buf,
				    "%s{\"name\":\"%s\",\"type\":\"%s\","
				    "\"provider_pid\":%d}",
				    first ? "" : ",", r->name, r->type,
				    r->provider_pid);
		first = 0;
	}
	evbuffer_add_printf(buf, "]");

	size_t len = evbuffer_get_length(buf);
	char *json = malloc(len + 1);
	if (!json) {
		evbuffer_free(buf);
		cb(500, "{\"error\":\"internal error\"}", 25, ctx);
		return 0;
	}
	evbuffer_copyout(buf, json, len);
	json[len] = '\0';
	evbuffer_free(buf);

	cb(200, json, len, ctx);
	free(json);
	return 0;
}

/* --- Dispatch --- */

int agent_op_dispatch(struct event_base *base, const char *method,
		      const char *path, const char *body, size_t body_len,
		      op_result_cb cb, void *caller_ctx)
{
	if (!method || !path) {
		cb(400, "{\"error\":\"bad request\"}", 22, caller_ctx);
		return 0;
	}

	/* GET /containers */
	if (!strcmp(method, "GET") && !strcmp(path, "/containers"))
		return op_get_containers(base, cb, caller_ctx);

	/* GET /status */
	if (!strcmp(method, "GET") && !strcmp(path, "/status"))
		return op_get_status(base, cb, caller_ctx);

	/* GET /skills */
	if (!strcmp(method, "GET") && !strcmp(path, "/skills"))
		return op_get_skills(cb, caller_ctx);

	/* GET /daemons */
	if (!strcmp(method, "GET") && !strcmp(path, "/daemons"))
		return op_get_daemons(base, cb, caller_ctx);

	/* PUT /containers/{name} */
	if (!strcmp(method, "PUT") && !strncmp(path, "/containers/", 12) &&
	    strlen(path) > 12)
		return op_put_container(base, path + 12, body, body_len, cb,
					caller_ctx);

	/* /services/{name}/... — proxy to provider */
	if (!strncmp(path, "/services/", 10))
		return proxy_op_service(base, method, path, body, body_len, cb,
					caller_ctx);

	cb(404, "{\"error\":\"not found\"}", 20, caller_ctx);
	return 0;
}
