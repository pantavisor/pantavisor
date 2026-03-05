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
#ifndef PV_AGENT_PROXY_H
#define PV_AGENT_PROXY_H

#include <stddef.h>
#include <event2/event.h>
#include <event2/http.h>

#include "agent-ops.h"

/* Service route entry discovered from xconnect-graph */
struct service_route {
	char *name;
	char *type;
	int provider_pid;
	char *provider_socket;
	struct service_route *next;
};

/* Global routing table head (owned by pv-devicepass.c) */
extern struct service_route *g_routes;
extern struct event_base *g_base;

/* Device identity (set by pv-devicepass.c from identity dir / tunnel auth) */
extern char *g_device_address;
extern char *g_guardian_address;

/*
 * Handle proxied service requests: /services/{name}/...
 * Looks up route, connects to provider socket via /proc/PID/root/,
 * injects identity headers, relays bidirectionally.
 */
void proxy_service_request(struct evhttp_request *req, void *arg);

/*
 * Free all entries in the routing table.
 */
void routes_free(struct service_route **head);

/*
 * Add a route to the routing table. Duplicates name/type/socket internally.
 */
int routes_add(struct service_route **head, const char *name, const char *type,
	       int provider_pid, const char *provider_socket);

/*
 * Look up a service route by name.
 */
struct service_route *routes_find(struct service_route *head, const char *name);

/*
 * Transport-agnostic service proxy operation.
 * Parses service name from path (/services/{name}/...),
 * connects to provider, relays request, calls cb with response.
 */
int proxy_op_service(struct event_base *base, const char *method,
		     const char *path, const char *body, size_t body_len,
		     op_result_cb cb, void *caller_ctx);

#endif /* PV_AGENT_PROXY_H */
