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
 * Reverse proxy for service requests.
 * Pattern adapted from pantavisor/xconnect/plugins/rest.c proxy sessions.
 * Routes /services/{name}/... to provider Unix sockets via /proc/PID/root/.
 * Injects X-DevicePass-Verified-* identity headers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <event2/event.h>
#include <event2/keyvalq_struct.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <picohttpparser.h>

#include "proxy.h"

/* --- Routing table management --- */

void routes_free(struct service_route **head)
{
	struct service_route *r = *head;
	while (r) {
		struct service_route *next = r->next;
		free(r->name);
		free(r->type);
		free(r->provider_socket);
		free(r);
		r = next;
	}
	*head = NULL;
}

int routes_add(struct service_route **head, const char *name, const char *type,
	       int provider_pid, const char *provider_socket)
{
	struct service_route *r = calloc(1, sizeof(*r));
	if (!r)
		return -1;

	r->name = strdup(name);
	r->type = strdup(type);
	r->provider_pid = provider_pid;
	r->provider_socket = strdup(provider_socket);

	if (!r->name || !r->type || !r->provider_socket) {
		free(r->name);
		free(r->type);
		free(r->provider_socket);
		free(r);
		return -1;
	}

	r->next = *head;
	*head = r;
	return 0;
}

struct service_route *routes_find(struct service_route *head, const char *name)
{
	struct service_route *r;
	for (r = head; r; r = r->next) {
		if (!strcmp(r->name, name))
			return r;
	}
	return NULL;
}

/* --- Op-based proxy response context (transport-agnostic) --- */

struct proxy_op_ctx {
	op_result_cb cb;
	void *caller_ctx;
	struct evbuffer *accum;
};

static void proxy_op_read_cb(struct bufferevent *bev, void *arg)
{
	struct proxy_op_ctx *ctx = arg;
	struct evbuffer *input = bufferevent_get_input(bev);
	evbuffer_add_buffer(ctx->accum, input);
}

static void proxy_op_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct proxy_op_ctx *ctx = arg;

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		size_t len = evbuffer_get_length(ctx->accum);

		if (len > 0) {
			char *data = malloc(len + 1);
			if (!data) {
				ctx->cb(500,
					"{\"error\":\"internal error\"}",
					25, ctx->caller_ctx);
				goto cleanup;
			}

			evbuffer_copyout(ctx->accum, data, len);
			data[len] = '\0';

			/* Parse HTTP response from provider */
			const char *msg;
			int minor_version, status;
			struct phr_header headers[64];
			size_t msg_len, num_headers = 64;
			int pret = phr_parse_response(data, len,
						      &minor_version, &status,
						      &msg, &msg_len, headers,
						      &num_headers, 0);

			if (pret > 0) {
				ctx->cb(status, data + pret, len - pret,
					ctx->caller_ctx);
			} else {
				ctx->cb(502, "{\"error\":\"bad gateway\"}",
					22, ctx->caller_ctx);
			}

			free(data);
		} else if (events & BEV_EVENT_ERROR) {
			ctx->cb(502, "{\"error\":\"bad gateway\"}", 22,
				ctx->caller_ctx);
		} else {
			ctx->cb(502, "{\"error\":\"empty response\"}", 25,
				ctx->caller_ctx);
		}

	cleanup:
		evbuffer_free(ctx->accum);
		bufferevent_free(bev);
		free(ctx);
	}
}

/*
 * Build an HTTP/1.0 request to send to the provider (transport-agnostic version).
 * Takes explicit method/path/body instead of evhttp_request.
 */
static int proxy_build_raw_request(struct evbuffer *out, const char *method,
				   const char *path_suffix, const char *body,
				   size_t body_len)
{
	evbuffer_add_printf(out, "%s %s HTTP/1.0\r\n", method,
			    (path_suffix && path_suffix[0]) ? path_suffix :
							      "/");
	evbuffer_add_printf(out, "Host: localhost\r\n");

	if (body && body_len > 0)
		evbuffer_add_printf(out, "Content-Type: application/json\r\n"
					 "Content-Length: %zu\r\n",
				    body_len);

	/* Inject identity headers (tunnel-sourced requests) */
	evbuffer_add_printf(out, "X-DevicePass-Request-Source: tunnel\r\n");
	evbuffer_add_printf(out, "X-DevicePass-Verified-Device: %s\r\n",
			    g_device_address ? g_device_address :
					       "pv-devicepass");
	if (g_guardian_address)
		evbuffer_add_printf(
			out, "X-DevicePass-Verified-Guardian: %s\r\n",
			g_guardian_address);

	char timestamp[64];
	time_t now = time(NULL);
	struct tm *tm = gmtime(&now);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);
	evbuffer_add_printf(out, "X-DevicePass-Verified-At: %s\r\n", timestamp);

	evbuffer_add_printf(out, "\r\n");

	if (body && body_len > 0)
		evbuffer_add(out, body, body_len);

	return 0;
}

/*
 * Transport-agnostic service proxy.
 * Parses service name from path, connects to provider, relays request,
 * calls cb with response body.
 */
int proxy_op_service(struct event_base *base, const char *method,
		     const char *path, const char *body, size_t body_len,
		     op_result_cb cb, void *caller_ctx)
{
	/* Parse service name from /services/{name}/... */
	if (!path || strncmp(path, "/services/", 10) != 0) {
		cb(400, "{\"error\":\"bad request\"}", 22, caller_ctx);
		return 0;
	}
	const char *p = path + 10;

	const char *slash = strchr(p, '/');
	size_t name_len = slash ? (size_t)(slash - p) : strlen(p);
	if (name_len == 0 || name_len > 255) {
		cb(400, "{\"error\":\"bad request\"}", 22, caller_ctx);
		return 0;
	}

	char name[256];
	memcpy(name, p, name_len);
	name[name_len] = '\0';

	const char *path_suffix = slash ? slash : "/";

	/* Look up route */
	struct service_route *route = routes_find(g_routes, name);
	if (!route) {
		cb(404, "{\"error\":\"service not found\"}", 28, caller_ctx);
		return 0;
	}

	/* Build provider socket path via /proc/PID/root/ */
	char provider_path[512];
	if (route->provider_pid > 0) {
		snprintf(provider_path, sizeof(provider_path),
			 "/proc/%d/root%s", route->provider_pid,
			 route->provider_socket);
	} else {
		strncpy(provider_path, route->provider_socket,
			sizeof(provider_path) - 1);
		provider_path[sizeof(provider_path) - 1] = '\0';
	}

	/* Connect to provider */
	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

	struct bufferevent *be_provider =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!be_provider) {
		cb(502, "{\"error\":\"bad gateway\"}", 22, caller_ctx);
		return 0;
	}

	if (bufferevent_socket_connect(be_provider, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		fprintf(stderr, "proxy: connect to %s failed: %s\n",
			provider_path, strerror(errno));
		bufferevent_free(be_provider);
		cb(502, "{\"error\":\"bad gateway\"}", 22, caller_ctx);
		return 0;
	}

	/* Allocate response context */
	struct proxy_op_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		bufferevent_free(be_provider);
		cb(500, "{\"error\":\"internal error\"}", 25, caller_ctx);
		return 0;
	}

	ctx->cb = cb;
	ctx->caller_ctx = caller_ctx;
	ctx->accum = evbuffer_new();
	if (!ctx->accum) {
		bufferevent_free(be_provider);
		free(ctx);
		cb(500, "{\"error\":\"internal error\"}", 25, caller_ctx);
		return 0;
	}

	/* Build and queue request to provider */
	struct evbuffer *out = bufferevent_get_output(be_provider);
	proxy_build_raw_request(out, method, path_suffix, body, body_len);

	/* Set up read/event callbacks */
	bufferevent_setcb(be_provider, proxy_op_read_cb, NULL,
			  proxy_op_event_cb, ctx);
	bufferevent_enable(be_provider, EV_READ | EV_WRITE);
	return 0;
}

/* --- HTTP proxy response context (legacy, used by proxy_service_request) --- */

struct proxy_response_ctx {
	struct evhttp_request *req;
	struct evbuffer *accum;
};

static void provider_read_cb(struct bufferevent *bev, void *arg)
{
	struct proxy_response_ctx *ctx = arg;
	struct evbuffer *input = bufferevent_get_input(bev);
	evbuffer_add_buffer(ctx->accum, input);
}

static void provider_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct proxy_response_ctx *ctx = arg;

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		size_t len = evbuffer_get_length(ctx->accum);

		if (len > 0) {
			char *data = malloc(len + 1);
			if (!data) {
				evhttp_send_error(ctx->req, 500,
						  "Internal Server Error");
				goto cleanup;
			}

			evbuffer_copyout(ctx->accum, data, len);
			data[len] = '\0';

			/* Parse HTTP response from provider */
			const char *msg;
			int minor_version, status;
			struct phr_header headers[64];
			size_t msg_len, num_headers = 64;
			int pret = phr_parse_response(data, len,
						      &minor_version, &status,
						      &msg, &msg_len, headers,
						      &num_headers, 0);

			if (pret > 0) {
				struct evbuffer *reply = evbuffer_new();
				if (reply) {
					evbuffer_add(reply, data + pret,
						     len - pret);

					/* Forward provider headers */
					struct evkeyvalq *out_headers =
						evhttp_request_get_output_headers(
							ctx->req);
					for (size_t i = 0; i < num_headers;
					     i++) {
						char key[256], val[1024];
						snprintf(key, sizeof(key),
							 "%.*s",
							 (int)headers[i]
								 .name_len,
							 headers[i].name);
						snprintf(val, sizeof(val),
							 "%.*s",
							 (int)headers[i]
								 .value_len,
							 headers[i].value);
						evhttp_add_header(out_headers,
								  key, val);
					}

					evhttp_send_reply(ctx->req, status,
							  "OK", reply);
					evbuffer_free(reply);
				} else {
					evhttp_send_error(
						ctx->req, 500,
						"Internal Server Error");
				}
			} else {
				evhttp_send_error(ctx->req, 502,
						  "Bad Gateway");
			}

			free(data);
		} else if (events & BEV_EVENT_ERROR) {
			evhttp_send_error(ctx->req, 502, "Bad Gateway");
		} else {
			evhttp_send_error(ctx->req, 502, "Empty Response");
		}

	cleanup:
		evbuffer_free(ctx->accum);
		bufferevent_free(bev);
		free(ctx);
	}
}

/*
 * Build the HTTP request to send to the provider.
 * Injects X-DevicePass-Verified-* identity headers.
 */
static int proxy_build_request(struct evbuffer *out, struct evhttp_request *req,
			       const char *path_suffix)
{
	const char *method_str;
	switch (evhttp_request_get_command(req)) {
	case EVHTTP_REQ_GET:
		method_str = "GET";
		break;
	case EVHTTP_REQ_POST:
		method_str = "POST";
		break;
	case EVHTTP_REQ_PUT:
		method_str = "PUT";
		break;
	case EVHTTP_REQ_DELETE:
		method_str = "DELETE";
		break;
	default:
		method_str = "GET";
		break;
	}

	/* Request body */
	struct evbuffer *body = evhttp_request_get_input_buffer(req);
	size_t body_len = body ? evbuffer_get_length(body) : 0;

	/* Request line */
	evbuffer_add_printf(out, "%s %s HTTP/1.0\r\n", method_str,
			    path_suffix[0] ? path_suffix : "/");

	/* Forward original headers, skip hop-by-hop */
	struct evkeyvalq *in_headers = evhttp_request_get_input_headers(req);
	struct evkeyval *header;
	TAILQ_FOREACH (header, in_headers, next) {
		if (!strcasecmp(header->key, "Connection") ||
		    !strcasecmp(header->key, "Transfer-Encoding") ||
		    !strcasecmp(header->key, "Content-Length"))
			continue;
		evbuffer_add_printf(out, "%s: %s\r\n", header->key,
				    header->value);
	}

	/* Content-Length if body present */
	if (body_len > 0) {
		evbuffer_add_printf(out, "Content-Length: %zu\r\n", body_len);
	}

	/* Inject identity headers */
	evbuffer_add_printf(out, "X-DevicePass-Request-Source: local\r\n");
	evbuffer_add_printf(out, "X-DevicePass-Verified-Device: %s\r\n",
			    g_device_address ? g_device_address :
					       "pv-devicepass");
	if (g_guardian_address)
		evbuffer_add_printf(
			out, "X-DevicePass-Verified-Guardian: %s\r\n",
			g_guardian_address);

	/* Timestamp */
	char timestamp[64];
	time_t now = time(NULL);
	struct tm *tm = gmtime(&now);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", tm);
	evbuffer_add_printf(out, "X-DevicePass-Verified-At: %s\r\n", timestamp);

	evbuffer_add_printf(out, "\r\n");

	/* Forward request body */
	if (body && body_len > 0) {
		evbuffer_add_buffer(out, body);
	}

	return 0;
}

/*
 * Handle /services/{name}/... requests.
 * Look up route, connect to provider socket, relay bidirectionally.
 */
void proxy_service_request(struct evhttp_request *req, void *arg)
{
	const char *uri = evhttp_request_get_uri(req);

	/* Parse service name from /services/{name}/... */
	if (strncmp(uri, "/services/", 10) != 0) {
		evhttp_send_error(req, 400, "Bad Request");
		return;
	}
	const char *p = uri + 10;

	const char *slash = strchr(p, '/');
	size_t name_len = slash ? (size_t)(slash - p) : strlen(p);
	if (name_len == 0 || name_len > 255) {
		evhttp_send_error(req, 400, "Bad Request");
		return;
	}

	char name[256];
	memcpy(name, p, name_len);
	name[name_len] = '\0';

	const char *path_suffix = slash ? slash : "/";

	/* Look up route */
	struct service_route *route = routes_find(g_routes, name);
	if (!route) {
		evhttp_send_error(req, 404, "Service Not Found");
		return;
	}

	/* Build provider socket path via /proc/PID/root/ */
	char provider_path[512];
	if (route->provider_pid > 0) {
		snprintf(provider_path, sizeof(provider_path),
			 "/proc/%d/root%s", route->provider_pid,
			 route->provider_socket);
	} else {
		strncpy(provider_path, route->provider_socket,
			sizeof(provider_path) - 1);
		provider_path[sizeof(provider_path) - 1] = '\0';
	}

	/* Connect to provider */
	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

	struct bufferevent *be_provider =
		bufferevent_socket_new(g_base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!be_provider) {
		evhttp_send_error(req, 502, "Bad Gateway");
		return;
	}

	if (bufferevent_socket_connect(be_provider, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		fprintf(stderr, "proxy: connect to %s failed: %s\n",
			provider_path, strerror(errno));
		bufferevent_free(be_provider);
		evhttp_send_error(req, 502, "Bad Gateway");
		return;
	}

	/* Allocate response context */
	struct proxy_response_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		bufferevent_free(be_provider);
		evhttp_send_error(req, 500, "Internal Server Error");
		return;
	}

	ctx->req = req;
	ctx->accum = evbuffer_new();
	if (!ctx->accum) {
		bufferevent_free(be_provider);
		free(ctx);
		evhttp_send_error(req, 500, "Internal Server Error");
		return;
	}

	/* Build and queue request to provider */
	struct evbuffer *out = bufferevent_get_output(be_provider);
	proxy_build_request(out, req, path_suffix);

	/* Set up read/event callbacks */
	bufferevent_setcb(be_provider, provider_read_cb, NULL,
			  provider_event_cb, ctx);
	bufferevent_enable(be_provider, EV_READ | EV_WRITE);
}
