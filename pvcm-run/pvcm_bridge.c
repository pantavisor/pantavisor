/*
 * pvcm-run HTTP bridge
 *
 * Two directions:
 *   MCU → Linux: MCU sends HTTP_REQ/DATA/END, proxy forwards to a
 *     local backend (unix socket or TCP), sends response back.
 *   Linux → MCU: evhttp listener accepts requests, forwards to MCU
 *     as INVOKE frames, waits for MCU reply asynchronously.
 *
 * All I/O is event-driven via libevent. No threads.
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE  /* for strcasestr */

#include "pvcm_bridge.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>

/* ---- Route table ---- */

static struct http_route routes[PVCM_MAX_ROUTES];
static int num_routes;

int pvcm_bridge_add_route(const char *spec)
{
	if (num_routes >= PVCM_MAX_ROUTES)
		return -1;

	/* parse "name=unix:/path" or "name=tcp:host:port" */
	const char *eq = strchr(spec, '=');
	if (!eq)
		return -1;

	struct http_route *r = &routes[num_routes];
	memset(r, 0, sizeof(*r));

	size_t nlen = eq - spec;
	if (nlen >= sizeof(r->name))
		nlen = sizeof(r->name) - 1;
	memcpy(r->name, spec, nlen);
	r->name[nlen] = '\0';

	const char *val = eq + 1;
	if (strncmp(val, "unix:", 5) == 0) {
		strncpy(r->unix_path, val + 5, sizeof(r->unix_path) - 1);
	} else if (strncmp(val, "tcp:", 4) == 0) {
		const char *hp = val + 4;
		const char *colon = strrchr(hp, ':');
		if (!colon)
			return -1;
		size_t hlen = colon - hp;
		if (hlen >= sizeof(r->tcp_host))
			hlen = sizeof(r->tcp_host) - 1;
		memcpy(r->tcp_host, hp, hlen);
		r->tcp_host[hlen] = '\0';
		r->tcp_port = atoi(colon + 1);
	} else {
		return -1;
	}

	fprintf(stdout, "[bridge] route: %s -> %s%s\n",
		r->name,
		r->unix_path[0] ? "unix:" : "tcp:",
		r->unix_path[0] ? r->unix_path : r->tcp_host);

	num_routes++;
	return 0;
}

static const struct http_route *find_route(const char *hostname)
{
	if (!hostname)
		return NULL;

	/* strip .pvlocal suffix if present */
	char name[64];
	strncpy(name, hostname, sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	char *suffix = strstr(name, ".pvlocal");
	if (suffix)
		*suffix = '\0';
	/* strip port if present (Host: foo.pvlocal:80) */
	char *colon = strchr(name, ':');
	if (colon)
		*colon = '\0';

	for (int i = 0; i < num_routes; i++) {
		if (strcmp(routes[i].name, name) == 0)
			return &routes[i];
	}
	return NULL;
}

/* Extract Host header value from raw headers string */
static const char *extract_host(const char *headers, char *buf, size_t buf_size)
{
	if (!headers)
		return NULL;

	const char *h = strcasestr(headers, "Host:");
	if (!h)
		return NULL;

	h += 5;
	while (*h == ' ' || *h == '\t') h++;

	size_t len = 0;
	while (h[len] && h[len] != '\r' && h[len] != '\n' && len < buf_size - 1)
		len++;
	memcpy(buf, h, len);
	buf[len] = '\0';
	return buf;
}

/* Connect to a backend — returns fd or -1 */
static int connect_backend(const struct http_route *route)
{
	if (route->unix_path[0]) {
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd < 0)
			return -1;
		struct sockaddr_un addr = { .sun_family = AF_UNIX };
		strncpy(addr.sun_path, route->unix_path,
			sizeof(addr.sun_path) - 1);
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			fprintf(stderr, "[bridge] connect unix:%s: %s\n",
				route->unix_path, strerror(errno));
			close(fd);
			return -1;
		}
		return fd;
	} else {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0)
			return -1;
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = htons(route->tcp_port),
		};
		inet_pton(AF_INET, route->tcp_host, &addr.sin_addr);
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
			fprintf(stderr, "[bridge] connect %s:%d: %s\n",
				route->tcp_host, route->tcp_port,
				strerror(errno));
			close(fd);
			return -1;
		}
		return fd;
	}
}

/* ---- HTTP client (MCU → Linux backend) ---- */

/*
 * Send an HTTP request to a backend and read the response.
 * Connects to the route's backend or falls back to host:port.
 * This is synchronous — acceptable for local sockets (sub-ms).
 */
/*
 * Send HTTP request to backend. Returns malloc'd body (caller frees).
 * *out_headers is also malloc'd if non-NULL.
 * Returns body length, or -1 on error.
 */
static int http_request(const char *method_str,
			const struct http_route *route,
			const char *host, int port,
			const char *path,
			const char *req_body, size_t req_body_len,
			char **out_body, int *resp_status,
			char **out_headers)
{
	int fd;

	if (route) {
		fd = connect_backend(route);
	} else {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd >= 0) {
			struct sockaddr_in addr = {
				.sin_family = AF_INET,
				.sin_port = htons(port),
			};
			inet_pton(AF_INET, host, &addr.sin_addr);
			if (connect(fd, (struct sockaddr *)&addr,
				    sizeof(addr)) < 0) {
				close(fd);
				fd = -1;
			}
		}
	}
	if (fd < 0)
		return -1;

	/* unix sockets require Host: localhost */
	const char *host_hdr = host;
	if (route) {
		if (route->unix_path[0])
			host_hdr = "localhost";
		else
			host_hdr = route->tcp_host;
	}

	char req_line[512];
	char cl[32];
	if (req_body_len > 0)
		snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n",
			 req_body_len);
	int n = snprintf(req_line, sizeof(req_line),
			 "%s %s HTTP/1.1\r\nHost: %s\r\n"
			 "Connection: close\r\n"
			 "%s"
			 "\r\n",
			 method_str, path, host_hdr,
			 req_body_len > 0 ? cl : "");

	write(fd, req_line, n);
	if (req_body && req_body_len > 0)
		write(fd, req_body, req_body_len);

	/* read response with timeout — dynamic buffer, no size limit */
	struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	size_t raw_cap = 4096;
	char *raw = malloc(raw_cap);
	if (!raw) { close(fd); return -1; }

	size_t total = 0;
	for (;;) {
		if (total + 1024 > raw_cap) {
			raw_cap *= 2;
			char *tmp = realloc(raw, raw_cap);
			if (!tmp) break;
			raw = tmp;
		}
		ssize_t r = read(fd, raw + total, raw_cap - total - 1);
		if (r <= 0)
			break;
		total += r;
		raw[total] = '\0';

		/* check if we have the full response */
		char *hdr_end = strstr(raw, "\r\n\r\n");
		if (hdr_end) {
			char *clh = strcasestr(raw, "Content-Length:");
			if (clh && clh < hdr_end) {
				size_t expected = atoi(clh + 15);
				size_t body_off = (hdr_end + 4) - raw;
				if (total - body_off >= expected)
					break;
			}
		}
	}
	close(fd);

	if (total == 0) { free(raw); return -1; }

	/* parse HTTP response */
	char *hdr_end = strstr(raw, "\r\n\r\n");
	int hdr_sep_len = 4;
	if (!hdr_end) {
		hdr_end = strstr(raw, "\n\n");
		hdr_sep_len = 2;
	}
	if (!hdr_end) { free(raw); return -1; }

	char *sp = strchr(raw, ' ');
	if (sp)
		*resp_status = atoi(sp + 1);

	/* extract headers — malloc'd */
	if (out_headers) {
		char *hdr_start = strstr(raw, "\r\n");
		if (hdr_start) {
			size_t hlen = hdr_end - hdr_start - 2;
			*out_headers = malloc(hlen + 1);
			if (*out_headers) {
				memcpy(*out_headers, hdr_start + 2, hlen);
				(*out_headers)[hlen] = '\0';
			}
		} else {
			*out_headers = NULL;
		}
	}

	/* extract body — malloc'd */
	char *body_start = hdr_end + hdr_sep_len;
	size_t body_len = total - (body_start - raw);
	*out_body = malloc(body_len + 1);
	if (*out_body) {
		memcpy(*out_body, body_start, body_len);
		(*out_body)[body_len] = '\0';
	}

	free(raw);
	return (int)body_len;
}

static const char *method_to_str(uint8_t method)
{
	switch (method) {
	case PVCM_HTTP_GET:    return "GET";
	case PVCM_HTTP_POST:   return "POST";
	case PVCM_HTTP_PUT:    return "PUT";
	case PVCM_HTTP_DELETE: return "DELETE";
	case PVCM_HTTP_HEAD:   return "HEAD";
	case PVCM_HTTP_PATCH:  return "PATCH";
	default:               return "GET";
	}
}

/*
 * Send arbitrary data as HTTP_DATA frames.
 * Concatenates multiple buffers (e.g. headers + body) into
 * a single DATA stream. Chunks to PVCM_MAX_CHUNK_SIZE per frame.
 */
static void send_data_stream(struct pvcm_transport *t, uint8_t stream_id,
			     const char *buf1, size_t len1,
			     const char *buf2, size_t len2)
{
	/* concatenate into one logical stream */
	const char *bufs[] = { buf1, buf2 };
	size_t lens[] = { len1, len2 };
	int nbufs = 2;

	size_t buf_idx = 0, buf_off = 0;
	pvcm_http_data_t data;
	data.op = PVCM_OP_HTTP_DATA;
	data.stream_id = stream_id;

	while (buf_idx < (size_t)nbufs) {
		size_t chunk = 0;

		/* fill one DATA frame from possibly multiple buffers */
		while (chunk < PVCM_MAX_CHUNK_SIZE && buf_idx < (size_t)nbufs) {
			size_t avail = lens[buf_idx] - buf_off;
			size_t room = PVCM_MAX_CHUNK_SIZE - chunk;
			size_t n = avail < room ? avail : room;

			if (n > 0 && bufs[buf_idx]) {
				memcpy(data.data + chunk,
				       bufs[buf_idx] + buf_off, n);
				chunk += n;
				buf_off += n;
			}

			if (buf_off >= lens[buf_idx]) {
				buf_idx++;
				buf_off = 0;
			}
		}

		if (chunk > 0) {
			data.len = (uint16_t)chunk;
			t->send_frame(t, &data, 4 + chunk);
		}
	}
}

/* ---- MCU → Linux: outbound HTTP request ---- */

/* pending request being assembled from MCU frames.
 * DATA stream carries: path (path_len) + headers (headers_len) + body.
 * Buffers are dynamically allocated from REQ metadata sizes. */
static struct {
	uint8_t stream_id;
	uint8_t method;
	uint16_t status_code;
	char *path;             /* malloc'd, path_len + 1 */
	char *headers;          /* malloc'd, headers_len + 1 */
	char *body;             /* malloc'd, body_len + 1 */
	uint16_t path_len;      /* expected from REQ */
	uint16_t headers_len;   /* expected from REQ */
	uint32_t body_expected; /* expected from REQ */
	size_t stream_offset;   /* total bytes received in DATA stream */
	bool active;
} pending_req;

static void pending_req_free(void)
{
	free(pending_req.path);
	free(pending_req.headers);
	free(pending_req.body);
	pending_req.path = NULL;
	pending_req.headers = NULL;
	pending_req.body = NULL;
}

int pvcm_bridge_init(struct pvcm_transport *t)
{
	(void)t;
	memset(&pending_req, 0, sizeof(pending_req));
	/* pointers are NULL after memset — allocated on demand in on_http_req */
	return 0;
}

int pvcm_bridge_on_http_req(struct pvcm_transport *t,
			    const uint8_t *buf, int len)
{
	(void)t;
	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;

	if (req->direction != PVCM_HTTP_DIR_REQUEST)
		return 0;

	/* free any previous buffers */
	pending_req_free();

	pending_req.stream_id = req->stream_id;
	pending_req.method = req->method;
	pending_req.path_len = req->path_len;
	pending_req.headers_len = req->headers_len;
	pending_req.body_expected = req->body_len;
	pending_req.stream_offset = 0;

	/* allocate exact sizes from metadata */
	pending_req.path = calloc(1, req->path_len + 1);
	pending_req.headers = calloc(1, req->headers_len + 1);
	pending_req.body = calloc(1, req->body_len + 1);
	pending_req.active = true;

	fprintf(stdout, "[bridge] HTTP_REQ: %s path_len=%u hdr_len=%u "
		"body_len=%u\n",
		method_to_str(req->method), req->path_len,
		req->headers_len, req->body_len);

	return 0;
}

/*
 * Demux DATA chunk into path / headers / body based on stream offset.
 * Buffers are exact-sized from REQ metadata — no overflow possible.
 */
int pvcm_bridge_on_http_data(struct pvcm_transport *t,
			     const uint8_t *buf, int len)
{
	(void)t;
	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	if (!pending_req.active || d->stream_id != pending_req.stream_id)
		return 0;

	const uint8_t *src = d->data;
	size_t remaining = d->len;
	size_t off = pending_req.stream_offset;

	size_t path_end = pending_req.path_len;
	size_t hdr_end = path_end + pending_req.headers_len;
	size_t body_end = hdr_end + pending_req.body_expected;

	while (remaining > 0) {
		if (off < path_end && pending_req.path) {
			size_t n = path_end - off;
			if (n > remaining) n = remaining;
			memcpy(pending_req.path + off, src, n);
			pending_req.path[off + n] = '\0';
			src += n; remaining -= n; off += n;
		} else if (off < hdr_end && pending_req.headers) {
			size_t hoff = off - path_end;
			size_t n = hdr_end - off;
			if (n > remaining) n = remaining;
			memcpy(pending_req.headers + hoff, src, n);
			pending_req.headers[hoff + n] = '\0';
			src += n; remaining -= n; off += n;
		} else if (off < body_end && pending_req.body) {
			size_t boff = off - hdr_end;
			size_t n = body_end - off;
			if (n > remaining) n = remaining;
			memcpy(pending_req.body + boff, src, n);
			pending_req.body[boff + n] = '\0';
			src += n; remaining -= n; off += n;
		} else {
			/* past all expected data — discard */
			break;
		}
	}

	pending_req.stream_offset = off;
	return 0;
}

int pvcm_bridge_on_http_end(struct pvcm_transport *t,
			    const uint8_t *buf, int len)
{
	(void)len;
	if (!pending_req.active)
		return 0;

	/* compute actual body length from stream */
	size_t hdr_end = pending_req.path_len + pending_req.headers_len;
	size_t body_received = 0;
	if (pending_req.stream_offset > hdr_end)
		body_received = pending_req.stream_offset - hdr_end;

	pending_req.active = false;

	fprintf(stdout, "[bridge] HTTP_END: forwarding %s %s "
		"(body=%zu bytes)\n",
		method_to_str(pending_req.method), pending_req.path,
		body_received);

	/* resolve route from Host header */
	char host_buf[64] = "";
	const char *hostname = extract_host(
		pending_req.headers[0] ? pending_req.headers : NULL,
		host_buf, sizeof(host_buf));
	const struct http_route *route = find_route(hostname);

	if (route) {
		fprintf(stdout, "[bridge] route: %s -> %s%s\n",
			hostname,
			route->unix_path[0] ? "unix:" : "",
			route->unix_path[0] ? route->unix_path
					    : route->tcp_host);
	}

	/* Don't forward MCU's Host header — http_request sets its own */
	const char *fwd_headers = NULL;
	if (!route && pending_req.headers && pending_req.headers[0])
		fwd_headers = pending_req.headers;

	char *resp_body = NULL;
	char *resp_headers = NULL;
	int resp_status = 500;

	int body_len = http_request(
		method_to_str(pending_req.method),
		route,
		"127.0.0.1", 12368,
		pending_req.path,
		body_received > 0 ? pending_req.body : NULL,
		body_received,
		&resp_body, &resp_status, &resp_headers);

	if (body_len < 0) {
		fprintf(stderr, "[bridge] upstream request failed\n");
		resp_status = 502;
		body_len = 0;
	}

	fprintf(stdout, "[bridge] upstream response: %d, body=%d bytes\n",
		resp_status, body_len);

	size_t hlen = resp_headers ? strlen(resp_headers) : 0;

	pvcm_http_req_t resp = {
		.op = PVCM_OP_HTTP_REQ,
		.stream_id = pending_req.stream_id,
		.direction = PVCM_HTTP_DIR_RESPONSE,
		.method = 0,
		.status_code = (uint16_t)resp_status,
		.path_len = 0,
		.headers_len = (uint16_t)hlen,
		.body_len = (uint32_t)body_len,
	};
	t->send_frame(t, &resp, sizeof(resp) - sizeof(uint32_t));

	/* stream headers + body as DATA frames */
	send_data_stream(t, pending_req.stream_id,
			 resp_headers, hlen,
			 resp_body, body_len);

	/* send HTTP_END */
	pvcm_http_end_t end = {
		.op = PVCM_OP_HTTP_END,
		.stream_id = pending_req.stream_id,
	};
	t->send_frame(t, &end, sizeof(end) - sizeof(uint32_t));

	free(resp_body);
	free(resp_headers);
	pending_req_free();
	return 0;
}

/* ---- Linux → MCU: inbound HTTP via evhttp ---- */

static struct pvcm_transport *invoke_transport;

/* pending reply from MCU */
static struct {
	uint8_t stream_id;
	bool active;
	bool complete;
	uint16_t status_code;
	char headers[1024];
	size_t headers_len;
	char body[8192];
	size_t body_len;
	struct evhttp_request *pending_req;  /* stashed evhttp request */
	struct event *timeout_ev;            /* 10s timeout timer */
} invoke_reply;

static uint8_t invoke_stream_id = 128; /* high range to avoid collision */

int pvcm_bridge_on_reply_req(struct pvcm_transport *t,
			     const uint8_t *buf, int len)
{
	(void)t;
	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;
	if (req->direction != PVCM_HTTP_DIR_REPLY)
		return 0;

	if (invoke_reply.active && req->stream_id == invoke_reply.stream_id) {
		invoke_reply.status_code = req->status_code;
		/* headers arrive via DATA stream in the new format */
		invoke_reply.headers_len = 0;
		invoke_reply.headers[0] = '\0';
	}
	return 0;
}

int pvcm_bridge_on_reply_data(struct pvcm_transport *t,
			      const uint8_t *buf, int len)
{
	(void)t;
	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	if (invoke_reply.active && d->stream_id == invoke_reply.stream_id) {
		size_t chunk = d->len;
		if (invoke_reply.body_len + chunk >
		    sizeof(invoke_reply.body) - 1)
			chunk = sizeof(invoke_reply.body) - 1 -
				invoke_reply.body_len;
		memcpy(invoke_reply.body + invoke_reply.body_len,
		       d->data, chunk);
		invoke_reply.body_len += chunk;
	}
	return 0;
}

/* Send the HTTP response back to the evhttp client */
static void invoke_send_response(int status_code, const char *body,
				 size_t body_len)
{
	struct evhttp_request *req = invoke_reply.pending_req;
	if (!req)
		return;

	struct evbuffer *buf = evbuffer_new();
	if (body && body_len > 0)
		evbuffer_add(buf, body, body_len);

	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "application/json");
	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Connection", "close");
	evhttp_send_reply(req, status_code, "OK", buf);
	evbuffer_free(buf);

	invoke_reply.pending_req = NULL;
}

int pvcm_bridge_on_reply_end(struct pvcm_transport *t,
			     const uint8_t *buf, int len)
{
	(void)t;
	uint8_t sid = buf[1];

	if (!invoke_reply.active || sid != invoke_reply.stream_id)
		return 0;

	invoke_reply.body[invoke_reply.body_len] = '\0';
	invoke_reply.complete = true;

	fprintf(stdout, "[bridge] INVOKE reply: status=%d body=%zu\n",
		invoke_reply.status_code, invoke_reply.body_len);

	/* cancel timeout timer */
	if (invoke_reply.timeout_ev) {
		evtimer_del(invoke_reply.timeout_ev);
		event_free(invoke_reply.timeout_ev);
		invoke_reply.timeout_ev = NULL;
	}

	/* send HTTP response */
	invoke_send_response(invoke_reply.status_code,
			     invoke_reply.body, invoke_reply.body_len);
	invoke_reply.active = false;
	return 0;
}

/* Timeout callback — send 504 if MCU doesn't reply in time */
static void invoke_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	(void)arg;

	if (!invoke_reply.active)
		return;

	fprintf(stderr, "[bridge] INVOKE timeout (10s)\n");
	invoke_send_response(504, "{\"error\":\"MCU timeout\"}", 22);
	invoke_reply.active = false;
	invoke_reply.timeout_ev = NULL;
}

/* evhttp request handler — invokes MCU and waits for async reply */
static void on_http_request(struct evhttp_request *req, void *arg)
{
	struct event_base *base = evhttp_connection_get_base(
		evhttp_request_get_connection(req));

	if (invoke_reply.active) {
		/* only one in-flight invoke at a time */
		evhttp_send_error(req, 503, "MCU busy");
		return;
	}

	const char *uri = evhttp_request_get_uri(req);
	enum evhttp_cmd_type cmd = evhttp_request_get_command(req);

	const char *method = "GET";
	uint8_t method_code = PVCM_HTTP_GET;
	switch (cmd) {
	case EVHTTP_REQ_POST:   method = "POST";   method_code = PVCM_HTTP_POST;   break;
	case EVHTTP_REQ_PUT:    method = "PUT";     method_code = PVCM_HTTP_PUT;    break;
	case EVHTTP_REQ_DELETE: method = "DELETE";  method_code = PVCM_HTTP_DELETE; break;
	default: break;
	}

	/* read request body */
	struct evbuffer *input = evhttp_request_get_input_buffer(req);
	size_t req_body_len = evbuffer_get_length(input);
	char req_body[4096] = "";
	if (req_body_len > 0) {
		if (req_body_len > sizeof(req_body) - 1)
			req_body_len = sizeof(req_body) - 1;
		evbuffer_copyout(input, req_body, req_body_len);
		req_body[req_body_len] = '\0';
	}

	fprintf(stdout, "[bridge-listen] %s %s (body=%zu)\n",
		method, uri, req_body_len);

	uint8_t sid = invoke_stream_id++;
	if (invoke_stream_id == 0)
		invoke_stream_id = 128;

	/* setup pending reply */
	invoke_reply.stream_id = sid;
	invoke_reply.active = true;
	invoke_reply.complete = false;
	invoke_reply.body_len = 0;
	invoke_reply.status_code = 0;
	invoke_reply.pending_req = req;

	/* start 10s timeout */
	invoke_reply.timeout_ev = evtimer_new(base, invoke_timeout_cb, NULL);
	struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
	evtimer_add(invoke_reply.timeout_ev, &tv);

	/* send INVOKE metadata + path + body as DATA stream */
	size_t plen = strlen(uri);

	pvcm_http_req_t ireq = {
		.op = PVCM_OP_HTTP_REQ,
		.stream_id = sid,
		.direction = PVCM_HTTP_DIR_INVOKE,
		.method = method_code,
		.path_len = (uint16_t)plen,
		.headers_len = 0,
		.body_len = (uint32_t)req_body_len,
	};

	invoke_transport->send_frame(invoke_transport, &ireq,
				     sizeof(ireq) - sizeof(uint32_t));

	/* stream path + body as DATA frames */
	send_data_stream(invoke_transport, sid,
			 uri, plen,
			 req_body, req_body_len);

	pvcm_http_end_t end = { .op = PVCM_OP_HTTP_END, .stream_id = sid };
	invoke_transport->send_frame(invoke_transport, &end,
				     sizeof(end) - sizeof(uint32_t));

	/* don't send reply here — reply comes async via on_reply_end */
}

int pvcm_bridge_start_listener(struct event_base *base,
			       struct pvcm_transport *t, int port)
{
	invoke_transport = t;

	struct evhttp *http = evhttp_new(base);
	if (!http) {
		fprintf(stderr, "[bridge-listen] evhttp_new failed\n");
		return -1;
	}

	evhttp_set_gencb(http, on_http_request, NULL);

	if (evhttp_bind_socket(http, "127.0.0.1", port) != 0) {
		fprintf(stderr, "[bridge-listen] bind failed on port %d\n",
			port);
		evhttp_free(http);
		return -1;
	}

	fprintf(stdout, "[bridge-listen] MCU HTTP server on port %d\n", port);
	return 0;
}
