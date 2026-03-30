/*
 * pvcm-proxy HTTP bridge
 *
 * Receives HTTP_REQ/DATA/END frames from the MCU, reassembles the
 * request, makes an HTTP request to the configured upstream, and
 * sends the response back as HTTP_REQ(RESPONSE)/DATA/END frames.
 *
 * For testing, the upstream is a simple HTTP connection to a local
 * server. In production, the upstream would be a Unix domain socket
 * injected by xconnect.
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE  /* for strcasestr */

#include "pvcm_bridge.h"

#include <stdbool.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

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

	fprintf(stdout, "[bridge] route: %s -> %s%s%s%s\n",
		r->name,
		r->unix_path[0] ? "unix:" : "tcp:",
		r->unix_path[0] ? r->unix_path : r->tcp_host,
		r->unix_path[0] ? "" : ":",
		r->unix_path[0] ? "" : val + 4 + strlen(r->tcp_host) + 1);

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
	/* also strip port if present (Host: foo.pvlocal:80) */
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
			close(fd);
			return -1;
		}
		return fd;
	}
}

/* pending request being assembled from MCU frames */
static struct {
	uint8_t stream_id;
	uint8_t method;
	uint16_t status_code;
	char path[256];
	char headers[512];
	char body[8192];
	size_t body_len;
	bool active;
} pending_req;

/* Simple HTTP client — connects to backend, sends request, gets response.
 * If route is non-NULL, connects to the route's backend.
 * Otherwise falls back to host:port (legacy). */
static int http_request(const char *method_str,
			const struct http_route *route,
			const char *host, int port,
			const char *path, const char *req_headers,
			const char *req_body, size_t req_body_len,
			char *resp_buf, size_t resp_buf_size,
			int *resp_status, char *resp_headers,
			size_t resp_headers_size)
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
	if (fd < 0) {
		fprintf(stderr, "[bridge] connect failed: %s (%s)\n",
			route ? (route->unix_path[0] ? route->unix_path
						     : route->tcp_host)
			      : host,
			strerror(errno));
		return -1;
	}

	/* send HTTP request — unix sockets use Host: localhost */
	const char *host_hdr = host;
	if (route) {
		if (route->unix_path[0])
			host_hdr = "localhost";
		else
			host_hdr = route->tcp_host;
	}

	char req_line[512];
	int n;
	char cl[32];
	if (req_body_len > 0)
		snprintf(cl, sizeof(cl), "Content-Length: %zu\r\n",
			 req_body_len);
	n = snprintf(req_line, sizeof(req_line),
		     "%s %s HTTP/1.1\r\nHost: %s\r\n"
		     "Connection: close\r\n"
		     "%s"
		     "%s"
		     "\r\n",
		     method_str, path, host_hdr,
		     req_headers ? req_headers : "",
		     req_body_len > 0 ? cl : "");

	write(fd, req_line, n);
	if (req_body && req_body_len > 0)
		write(fd, req_body, req_body_len);

	/* read response with timeout — upstream may stream or hang */
	struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	char raw[16384];
	size_t total = 0;
	while (total < sizeof(raw) - 1) {
		ssize_t r = read(fd, raw + total, sizeof(raw) - 1 - total);
		if (r <= 0)
			break;
		total += r;
		/* if we got headers + some body, check if we have Content-Length
		 * worth of data and stop early */
		if (total > 4) {
			char *hdr_end = strstr(raw, "\r\n\r\n");
			if (hdr_end) {
				char *cl = strcasestr(raw, "Content-Length:");
				if (cl && cl < hdr_end) {
					size_t expected = atoi(cl + 15);
					size_t body_start = (hdr_end + 4) - raw;
					if (total - body_start >= expected)
						break;
				}
			}
		}
	}
	raw[total] = '\0';
	close(fd);

	if (total == 0) {
		fprintf(stderr, "[bridge] empty response from backend\n");
		return -1;
	}

	/* parse HTTP response — accept both \r\n\r\n and \n\n as header end */
	char *status_line = raw;
	char *hdr_end = strstr(raw, "\r\n\r\n");
	int hdr_sep_len = 4;
	if (!hdr_end) {
		hdr_end = strstr(raw, "\n\n");
		hdr_sep_len = 2;
	}
	if (!hdr_end)
		return -1;

	/* parse status code */
	char *sp = strchr(status_line, ' ');
	if (sp)
		*resp_status = atoi(sp + 1);

	/* extract headers */
	char *hdr_start = strstr(status_line, "\r\n");
	if (hdr_start && resp_headers) {
		size_t hlen = hdr_end - hdr_start - 2;
		if (hlen > resp_headers_size - 1)
			hlen = resp_headers_size - 1;
		memcpy(resp_headers, hdr_start + 2, hlen);
		resp_headers[hlen] = '\0';
	}

	/* extract body */
	char *body_start = hdr_end + hdr_sep_len;
	size_t body_len = total - (body_start - raw);
	if (body_len > resp_buf_size - 1)
		body_len = resp_buf_size - 1;
	memcpy(resp_buf, body_start, body_len);
	resp_buf[body_len] = '\0';

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

int pvcm_bridge_init(struct pvcm_transport *t)
{
	memset(&pending_req, 0, sizeof(pending_req));
	return 0;
}

int pvcm_bridge_on_http_req(struct pvcm_transport *t,
			    const uint8_t *buf, int len)
{
	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;

	if (req->direction != PVCM_HTTP_DIR_REQUEST) {
		fprintf(stderr, "[bridge] ignoring non-request HTTP_REQ "
			"dir=%d\n", req->direction);
		return 0;
	}

	pending_req.stream_id = req->stream_id;
	pending_req.method = req->method;
	pending_req.body_len = 0;
	pending_req.active = true;

	/* extract path */
	size_t plen = req->path_len;
	if (plen > sizeof(pending_req.path) - 1)
		plen = sizeof(pending_req.path) - 1;
	memcpy(pending_req.path, req->data, plen);
	pending_req.path[plen] = '\0';

	/* extract headers */
	size_t hlen = req->headers_len;
	if (hlen > sizeof(pending_req.headers) - 1)
		hlen = sizeof(pending_req.headers) - 1;
	if (hlen > 0)
		memcpy(pending_req.headers, req->data + plen, hlen);
	pending_req.headers[hlen] = '\0';

	fprintf(stdout, "[bridge] HTTP_REQ: %s %s (body_size=%u)\n",
		method_to_str(req->method), pending_req.path,
		req->total_body_size);

	return 0;
}

int pvcm_bridge_on_http_data(struct pvcm_transport *t,
			     const uint8_t *buf, int len)
{
	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	if (!pending_req.active || d->stream_id != pending_req.stream_id)
		return 0;

	size_t chunk = d->len;
	if (pending_req.body_len + chunk > sizeof(pending_req.body) - 1)
		chunk = sizeof(pending_req.body) - 1 - pending_req.body_len;

	memcpy(pending_req.body + pending_req.body_len, d->data, chunk);
	pending_req.body_len += chunk;

	return 0;
}

int pvcm_bridge_on_http_end(struct pvcm_transport *t,
			    const uint8_t *buf, int len)
{
	if (!pending_req.active)
		return 0;

	pending_req.body[pending_req.body_len] = '\0';
	pending_req.active = false;

	fprintf(stdout, "[bridge] HTTP_END: forwarding %s %s "
		"(body=%zu bytes)\n",
		method_to_str(pending_req.method), pending_req.path,
		pending_req.body_len);

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

	/* forward to upstream HTTP server */
	char resp_body[8192] = "";
	char resp_headers[1024] = "";
	int resp_status = 500;

	/* Don't forward MCU's Host header to backend — http_request
	 * sets its own Host header based on the route. Only forward
	 * non-Host headers from the MCU. */
	const char *fwd_headers = NULL;
	if (!route && pending_req.headers[0])
		fwd_headers = pending_req.headers;

	int body_len = http_request(
		method_to_str(pending_req.method),
		route,
		"127.0.0.1", 12368,
		pending_req.path,
		fwd_headers,
		pending_req.body_len > 0 ? pending_req.body : NULL,
		pending_req.body_len,
		resp_body, sizeof(resp_body),
		&resp_status, resp_headers, sizeof(resp_headers));

	if (body_len < 0) {
		fprintf(stderr, "[bridge] upstream request failed\n");
		resp_status = 502;
		body_len = 0;
	}

	fprintf(stdout, "[bridge] upstream response: %d, body=%d bytes\n",
		resp_status, body_len);

	/* send HTTP_REQ response */
	pvcm_http_req_t resp = {
		.op = PVCM_OP_HTTP_REQ,
		.stream_id = pending_req.stream_id,
		.direction = PVCM_HTTP_DIR_RESPONSE,
		.method = 0,
		.status_code = (uint16_t)resp_status,
		.total_body_size = (uint32_t)body_len,
	};

	/* pack response headers */
	size_t hlen = strlen(resp_headers);
	if (hlen > sizeof(resp.data))
		hlen = sizeof(resp.data);
	resp.headers_len = (uint16_t)hlen;
	resp.path_len = 0;
	if (hlen > 0)
		memcpy(resp.data, resp_headers, hlen);

	t->send_frame(t, &resp, sizeof(resp) - sizeof(uint32_t));

	/* send body chunks */
	size_t offset = 0;
	while (offset < (size_t)body_len) {
		pvcm_http_data_t data = {
			.op = PVCM_OP_HTTP_DATA,
			.stream_id = pending_req.stream_id,
		};
		size_t chunk = body_len - offset;
		if (chunk > PVCM_MAX_CHUNK_SIZE)
			chunk = PVCM_MAX_CHUNK_SIZE;
		data.len = (uint16_t)chunk;
		memcpy(data.data, resp_body + offset, chunk);
		t->send_frame(t, &data, 4 + chunk);
		offset += chunk;
	}

	/* send HTTP_END */
	pvcm_http_end_t end = {
		.op = PVCM_OP_HTTP_END,
		.stream_id = pending_req.stream_id,
	};
	t->send_frame(t, &end, sizeof(end) - sizeof(uint32_t));

	return 0;
}

/* ---- MCU as HTTP server (inbound requests) ---- */

#include <pthread.h>
#include <poll.h>

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
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} invoke_reply = {
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
};

static uint8_t invoke_stream_id = 128; /* high range to avoid collision */

int pvcm_bridge_on_reply_req(struct pvcm_transport *t,
			     const uint8_t *buf, int len)
{
	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;
	fprintf(stdout, "[bridge] REPLY_REQ: dir=%d sid=%d status=%d "
		"(expect sid=%d active=%d)\n",
		req->direction, req->stream_id, req->status_code,
		invoke_reply.stream_id, invoke_reply.active);
	if (req->direction != PVCM_HTTP_DIR_REPLY)
		return 0;

	pthread_mutex_lock(&invoke_reply.mutex);
	if (invoke_reply.active && req->stream_id == invoke_reply.stream_id) {
		invoke_reply.status_code = req->status_code;
		size_t hlen = req->headers_len;
		if (hlen > sizeof(invoke_reply.headers) - 1)
			hlen = sizeof(invoke_reply.headers) - 1;
		if (hlen > 0)
			memcpy(invoke_reply.headers, req->data + req->path_len, hlen);
		invoke_reply.headers[hlen] = '\0';
		invoke_reply.headers_len = hlen;
	}
	pthread_mutex_unlock(&invoke_reply.mutex);
	return 0;
}

int pvcm_bridge_on_reply_data(struct pvcm_transport *t,
			      const uint8_t *buf, int len)
{
	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	pthread_mutex_lock(&invoke_reply.mutex);
	if (invoke_reply.active && d->stream_id == invoke_reply.stream_id) {
		size_t chunk = d->len;
		if (invoke_reply.body_len + chunk > sizeof(invoke_reply.body) - 1)
			chunk = sizeof(invoke_reply.body) - 1 - invoke_reply.body_len;
		memcpy(invoke_reply.body + invoke_reply.body_len, d->data, chunk);
		invoke_reply.body_len += chunk;
	}
	pthread_mutex_unlock(&invoke_reply.mutex);
	return 0;
}

int pvcm_bridge_on_reply_end(struct pvcm_transport *t,
			     const uint8_t *buf, int len)
{
	uint8_t sid = buf[1];
	fprintf(stdout, "[bridge] REPLY_END: sid=%d (expect sid=%d "
		"active=%d)\n", sid, invoke_reply.stream_id,
		invoke_reply.active);

	pthread_mutex_lock(&invoke_reply.mutex);
	if (invoke_reply.active && sid == invoke_reply.stream_id) {
		invoke_reply.body[invoke_reply.body_len] = '\0';
		invoke_reply.complete = true;
		fprintf(stdout, "[bridge] REPLY complete: status=%d "
			"body=%zu\n", invoke_reply.status_code,
			invoke_reply.body_len);
		pthread_cond_signal(&invoke_reply.cond);
	}
	pthread_mutex_unlock(&invoke_reply.mutex);
	return 0;
}

/* Forward an inbound HTTP request to the MCU and wait for reply */
static int invoke_mcu(struct pvcm_transport *t,
		      const char *method, const char *path,
		      const char *req_body, size_t req_body_len,
		      char *resp_body, size_t resp_body_size,
		      int *resp_status)
{
	uint8_t sid = invoke_stream_id++;
	if (invoke_stream_id == 0)
		invoke_stream_id = 128;

	uint8_t method_code = PVCM_HTTP_GET;
	if (strcmp(method, "POST") == 0) method_code = PVCM_HTTP_POST;
	else if (strcmp(method, "PUT") == 0) method_code = PVCM_HTTP_PUT;
	else if (strcmp(method, "DELETE") == 0) method_code = PVCM_HTTP_DELETE;

	/* setup pending reply */
	pthread_mutex_lock(&invoke_reply.mutex);
	invoke_reply.stream_id = sid;
	invoke_reply.active = true;
	invoke_reply.complete = false;
	invoke_reply.body_len = 0;
	invoke_reply.status_code = 0;
	pthread_mutex_unlock(&invoke_reply.mutex);

	/* send INVOKE request to MCU */
	pvcm_http_req_t req = {
		.op = PVCM_OP_HTTP_REQ,
		.stream_id = sid,
		.direction = PVCM_HTTP_DIR_INVOKE,
		.method = method_code,
		.total_body_size = (uint32_t)req_body_len,
	};
	size_t plen = strlen(path);
	if (plen > sizeof(req.data)) plen = sizeof(req.data);
	req.path_len = (uint16_t)plen;
	req.headers_len = 0;
	memcpy(req.data, path, plen);

	t->send_frame(t, &req, sizeof(req) - sizeof(uint32_t));

	/* send body if any */
	if (req_body && req_body_len > 0) {
		size_t off = 0;
		while (off < req_body_len) {
			pvcm_http_data_t data = {
				.op = PVCM_OP_HTTP_DATA,
				.stream_id = sid,
			};
			size_t chunk = req_body_len - off;
			if (chunk > PVCM_MAX_CHUNK_SIZE) chunk = PVCM_MAX_CHUNK_SIZE;
			data.len = (uint16_t)chunk;
			memcpy(data.data, req_body + off, chunk);
			t->send_frame(t, &data, 4 + chunk);
			off += chunk;
		}
	}

	pvcm_http_end_t end = { .op = PVCM_OP_HTTP_END, .stream_id = sid };
	t->send_frame(t, &end, sizeof(end) - sizeof(uint32_t));

	/* wait for MCU reply (10s timeout) */
	pthread_mutex_lock(&invoke_reply.mutex);
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += 10;

	while (!invoke_reply.complete) {
		if (pthread_cond_timedwait(&invoke_reply.cond,
					  &invoke_reply.mutex, &ts) != 0) {
			invoke_reply.active = false;
			pthread_mutex_unlock(&invoke_reply.mutex);
			fprintf(stderr, "[bridge] MCU invoke timeout\n");
			*resp_status = 504;
			return -1;
		}
	}

	*resp_status = invoke_reply.status_code;
	size_t blen = invoke_reply.body_len;
	if (blen > resp_body_size - 1) blen = resp_body_size - 1;
	memcpy(resp_body, invoke_reply.body, blen);
	resp_body[blen] = '\0';
	invoke_reply.active = false;
	pthread_mutex_unlock(&invoke_reply.mutex);

	return (int)blen;
}

/* HTTP listener thread — accepts connections and invokes MCU */
static struct pvcm_transport *listener_transport;
static int listener_port;

static void handle_client(int client_fd)
{
	char raw[4096];
	ssize_t n = read(client_fd, raw, sizeof(raw) - 1);
	if (n <= 0) { close(client_fd); return; }
	raw[n] = '\0';

	/* parse HTTP request line */
	char method[16], path[256];
	sscanf(raw, "%15s %255s", method, path);

	/* find body */
	char *body_start = strstr(raw, "\r\n\r\n");
	char *req_body = NULL;
	size_t req_body_len = 0;
	if (body_start) {
		req_body = body_start + 4;
		req_body_len = n - (req_body - raw);
	}

	fprintf(stdout, "[bridge-listen] %s %s (body=%zu)\n",
		method, path, req_body_len);

	/* invoke MCU */
	char resp_body[8192] = "";
	int resp_status = 500;
	int body_len = invoke_mcu(listener_transport, method, path,
				  req_body, req_body_len,
				  resp_body, sizeof(resp_body),
				  &resp_status);
	if (body_len < 0) body_len = 0;

	/* send HTTP response */
	char resp[16384];
	int rn = snprintf(resp, sizeof(resp),
			  "HTTP/1.1 %d OK\r\n"
			  "Content-Type: application/json\r\n"
			  "Content-Length: %d\r\n"
			  "Connection: close\r\n"
			  "\r\n%s",
			  resp_status, body_len, resp_body);
	write(client_fd, resp, rn);
	close(client_fd);
}

static void *listener_thread(void *arg)
{
	int port = listener_port;
	int srv = socket(AF_INET, SOCK_STREAM, 0);
	int opt = 1;
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

	if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "[bridge-listen] bind failed: %m\n");
		return NULL;
	}
	listen(srv, 4);
	fprintf(stdout, "[bridge-listen] MCU HTTP server on port %d\n", port);

	while (1) {
		int client = accept(srv, NULL, NULL);
		if (client < 0) break;
		handle_client(client);
	}
	close(srv);
	return NULL;
}

int pvcm_bridge_start_listener(struct pvcm_transport *t, int port)
{
	listener_transport = t;
	listener_port = port;

	pthread_t tid;
	pthread_create(&tid, NULL, listener_thread, NULL);
	pthread_detach(tid);

	return 0;
}
