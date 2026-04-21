/*
 * PVCM HTTP Client — async HTTP over PVCM protocol
 *
 * All requests are fire-and-forget: pvcm_get() sends frames and
 * returns immediately. Responses arrive via callbacks on the
 * PVCM server thread.
 *
 * Multiple requests can be in flight simultaneously, keyed by
 * stream_id. Each pending slot holds the callbacks and reassembly
 * state.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>
#include <pantavisor/pvcm_transport.h>

#include <string.h>

LOG_MODULE_REGISTER(pvcm_client, CONFIG_LOG_DEFAULT_LEVEL);

/* ---- Pending request slots ---- */

#define MAX_PENDING 4

#define PVCM_MAX_HEADERS_SIZE (16 * 1024)
#define PVCM_MAX_BODY_SIZE    (32 * 1024)

struct pending_http {
	uint8_t stream_id;
	bool active;

	/* callbacks */
	struct pvcm_http_callbacks cb;

	/* response metadata from REQ frame */
	uint16_t status_code;
	uint16_t headers_expected;
	uint32_t body_expected;

	/* stream reassembly */
	size_t stream_offset;

	/* buffered mode (on_response) */
	char *headers;          /* k_malloc'd */
	uint16_t headers_alloc;
	size_t headers_len;
	char *body;             /* k_malloc'd */
	uint32_t body_alloc;
	size_t body_len;

	/* chunk mode flags */
	bool headers_delivered; /* first chunk got headers */
};

static struct pending_http pending[MAX_PENDING];
static uint8_t next_stream_id = 1;

static struct pending_http *find_pending(uint8_t stream_id)
{
	for (int i = 0; i < MAX_PENDING; i++) {
		if (pending[i].active && pending[i].stream_id == stream_id)
			return &pending[i];
	}
	return NULL;
}

static struct pending_http *alloc_pending(void)
{
	for (int i = 0; i < MAX_PENDING; i++) {
		if (!pending[i].active)
			return &pending[i];
	}
	return NULL;
}

static void free_pending(struct pending_http *p)
{
	k_free(p->headers);
	k_free(p->body);
	memset(p, 0, sizeof(*p));
}

/* Check if stream_id matches a pending outbound HTTP request */
bool pvcm_client_has_pending_http(uint8_t stream_id)
{
	return find_pending(stream_id) != NULL;
}

/* ---- Send request frames ---- */

static int send_http_request(uint8_t method, const char *path,
			     const char *req_headers,
			     const char *body, size_t body_len,
			     const struct pvcm_http_callbacks *cb)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	struct pending_http *p = alloc_pending();
	if (!p) {
		LOG_ERR("no pending slots available");
		return -ENOMEM;
	}

	uint8_t sid = next_stream_id++;
	if (next_stream_id == 0)
		next_stream_id = 1;

	memset(p, 0, sizeof(*p));
	p->stream_id = sid;
	p->active = true;
	if (cb)
		p->cb = *cb;

	LOG_INF("HTTP send: sid=%d path=%s", sid, path);

	/* send REQ metadata */
	size_t path_len = strlen(path);
	size_t hdr_len = req_headers ? strlen(req_headers) : 0;

	pvcm_http_req_t req = {
		.op = PVCM_OP_HTTP_REQ,
		.stream_id = sid,
		.direction = PVCM_HTTP_DIR_REQUEST,
		.method = method,
		.status_code = 0,
		.path_len = (uint16_t)path_len,
		.headers_len = (uint16_t)hdr_len,
		.body_len = (uint32_t)body_len,
	};

	int ret = t->send_frame(&req, sizeof(req) - sizeof(uint32_t));
	if (ret < 0) {
		free_pending(p);
		return -EIO;
	}

	/* stream path + headers + body as DATA frames */
	const char *parts[] = { path, req_headers, body };
	size_t part_lens[] = { path_len, hdr_len, body_len };
	size_t pi = 0, poff = 0;

	while (pi < 3) {
		pvcm_http_data_t data = {
			.op = PVCM_OP_HTTP_DATA,
			.stream_id = sid,
		};
		size_t chunk = 0;

		while (chunk < PVCM_MAX_CHUNK_SIZE && pi < 3) {
			if (!parts[pi] || part_lens[pi] == 0) {
				pi++; poff = 0; continue;
			}
			size_t avail = part_lens[pi] - poff;
			size_t room = PVCM_MAX_CHUNK_SIZE - chunk;
			size_t n = avail < room ? avail : room;
			memcpy(data.data + chunk, parts[pi] + poff, n);
			chunk += n; poff += n;
			if (poff >= part_lens[pi]) { pi++; poff = 0; }
		}

		if (chunk > 0) {
			data.len = (uint16_t)chunk;
			t->send_frame(&data, 4 + chunk);
		}
	}

	/* send END */
	pvcm_http_end_t end = {
		.op = PVCM_OP_HTTP_END,
		.stream_id = sid,
	};
	t->send_frame(&end, sizeof(end) - sizeof(uint32_t));

	return 0;
}

/* ---- Response handlers (called from server thread) ---- */

void pvcm_client_on_http_req(const uint8_t *buf, int len)
{
	if ((size_t)len < sizeof(pvcm_http_req_t) - sizeof(uint32_t))
		return;

	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;

	if (req->direction != PVCM_HTTP_DIR_RESPONSE)
		return;

	struct pending_http *p = find_pending(req->stream_id);
	if (!p)
		return;

	LOG_INF("HTTP resp: sid=%d status=%d hdr=%u body=%u",
		req->stream_id, req->status_code,
		req->headers_len, req->body_len);

	p->status_code = req->status_code;
	p->headers_expected = req->headers_len;
	p->body_expected = req->body_len;
	p->stream_offset = 0;
	p->headers_delivered = false;

	if (p->cb.on_response) {
		/* buffered mode — allocate, cap at limits */
		uint16_t ha = req->headers_len < PVCM_MAX_HEADERS_SIZE
			      ? req->headers_len : PVCM_MAX_HEADERS_SIZE;
		uint32_t ba = req->body_len < PVCM_MAX_BODY_SIZE
			      ? req->body_len : PVCM_MAX_BODY_SIZE;

		if (req->body_len > PVCM_MAX_BODY_SIZE) {
			/* too large for buffered mode */
			if (p->cb.on_error) {
				p->cb.on_error(PVCM_ERR_OVERSIZED,
					       "body exceeds 32K, use on_chunk",
					       p->cb.ctx);
			}
			free_pending(p);
			return;
		}

		p->headers_alloc = ha;
		p->body_alloc = ba;
		p->headers = ha > 0 ? k_malloc(ha + 1) : NULL;
		p->body = ba > 0 ? k_malloc(ba + 1) : NULL;
		if (p->headers) p->headers[0] = '\0';
		if (p->body) p->body[0] = '\0';
	}
	/* chunk mode: no allocation needed — deliver directly */
}

void pvcm_client_on_http_data(const uint8_t *buf, int len)
{
	if ((size_t)len < 4)
		return;

	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	struct pending_http *p = find_pending(d->stream_id);
	if (!p)
		return;

	const uint8_t *src = d->data;
	size_t remaining = d->len;
	size_t off = p->stream_offset;
	size_t hdr_end = p->headers_expected;
	size_t body_end = hdr_end + p->body_expected;

	if (p->cb.on_chunk) {
		/* streaming mode — deliver chunks directly */
		while (remaining > 0) {
			if (off < hdr_end) {
				/* skip headers in chunk mode — buffer them
				 * temporarily for the first on_chunk call */
				size_t n = hdr_end - off;
				if (n > remaining) n = remaining;

				/* buffer headers for first delivery */
				if (!p->headers && p->headers_expected > 0) {
					uint16_t ha = p->headers_expected < PVCM_MAX_HEADERS_SIZE
						      ? p->headers_expected : PVCM_MAX_HEADERS_SIZE;
					p->headers_alloc = ha;
					p->headers = k_malloc(ha + 1);
					if (p->headers) p->headers[0] = '\0';
				}
				if (p->headers && off < p->headers_alloc) {
					size_t tc = n;
					if (off + tc > p->headers_alloc)
						tc = p->headers_alloc - off;
					memcpy(p->headers + off, src, tc);
					p->headers[off + tc] = '\0';
					p->headers_len = off + tc;
				}
				src += n; remaining -= n; off += n;
			} else {
				/* body region — deliver as chunk */
				size_t n = remaining;
				if (off + n > body_end)
					n = body_end - off;

				const char *hdrs = NULL;
				if (!p->headers_delivered) {
					hdrs = p->headers;
					p->headers_delivered = true;
				}

				p->cb.on_chunk(p->status_code,
					       (const char *)src, n,
					       hdrs, false, p->cb.ctx);
				src += n; remaining -= n; off += n;
			}
		}
	} else if (p->cb.on_response) {
		/* buffered mode — accumulate */
		while (remaining > 0) {
			if (off < hdr_end) {
				size_t n = hdr_end - off;
				if (n > remaining) n = remaining;
				if (p->headers && off < p->headers_alloc) {
					size_t tc = n;
					if (off + tc > p->headers_alloc)
						tc = p->headers_alloc - off;
					memcpy(p->headers + off, src, tc);
					p->headers[off + tc] = '\0';
					p->headers_len = off + tc;
				}
				src += n; remaining -= n; off += n;
			} else if (off < body_end) {
				size_t boff = off - hdr_end;
				size_t n = body_end - off;
				if (n > remaining) n = remaining;
				if (p->body && boff < p->body_alloc) {
					size_t tc = n;
					if (boff + tc > p->body_alloc)
						tc = p->body_alloc - boff;
					memcpy(p->body + boff, src, tc);
					p->body[boff + tc] = '\0';
					p->body_len = boff + tc;
				}
				src += n; remaining -= n; off += n;
			} else {
				break;
			}
		}
	}

	p->stream_offset = off;
}

void pvcm_client_on_http_end(const uint8_t *buf, int len)
{
	if ((size_t)len < 2)
		return;

	uint8_t stream_id = buf[1];

	struct pending_http *p = find_pending(stream_id);
	if (!p)
		return;

	LOG_INF("HTTP complete: sid=%d status=%d body=%zu",
		stream_id, p->status_code, p->body_len);

	if (p->cb.on_chunk) {
		/* final chunk delivery */
		const char *hdrs = NULL;
		if (!p->headers_delivered) {
			hdrs = p->headers;
			p->headers_delivered = true;
		}
		p->cb.on_chunk(p->status_code, "", 0, hdrs, true, p->cb.ctx);
	} else if (p->cb.on_response) {
		p->cb.on_response(p->status_code,
				  p->body ? p->body : "",
				  p->body_len,
				  p->headers ? p->headers : "",
				  p->cb.ctx);
	}

	free_pending(p);
}

/* ---- Public API ---- */

int pvcm_get(const char *path, const struct pvcm_http_callbacks *cb)
{
	return send_http_request(PVCM_HTTP_GET, path, NULL, NULL, 0, cb);
}

int pvcm_post(const char *path, const char *body, size_t body_len,
	      const struct pvcm_http_callbacks *cb)
{
	return send_http_request(PVCM_HTTP_POST, path,
				"Content-Type: application/json\r\n",
				body, body_len, cb);
}

int pvcm_put(const char *path, const char *body, size_t body_len,
	     const struct pvcm_http_callbacks *cb)
{
	return send_http_request(PVCM_HTTP_PUT, path,
				"Content-Type: application/json\r\n",
				body, body_len, cb);
}

int pvcm_delete(const char *path, const struct pvcm_http_callbacks *cb)
{
	return send_http_request(PVCM_HTTP_DELETE, path, NULL, NULL, 0, cb);
}

int pvcm_http(const struct pvcm_http_request *req,
	      const struct pvcm_http_callbacks *cb)
{
	return send_http_request(req->method, req->path, req->headers,
				req->body, req->body_len, cb);
}

/* ---- MCU as HTTP server ---- */

#define MAX_SERVE_HANDLERS 8

static struct {
	const char *path_prefix;
	pvcm_http_handler_t handler;
	void *ctx;
} serve_handlers[MAX_SERVE_HANDLERS];
static int serve_handler_count;

/* pending inbound INVOKE request */
static struct {
	uint8_t stream_id;
	uint8_t method;
	uint16_t path_len;
	uint16_t headers_len;
	uint32_t body_expected;
	size_t stream_offset;
	char *path;
	char *headers;
	char *body;
	size_t body_len;
	bool active;
} invoke_pending;

static void invoke_pending_free(void)
{
	k_free(invoke_pending.path);
	k_free(invoke_pending.headers);
	k_free(invoke_pending.body);
	invoke_pending.path = NULL;
	invoke_pending.headers = NULL;
	invoke_pending.body = NULL;
}

int pvcm_http_serve(const char *path_prefix, pvcm_http_handler_t handler,
		    void *ctx)
{
	if (serve_handler_count >= MAX_SERVE_HANDLERS)
		return -ENOMEM;

	serve_handlers[serve_handler_count].path_prefix = path_prefix;
	serve_handlers[serve_handler_count].handler = handler;
	serve_handlers[serve_handler_count].ctx = ctx;
	serve_handler_count++;

	LOG_INF("registered HTTP handler for %s", path_prefix);
	return 0;
}

int pvcm_http_respond(uint8_t stream_id, uint16_t status_code,
		      const char *headers,
		      const char *body, size_t body_len)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	size_t hlen = headers ? strlen(headers) : 0;

	pvcm_http_req_t resp = {
		.op = PVCM_OP_HTTP_REQ,
		.stream_id = stream_id,
		.direction = PVCM_HTTP_DIR_REPLY,
		.status_code = status_code,
		.path_len = 0,
		.headers_len = (uint16_t)hlen,
		.body_len = (uint32_t)body_len,
	};

	int ret = t->send_frame(&resp, sizeof(resp) - sizeof(uint32_t));
	LOG_INF("HTTP respond: REQ(REPLY) sid=%d status=%d ret=%d",
		stream_id, status_code, ret);

	/* stream headers + body as DATA frames */
	const char *parts[] = { headers, body };
	size_t part_lens[] = { hlen, body_len };
	size_t pi = 0, poff = 0;

	while (pi < 2) {
		pvcm_http_data_t data = {
			.op = PVCM_OP_HTTP_DATA,
			.stream_id = stream_id,
		};
		size_t chunk = 0;

		while (chunk < PVCM_MAX_CHUNK_SIZE && pi < 2) {
			if (!parts[pi] || part_lens[pi] == 0) {
				pi++; poff = 0; continue;
			}
			size_t avail = part_lens[pi] - poff;
			size_t room = PVCM_MAX_CHUNK_SIZE - chunk;
			size_t n = avail < room ? avail : room;
			memcpy(data.data + chunk, parts[pi] + poff, n);
			chunk += n; poff += n;
			if (poff >= part_lens[pi]) { pi++; poff = 0; }
		}

		if (chunk > 0) {
			data.len = (uint16_t)chunk;
			ret = t->send_frame(&data, 4 + chunk);
		}
	}

	pvcm_http_end_t end = {
		.op = PVCM_OP_HTTP_END,
		.stream_id = stream_id,
	};
	ret = t->send_frame(&end, sizeof(end) - sizeof(uint32_t));
	LOG_INF("HTTP respond: END sid=%d ret=%d", stream_id, ret);

	return 0;
}

/* ---- INVOKE handlers (called from server thread) ---- */

void pvcm_client_on_invoke_req(const uint8_t *buf, int len)
{
	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;

	if (req->direction != PVCM_HTTP_DIR_INVOKE)
		return;

	invoke_pending_free();
	invoke_pending.stream_id = req->stream_id;
	invoke_pending.method = req->method;
	invoke_pending.path_len = req->path_len;
	invoke_pending.headers_len = req->headers_len;
	invoke_pending.body_expected = req->body_len;
	invoke_pending.stream_offset = 0;
	invoke_pending.body_len = 0;
	invoke_pending.path = req->path_len > 0
			      ? k_malloc(req->path_len + 1) : NULL;
	invoke_pending.headers = req->headers_len > 0
				 ? k_malloc(req->headers_len + 1) : NULL;
	invoke_pending.body = req->body_len > 0
			      ? k_malloc(req->body_len + 1) : NULL;
	if (invoke_pending.path) invoke_pending.path[0] = '\0';
	if (invoke_pending.headers) invoke_pending.headers[0] = '\0';
	if (invoke_pending.body) invoke_pending.body[0] = '\0';
	invoke_pending.active = true;

	LOG_INF("INVOKE: method=%d path_len=%u hdr_len=%u body_len=%u",
		req->method, req->path_len, req->headers_len, req->body_len);
}

void pvcm_client_on_invoke_data(const uint8_t *buf, int len)
{
	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	if (!invoke_pending.active || d->stream_id != invoke_pending.stream_id)
		return;

	const uint8_t *src = d->data;
	size_t remaining = d->len;
	size_t off = invoke_pending.stream_offset;
	size_t path_end = invoke_pending.path_len;
	size_t hdr_end = path_end + invoke_pending.headers_len;
	size_t body_end = hdr_end + invoke_pending.body_expected;

	while (remaining > 0) {
		if (off < path_end && invoke_pending.path) {
			size_t n = path_end - off;
			if (n > remaining) n = remaining;
			memcpy(invoke_pending.path + off, src, n);
			invoke_pending.path[off + n] = '\0';
			src += n; remaining -= n; off += n;
		} else if (off < hdr_end && invoke_pending.headers) {
			size_t hoff = off - path_end;
			size_t n = hdr_end - off;
			if (n > remaining) n = remaining;
			memcpy(invoke_pending.headers + hoff, src, n);
			invoke_pending.headers[hoff + n] = '\0';
			src += n; remaining -= n; off += n;
		} else if (off < body_end && invoke_pending.body) {
			size_t boff = off - hdr_end;
			size_t n = body_end - off;
			if (n > remaining) n = remaining;
			memcpy(invoke_pending.body + boff, src, n);
			invoke_pending.body[boff + n] = '\0';
			invoke_pending.body_len = boff + n;
			src += n; remaining -= n; off += n;
		} else {
			break;
		}
	}

	invoke_pending.stream_offset = off;
}

void pvcm_client_on_invoke_end(const uint8_t *buf, int len)
{
	if (!invoke_pending.active)
		return;

	invoke_pending.active = false;

	for (int i = 0; i < serve_handler_count; i++) {
		const char *prefix = serve_handlers[i].path_prefix;
		if (invoke_pending.path &&
		    strncmp(invoke_pending.path, prefix, strlen(prefix)) == 0) {
			serve_handlers[i].handler(
				invoke_pending.stream_id,
				invoke_pending.method,
				invoke_pending.path ? invoke_pending.path : "",
				invoke_pending.headers ? invoke_pending.headers : "",
				invoke_pending.body ? invoke_pending.body : "",
				invoke_pending.body_len,
				serve_handlers[i].ctx);
			invoke_pending_free();
			return;
		}
	}

	LOG_WRN("no handler for %s",
		invoke_pending.path ? invoke_pending.path : "(null)");
	pvcm_http_respond(invoke_pending.stream_id, 404,
			  "Content-Type: application/json\r\n",
			  "{\"error\":\"not found\"}", 20);
	invoke_pending_free();
}
