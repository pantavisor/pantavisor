/*
 * PVCM HTTP Client -- simple HTTP over PVCM protocol
 *
 * Implements the simple pvcm_get/post/put/delete API by translating
 * to HTTP_REQ/DATA/END frames. Responses are reassembled from
 * incoming HTTP_REQ(RESPONSE)/DATA/END frames delivered by the
 * server thread.
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

static K_SEM_DEFINE(http_resp_sem, 0, 1);
static K_MUTEX_DEFINE(client_mutex);

/* pending request slot (single in-flight request for simplicity).
 * Response DATA stream carries: headers (headers_expected) + body. */
static struct {
	uint8_t stream_id;
	bool active;
	uint16_t status_code;
	uint16_t headers_expected;  /* from REQ metadata */
	size_t stream_offset;       /* total DATA bytes received */
	char body[2048];
	size_t body_len;
	size_t body_cap;
	char headers[2048];
	size_t headers_len;
	bool complete;
} pending;
static uint8_t next_stream_id = 1;

/* Check if stream_id matches a pending outbound HTTP request */
bool pvcm_client_has_pending_http(uint8_t stream_id)
{
	return pending.active && pending.stream_id == stream_id;
}

/*
 * Called by the server thread when an HTTP response frame arrives.
 * Reassembles the response body from DATA chunks.
 */
void pvcm_client_on_http_req(const uint8_t *buf, int len)
{
	if ((size_t)len < sizeof(pvcm_http_req_t) - sizeof(uint32_t))
		return;

	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;

	LOG_INF("HTTP resp: dir=%d sid=%d pending_sid=%d active=%d status=%d",
		req->direction, req->stream_id,
		pending.stream_id, pending.active, req->status_code);

	if (req->direction != PVCM_HTTP_DIR_RESPONSE)
		return;

	if (!pending.active || req->stream_id != pending.stream_id)
		return;

	pending.status_code = req->status_code;
	pending.headers_expected = req->headers_len;
	pending.stream_offset = 0;
	/* headers and body arrive via DATA frames */
}

/*
 * Demux DATA into headers + body based on stream offset.
 * Response DATA stream: headers (headers_expected bytes) + body.
 */
void pvcm_client_on_http_data(const uint8_t *buf, int len)
{
	if ((size_t)len < 4)
		return;

	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	if (!pending.active || d->stream_id != pending.stream_id)
		return;

	const uint8_t *src = d->data;
	size_t remaining = d->len;
	size_t off = pending.stream_offset;
	size_t hdr_end = pending.headers_expected;

	while (remaining > 0) {
		if (off < hdr_end) {
			/* headers region */
			size_t n = hdr_end - off;
			if (n > remaining) n = remaining;
			if (off + n <= sizeof(pending.headers) - 1) {
				memcpy(pending.headers + off, src, n);
				pending.headers[off + n] = '\0';
				pending.headers_len = off + n;
			}
			src += n; remaining -= n; off += n;
		} else {
			/* body region */
			size_t n = remaining;
			if (pending.body_len + n > pending.body_cap)
				n = pending.body_cap - pending.body_len;
			if (n > 0) {
				memcpy(pending.body + pending.body_len, src, n);
				pending.body_len += n;
			}
			src += n; remaining -= n; off += n;
		}
	}

	pending.stream_offset = off;
}

void pvcm_client_on_http_end(const uint8_t *buf, int len)
{
	if ((size_t)len < 2)
		return;

	uint8_t stream_id = buf[1];

	if (!pending.active || stream_id != pending.stream_id)
		return;

	pending.complete = true;
	LOG_INF("HTTP complete: sid=%d status=%d body=%zu",
		stream_id, pending.status_code, pending.body_len);
	k_sem_give(&http_resp_sem);
}

/*
 * Send an HTTP request and wait for the complete response.
 */
static int do_http_request(uint8_t method, const char *path,
			   const char *req_headers,
			   const char *body, size_t body_len,
			   pvcm_http_cb_t cb, void *ctx)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	k_mutex_lock(&client_mutex, K_FOREVER);

	uint8_t sid = next_stream_id++;
	if (next_stream_id == 0)
		next_stream_id = 1;

	/* set up pending response slot */
	pending.stream_id = sid;
	pending.active = true;
	LOG_INF("HTTP send: sid=%d path=%s", sid, path);
	pending.status_code = 0;
	pending.headers_expected = 0;
	pending.stream_offset = 0;
	pending.body_len = 0;
	pending.body_cap = sizeof(pending.body) - 1;
	pending.headers_len = 0;
	pending.headers[0] = '\0';
	pending.complete = false;
	k_sem_reset(&http_resp_sem);

	/* build and send HTTP_REQ metadata (no data — path+headers+body via DATA) */
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

	t->send_frame(&req, sizeof(req) - sizeof(uint32_t));

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
				pi++;
				poff = 0;
				continue;
			}
			size_t avail = part_lens[pi] - poff;
			size_t room = PVCM_MAX_CHUNK_SIZE - chunk;
			size_t n = avail < room ? avail : room;
			memcpy(data.data + chunk, parts[pi] + poff, n);
			chunk += n;
			poff += n;
			if (poff >= part_lens[pi]) {
				pi++;
				poff = 0;
			}
		}

		if (chunk > 0) {
			data.len = (uint16_t)chunk;
			t->send_frame(&data, 4 + chunk);
		}
	}

	/* send HTTP_END */
	pvcm_http_end_t end = {
		.op = PVCM_OP_HTTP_END,
		.stream_id = sid,
	};
	t->send_frame(&end, sizeof(end) - sizeof(uint32_t));

	/*
	 * Wait for the server thread to receive and dispatch the response.
	 * pvcm_get is called from the shell thread (or app thread), NOT from
	 * the server thread. The server thread continues its recv loop and
	 * dispatches HTTP_REQ(RESPONSE)/DATA/END to pvcm_client_on_http_*
	 * which populates pending and signals http_resp_sem.
	 */
	int ret = k_sem_take(&http_resp_sem, K_SECONDS(10));

	pending.active = false;

	if (ret != 0) {
		LOG_ERR("HTTP request timeout (path=%s)", path);
		k_mutex_unlock(&client_mutex);
		return -ETIMEDOUT;
	}

	/* null-terminate body */
	pending.body[pending.body_len] = '\0';

	LOG_INF("HTTP response: %d, body=%zu bytes",
		pending.status_code, pending.body_len);

	/* deliver to callback */
	if (cb) {
		cb(pending.status_code, pending.body, pending.body_len,
		   pending.headers, ctx);
	}

	k_mutex_unlock(&client_mutex);
	return 0;
}

int pvcm_get(const char *path, pvcm_http_cb_t cb, void *ctx)
{
	return do_http_request(PVCM_HTTP_GET, path, NULL, NULL, 0, cb, ctx);
}

int pvcm_post(const char *path, const char *body, size_t body_len,
	      pvcm_http_cb_t cb, void *ctx)
{
	return do_http_request(PVCM_HTTP_POST, path,
			      "Content-Type: application/json\r\n",
			      body, body_len, cb, ctx);
}

int pvcm_put(const char *path, const char *body, size_t body_len,
	     pvcm_http_cb_t cb, void *ctx)
{
	return do_http_request(PVCM_HTTP_PUT, path,
			      "Content-Type: application/json\r\n",
			      body, body_len, cb, ctx);
}

int pvcm_delete(const char *path, pvcm_http_cb_t cb, void *ctx)
{
	return do_http_request(PVCM_HTTP_DELETE, path, NULL, NULL, 0, cb, ctx);
}

int pvcm_http(const struct pvcm_http_request *req,
	      pvcm_http_cb_t cb, void *ctx)
{
	return do_http_request(req->method, req->path, req->headers,
			      req->body, req->body_len, cb, ctx);
}

/* streaming and server APIs - stubs for now */

pvcm_http_stream_t *pvcm_http_download(const char *path,
					pvcm_http_stream_cb_t cb, void *ctx)
{
	LOG_WRN("pvcm_http_download not yet implemented");
	return NULL;
}

pvcm_http_stream_t *pvcm_http_upload(uint8_t method, const char *path,
				     const char *headers,
				     uint32_t total_size)
{
	LOG_WRN("pvcm_http_upload not yet implemented");
	return NULL;
}

int pvcm_http_stream_write(pvcm_http_stream_t *s, const void *data,
			   size_t len)
{
	return -ENOTSUP;
}

int pvcm_http_stream_close(pvcm_http_stream_t *s)
{
	return -ENOTSUP;
}

/* ---- MCU as HTTP server ---- */

#define MAX_SERVE_HANDLERS 8

static struct {
	const char *path_prefix;
	pvcm_http_handler_t handler;
	void *ctx;
} serve_handlers[MAX_SERVE_HANDLERS];
static int serve_handler_count;

/* pending inbound request assembled from INVOKE DATA stream.
 * DATA carries: path (path_len) + headers (headers_len) + body. */
static struct {
	uint8_t stream_id;
	uint8_t method;
	uint16_t path_len;
	uint16_t headers_len;
	size_t stream_offset;
	char path[1024];
	char headers[2048];
	char body[4096];
	size_t body_len;
	bool active;
} invoke_pending;

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

	/* send HTTP_REQ(REPLY) metadata */
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

	/* send HTTP_END */
	pvcm_http_end_t end = {
		.op = PVCM_OP_HTTP_END,
		.stream_id = stream_id,
	};
	ret = t->send_frame(&end, sizeof(end) - sizeof(uint32_t));
	LOG_INF("HTTP respond: END sid=%d ret=%d", stream_id, ret);

	return 0;
}

/*
 * Called by server thread for inbound INVOKE requests from pvcm-run.
 */
void pvcm_client_on_invoke_req(const uint8_t *buf, int len)
{
	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;

	if (req->direction != PVCM_HTTP_DIR_INVOKE)
		return;

	invoke_pending.stream_id = req->stream_id;
	invoke_pending.method = req->method;
	invoke_pending.path_len = req->path_len;
	invoke_pending.headers_len = req->headers_len;
	invoke_pending.stream_offset = 0;
	invoke_pending.body_len = 0;
	invoke_pending.path[0] = '\0';
	invoke_pending.headers[0] = '\0';
	invoke_pending.active = true;

	LOG_INF("INVOKE: method=%d path_len=%u hdr_len=%u body_len=%u",
		req->method, req->path_len, req->headers_len, req->body_len);
}

/* Demux INVOKE DATA into path + headers + body */
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

	while (remaining > 0) {
		if (off < path_end) {
			size_t n = path_end - off;
			if (n > remaining) n = remaining;
			if (off + n <= sizeof(invoke_pending.path) - 1) {
				memcpy(invoke_pending.path + off, src, n);
				invoke_pending.path[off + n] = '\0';
			}
			src += n; remaining -= n; off += n;
		} else if (off < hdr_end) {
			size_t hoff = off - path_end;
			size_t n = hdr_end - off;
			if (n > remaining) n = remaining;
			if (hoff + n <= sizeof(invoke_pending.headers) - 1) {
				memcpy(invoke_pending.headers + hoff, src, n);
				invoke_pending.headers[hoff + n] = '\0';
			}
			src += n; remaining -= n; off += n;
		} else {
			size_t n = remaining;
			if (invoke_pending.body_len + n >
			    sizeof(invoke_pending.body) - 1)
				n = sizeof(invoke_pending.body) - 1 -
				    invoke_pending.body_len;
			if (n > 0) {
				memcpy(invoke_pending.body +
				       invoke_pending.body_len, src, n);
				invoke_pending.body_len += n;
			}
			src += n; remaining -= n; off += n;
		}
	}

	invoke_pending.stream_offset = off;
}

void pvcm_client_on_invoke_end(const uint8_t *buf, int len)
{
	if (!invoke_pending.active)
		return;

	invoke_pending.body[invoke_pending.body_len] = '\0';
	invoke_pending.active = false;

	/* find matching handler */
	for (int i = 0; i < serve_handler_count; i++) {
		const char *prefix = serve_handlers[i].path_prefix;
		if (strncmp(invoke_pending.path, prefix, strlen(prefix)) == 0) {
			serve_handlers[i].handler(
				invoke_pending.method,
				invoke_pending.path,
				invoke_pending.headers,
				invoke_pending.body,
				invoke_pending.body_len,
				serve_handlers[i].ctx);
			return;
		}
	}

	/* no handler — send 404 */
	LOG_WRN("no handler for %s", invoke_pending.path);
	pvcm_http_respond(invoke_pending.stream_id, 404,
			  "Content-Type: application/json\r\n",
			  "{\"error\":\"not found\"}", 20);
}

/* Helper: get the stream_id of the current invoke being handled */
uint8_t pvcm_get_invoke_stream_id(void)
{
	return invoke_pending.stream_id;
}
