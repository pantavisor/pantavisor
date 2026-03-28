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

/* pending request slot (single in-flight request for simplicity) */
static struct {
	uint8_t stream_id;
	bool active;
	uint16_t status_code;
	char body[2048];
	size_t body_len;
	size_t body_cap;
	char headers[512];
	size_t headers_len;
	bool complete;
} pending;
static uint8_t next_stream_id = 1;

/*
 * Called by the server thread when an HTTP response frame arrives.
 * Reassembles the response body from DATA chunks.
 */
void pvcm_client_on_http_req(const uint8_t *buf, int len)
{
	if ((size_t)len < sizeof(pvcm_http_req_t) - sizeof(uint32_t) -
			  sizeof(((pvcm_http_req_t *)0)->data))
		return;

	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;

	if (req->direction != PVCM_HTTP_DIR_RESPONSE)
		return;

	if (!pending.active || req->stream_id != pending.stream_id)
		return;

	pending.status_code = req->status_code;

	/* extract headers from data field */
	uint16_t path_len = req->path_len;
	uint16_t hdr_len = req->headers_len;
	if (hdr_len > 0 && hdr_len < sizeof(pending.headers)) {
		memcpy(pending.headers, req->data + path_len, hdr_len);
		pending.headers[hdr_len] = '\0';
		pending.headers_len = hdr_len;
	}
}

void pvcm_client_on_http_data(const uint8_t *buf, int len)
{
	if ((size_t)len < 4)
		return;

	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	if (!pending.active || d->stream_id != pending.stream_id)
		return;

	size_t chunk_len = d->len;
	if (pending.body_len + chunk_len > pending.body_cap)
		chunk_len = pending.body_cap - pending.body_len;

	if (chunk_len > 0) {
		memcpy(pending.body + pending.body_len, d->data, chunk_len);
		pending.body_len += chunk_len;
	}
}

void pvcm_client_on_http_end(const uint8_t *buf, int len)
{
	if ((size_t)len < 2)
		return;

	uint8_t stream_id = buf[1];

	if (!pending.active || stream_id != pending.stream_id)
		return;

	pending.complete = true;
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
	pending.status_code = 0;
	pending.body_len = 0;
	pending.body_cap = sizeof(pending.body) - 1;
	pending.headers_len = 0;
	pending.headers[0] = '\0';
	pending.complete = false;
	k_sem_reset(&http_resp_sem);

	/* build and send HTTP_REQ */
	pvcm_http_req_t req = {
		.op = PVCM_OP_HTTP_REQ,
		.stream_id = sid,
		.direction = PVCM_HTTP_DIR_REQUEST,
		.method = method,
		.status_code = 0,
		.total_body_size = (uint32_t)body_len,
	};

	size_t path_len = strlen(path);
	if (path_len > sizeof(req.data) - 1)
		path_len = sizeof(req.data) - 1;
	req.path_len = (uint16_t)path_len;

	size_t hdr_len = req_headers ? strlen(req_headers) : 0;
	if (path_len + hdr_len > sizeof(req.data))
		hdr_len = sizeof(req.data) - path_len;
	req.headers_len = (uint16_t)hdr_len;

	memcpy(req.data, path, path_len);
	if (hdr_len > 0)
		memcpy(req.data + path_len, req_headers, hdr_len);

	t->send_frame(&req, sizeof(req) - sizeof(uint32_t));

	/* send body chunks if any */
	if (body && body_len > 0) {
		size_t offset = 0;
		while (offset < body_len) {
			pvcm_http_data_t data = {
				.op = PVCM_OP_HTTP_DATA,
				.stream_id = sid,
			};
			size_t chunk = body_len - offset;
			if (chunk > PVCM_MAX_CHUNK_SIZE)
				chunk = PVCM_MAX_CHUNK_SIZE;
			data.len = (uint16_t)chunk;
			memcpy(data.data, body + offset, chunk);
			t->send_frame(&data,
				      4 + chunk); /* op + stream_id + len + data */
			offset += chunk;
		}
	}

	/* send HTTP_END */
	pvcm_http_end_t end = {
		.op = PVCM_OP_HTTP_END,
		.stream_id = sid,
	};
	t->send_frame(&end, sizeof(end) - sizeof(uint32_t));

	/* Pump recv_frame ourselves while waiting for the response.
	 * We can't use k_sem_take because the server thread (which
	 * normally calls recv_frame) is blocked here — deadlock.
	 * Instead, read frames in a loop and dispatch them.
	 */
	extern void pvcm_server_dispatch(const uint8_t *buf, int len);
	uint8_t rx[1024];
	int64_t deadline = k_uptime_get() + 10000; /* 10s timeout */
	int ret = -ETIMEDOUT;

	while (k_uptime_get() < deadline) {
		/* sleep briefly to let the management thread (COOP 8)
		 * process vring and deliver frames to our queue */
		k_sleep(K_MSEC(50));

		int flen = t->recv_frame(rx, sizeof(rx), 200);
		if (flen > 0) {
			pvcm_server_dispatch(rx, flen);
		}
		if (pending.complete) {
			ret = 0;
			break;
		}
	}

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

/* pending inbound request being assembled from INVOKE frames */
static struct {
	uint8_t stream_id;
	uint8_t method;
	char path[256];
	char headers[512];
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

	/* send HTTP_REQ(REPLY) */
	pvcm_http_req_t resp = {
		.op = PVCM_OP_HTTP_REQ,
		.stream_id = stream_id,
		.direction = PVCM_HTTP_DIR_REPLY,
		.status_code = status_code,
		.total_body_size = (uint32_t)body_len,
	};

	size_t hlen = headers ? strlen(headers) : 0;
	if (hlen > sizeof(resp.data))
		hlen = sizeof(resp.data);
	resp.headers_len = (uint16_t)hlen;
	resp.path_len = 0;
	if (hlen > 0)
		memcpy(resp.data, headers, hlen);

	int ret = t->send_frame(&resp, sizeof(resp) - sizeof(uint32_t));
	LOG_INF("HTTP respond: sent REQ(REPLY) sid=%d status=%d ret=%d",
		stream_id, status_code, ret);

	/* send body chunks */
	if (body && body_len > 0) {
		size_t offset = 0;
		while (offset < body_len) {
			pvcm_http_data_t data = {
				.op = PVCM_OP_HTTP_DATA,
				.stream_id = stream_id,
			};
			size_t chunk = body_len - offset;
			if (chunk > PVCM_MAX_CHUNK_SIZE)
				chunk = PVCM_MAX_CHUNK_SIZE;
			data.len = (uint16_t)chunk;
			memcpy(data.data, body + offset, chunk);
			ret = t->send_frame(&data, 4 + chunk);
			LOG_INF("HTTP respond: sent DATA sid=%d chunk=%zu ret=%d",
				stream_id, chunk, ret);
			offset += chunk;
		}
	}

	/* send HTTP_END */
	pvcm_http_end_t end = {
		.op = PVCM_OP_HTTP_END,
		.stream_id = stream_id,
	};
	ret = t->send_frame(&end, sizeof(end) - sizeof(uint32_t));
	LOG_INF("HTTP respond: sent END sid=%d ret=%d", stream_id, ret);

	return 0;
}

/*
 * Called by server thread for inbound INVOKE requests from pvcm-proxy.
 */
void pvcm_client_on_invoke_req(const uint8_t *buf, int len)
{
	const pvcm_http_req_t *req = (const pvcm_http_req_t *)buf;

	if (req->direction != PVCM_HTTP_DIR_INVOKE)
		return;

	invoke_pending.stream_id = req->stream_id;
	invoke_pending.method = req->method;
	invoke_pending.body_len = 0;
	invoke_pending.active = true;

	size_t plen = req->path_len;
	if (plen > sizeof(invoke_pending.path) - 1)
		plen = sizeof(invoke_pending.path) - 1;
	memcpy(invoke_pending.path, req->data, plen);
	invoke_pending.path[plen] = '\0';

	size_t hlen = req->headers_len;
	if (hlen > sizeof(invoke_pending.headers) - 1)
		hlen = sizeof(invoke_pending.headers) - 1;
	if (hlen > 0)
		memcpy(invoke_pending.headers, req->data + plen, hlen);
	invoke_pending.headers[hlen] = '\0';

	LOG_INF("INVOKE: %s %s",
		req->method == PVCM_HTTP_GET ? "GET" :
		req->method == PVCM_HTTP_POST ? "POST" : "?",
		invoke_pending.path);
}

void pvcm_client_on_invoke_data(const uint8_t *buf, int len)
{
	const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;

	if (!invoke_pending.active || d->stream_id != invoke_pending.stream_id)
		return;

	size_t chunk = d->len;
	if (invoke_pending.body_len + chunk > sizeof(invoke_pending.body) - 1)
		chunk = sizeof(invoke_pending.body) - 1 - invoke_pending.body_len;

	memcpy(invoke_pending.body + invoke_pending.body_len, d->data, chunk);
	invoke_pending.body_len += chunk;
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
