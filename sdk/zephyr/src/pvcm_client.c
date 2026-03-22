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

	/* wait for response (10s timeout) */
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

int pvcm_http_serve(const char *path_prefix, pvcm_http_handler_t handler,
		    void *ctx)
{
	LOG_WRN("pvcm_http_serve not yet implemented");
	return -ENOTSUP;
}

int pvcm_http_respond(uint8_t stream_id, uint16_t status_code,
		      const char *headers,
		      const char *body, size_t body_len)
{
	return -ENOTSUP;
}
