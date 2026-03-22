/*
 * PVCM HTTP Client -- simple and streaming HTTP over PVCM
 *
 * Translates the MCU SDK HTTP API into PVCM_OP_HTTP_REQ/DATA/END
 * frames sent via the transport.
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

/* TODO: implement HTTP request/response framing
 *
 * Simple API (pvcm_get/post/put/delete):
 * 1. Allocate stream_id
 * 2. Send HTTP_REQ frame with method + path + headers
 * 3. If body: send HTTP_DATA chunks
 * 4. Send HTTP_END
 * 5. Wait for HTTP_REQ response + HTTP_DATA chunks + HTTP_END
 * 6. Reassemble body, call callback with complete response
 *
 * Streaming API (pvcm_http_download/upload):
 * 1-4 same as simple
 * 5. Deliver each HTTP_DATA chunk to callback as it arrives
 * 6. Call callback with is_last=true on HTTP_END
 *
 * Server API (pvcm_http_serve):
 * 1. Register path prefix + handler
 * 2. When HTTP_REQ arrives with dir=INVOKE, match path
 * 3. Reassemble body from HTTP_DATA chunks
 * 4. Call handler
 * 5. Handler calls pvcm_http_respond() which sends HTTP_REQ(REPLY)
 *    + HTTP_DATA + HTTP_END
 */

static uint8_t next_stream_id = 1;

int pvcm_get(const char *path, pvcm_http_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	LOG_WRN("pvcm_get not yet implemented");
	return -ENOTSUP;
}

int pvcm_post(const char *path, const char *body, size_t body_len,
	      pvcm_http_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(body);
	ARG_UNUSED(body_len);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	LOG_WRN("pvcm_post not yet implemented");
	return -ENOTSUP;
}

int pvcm_put(const char *path, const char *body, size_t body_len,
	     pvcm_http_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(body);
	ARG_UNUSED(body_len);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	LOG_WRN("pvcm_put not yet implemented");
	return -ENOTSUP;
}

int pvcm_delete(const char *path, pvcm_http_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	LOG_WRN("pvcm_delete not yet implemented");
	return -ENOTSUP;
}

int pvcm_http(const struct pvcm_http_request *req,
	      pvcm_http_cb_t cb, void *ctx)
{
	ARG_UNUSED(req);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	LOG_WRN("pvcm_http not yet implemented");
	return -ENOTSUP;
}

pvcm_http_stream_t *pvcm_http_download(const char *path,
					pvcm_http_stream_cb_t cb, void *ctx)
{
	ARG_UNUSED(path);
	ARG_UNUSED(cb);
	ARG_UNUSED(ctx);
	LOG_WRN("pvcm_http_download not yet implemented");
	return NULL;
}

pvcm_http_stream_t *pvcm_http_upload(uint8_t method, const char *path,
				     const char *headers,
				     uint32_t total_size)
{
	ARG_UNUSED(method);
	ARG_UNUSED(path);
	ARG_UNUSED(headers);
	ARG_UNUSED(total_size);
	LOG_WRN("pvcm_http_upload not yet implemented");
	return NULL;
}

int pvcm_http_stream_write(pvcm_http_stream_t *s, const void *data,
			   size_t len)
{
	ARG_UNUSED(s);
	ARG_UNUSED(data);
	ARG_UNUSED(len);
	return -ENOTSUP;
}

int pvcm_http_stream_close(pvcm_http_stream_t *s)
{
	ARG_UNUSED(s);
	return -ENOTSUP;
}

int pvcm_http_serve(const char *path_prefix, pvcm_http_handler_t handler,
		    void *ctx)
{
	ARG_UNUSED(path_prefix);
	ARG_UNUSED(handler);
	ARG_UNUSED(ctx);
	LOG_WRN("pvcm_http_serve not yet implemented");
	return -ENOTSUP;
}

int pvcm_http_respond(uint8_t stream_id, uint16_t status_code,
		      const char *headers,
		      const char *body, size_t body_len)
{
	ARG_UNUSED(stream_id);
	ARG_UNUSED(status_code);
	ARG_UNUSED(headers);
	ARG_UNUSED(body);
	ARG_UNUSED(body_len);
	return -ENOTSUP;
}
