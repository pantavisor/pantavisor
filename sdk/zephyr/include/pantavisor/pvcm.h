/*
 * Pantavisor RTOS SDK -- Public API
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PANTAVISOR_PVCM_H
#define PANTAVISOR_PVCM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Health callback -- called by heartbeat module before each heartbeat.
 * Return PVCM_HEALTH_OK or PVCM_HEALTH_DEGRADED.
 */
typedef uint8_t (*pvcm_health_cb_t)(void);

void pvcm_register_health_cb(pvcm_health_cb_t cb);

/* ---- Simple HTTP API (requires CONFIG_PANTAVISOR_BRIDGE) ----
 *
 * For small JSON requests/responses. The SDK collects all response
 * chunks and delivers the complete body to the callback.
 */
typedef void (*pvcm_http_cb_t)(uint16_t status_code,
			       const char *body, size_t body_len,
			       const char *headers, void *ctx);

int pvcm_get(const char *path, pvcm_http_cb_t cb, void *ctx);
int pvcm_post(const char *path, const char *body, size_t body_len,
	      pvcm_http_cb_t cb, void *ctx);
int pvcm_put(const char *path, const char *body, size_t body_len,
	     pvcm_http_cb_t cb, void *ctx);
int pvcm_delete(const char *path, pvcm_http_cb_t cb, void *ctx);

/* ---- Generic HTTP API ----
 *
 * Full control over method, headers, and body. Use for non-standard
 * methods, custom headers, or when you need response headers.
 */
struct pvcm_http_request {
	uint8_t  method;        /* PVCM_HTTP_GET, POST, etc. */
	const char *path;
	const char *headers;    /* "Key: Value\r\n..." or NULL */
	const char *body;
	size_t   body_len;
};

int pvcm_http(const struct pvcm_http_request *req,
	      pvcm_http_cb_t cb, void *ctx);

/* ---- Streaming HTTP API ----
 *
 * For large transfers (firmware images, assets, sensor logs).
 * Data is delivered/sent in chunks — no full-body buffering.
 */
typedef struct pvcm_http_stream pvcm_http_stream_t;

/* Download: callback called for each chunk received */
typedef void (*pvcm_http_stream_cb_t)(const void *data, size_t len,
				      bool is_last, void *ctx);

/* Start a streaming download */
pvcm_http_stream_t *pvcm_http_download(const char *path,
					pvcm_http_stream_cb_t cb, void *ctx);

/* Start a streaming upload (POST/PUT) */
pvcm_http_stream_t *pvcm_http_upload(uint8_t method, const char *path,
				     const char *headers,
				     uint32_t total_size);

/* Send a chunk of upload data */
int pvcm_http_stream_write(pvcm_http_stream_t *s, const void *data,
			   size_t len);

/* Finish the stream (upload: sends HTTP_END, download: cleanup) */
int pvcm_http_stream_close(pvcm_http_stream_t *s);

/* ---- MCU as HTTP server ----
 *
 * Register handlers for inbound HTTP requests from Linux containers.
 */
typedef void (*pvcm_http_handler_t)(uint8_t method, const char *path,
				    const char *headers,
				    const char *body, size_t body_len,
				    void *ctx);

int pvcm_http_serve(const char *path_prefix, pvcm_http_handler_t handler,
		    void *ctx);

/* Send response to an inbound request */
int pvcm_http_respond(uint8_t stream_id, uint16_t status_code,
		      const char *headers,
		      const char *body, size_t body_len);

/* ---- Log API (for non-Zephyr log users, e.g. FreeRTOS compat) ---- */

void pvcm_log(uint8_t level, const char *module, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* PANTAVISOR_PVCM_H */
