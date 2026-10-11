/*
 * Pantavisor RTOS SDK — public API
 *
 * All HTTP and D-Bus calls are asynchronous. The caller sends the
 * request and returns immediately. Responses arrive via callbacks
 * on the PVCM server thread.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PANTAVISOR_PVCM_H
#define PANTAVISOR_PVCM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pantavisor/pvcm_protocol.h>

/* ---- Health monitoring ---- */

typedef uint8_t (*pvcm_health_cb_t)(void);
void pvcm_register_health_cb(pvcm_health_cb_t cb);

/* ---- HTTP API (requires CONFIG_PANTAVISOR_BRIDGE) ----
 *
 * All calls are async — send request, return immediately.
 * Response delivered via callbacks on the server thread.
 */

/* Error codes for on_error callback */
#define PVCM_ERR_TIMEOUT    (-1)  /* no response within deadline */
#define PVCM_ERR_OVERSIZED  (-2)  /* body > 32K with on_response (use on_chunk) */
#define PVCM_ERR_SEND       (-3)  /* failed to send request frames */
#define PVCM_ERR_NOMEM      (-4)  /* allocation failed */

/* Full response — called once with complete body.
 * Only used when on_response is set and body fits in 32K. */
typedef void (*pvcm_http_cb_t)(uint16_t status_code,
			       const char *body, size_t body_len,
			       const char *headers, void *ctx);

/* Chunk callback — called per body chunk, any size.
 * headers is non-NULL on the first call only.
 * is_last=true on the final chunk. */
typedef void (*pvcm_http_chunk_cb_t)(uint16_t status_code,
				     const char *data, size_t data_len,
				     const char *headers, bool is_last,
				     void *ctx);

/* Error callback — transport, timeout, oversized, etc. */
typedef void (*pvcm_http_error_cb_t)(int error, const char *msg, void *ctx);

struct pvcm_http_callbacks {
	pvcm_http_cb_t       on_response;  /* set this OR on_chunk */
	pvcm_http_chunk_cb_t on_chunk;     /* streaming body delivery */
	pvcm_http_error_cb_t on_error;     /* errors (timeout, etc.) */
	void *ctx;
};

/* Simple API — async GET/POST/PUT/DELETE */
int pvcm_get(const char *path, const struct pvcm_http_callbacks *cb);
int pvcm_post(const char *path, const char *body, size_t body_len,
	      const struct pvcm_http_callbacks *cb);
int pvcm_put(const char *path, const char *body, size_t body_len,
	     const struct pvcm_http_callbacks *cb);
int pvcm_delete(const char *path, const struct pvcm_http_callbacks *cb);

/* Generic API — full control over method, headers, body */
struct pvcm_http_request {
	uint8_t     method;      /* PVCM_HTTP_GET, POST, etc. */
	const char *path;
	const char *headers;     /* "Key: Value\r\n..." or NULL */
	const char *body;
	size_t      body_len;
};

int pvcm_http(const struct pvcm_http_request *req,
	      const struct pvcm_http_callbacks *cb);

/* ---- MCU as HTTP server ---- */

typedef void (*pvcm_http_handler_t)(uint8_t stream_id,
				    uint8_t method, const char *path,
				    const char *headers,
				    const char *body, size_t body_len,
				    void *ctx);

int pvcm_http_serve(const char *path_prefix, pvcm_http_handler_t handler,
		    void *ctx);

int pvcm_http_respond(uint8_t stream_id, uint16_t status_code,
		      const char *headers,
		      const char *body, size_t body_len);

/* ---- D-Bus Gateway API (requires CONFIG_PANTAVISOR_DBUS) ---- */

typedef void (*pvcm_dbus_cb_t)(uint8_t error, const char *result,
			       size_t result_len, void *ctx);

int pvcm_dbus_call(const char *dest, const char *obj_path,
		   const char *interface, const char *member,
		   const char *args_json,
		   pvcm_dbus_cb_t cb, void *ctx);

typedef void (*pvcm_dbus_signal_cb_t)(const char *sender,
				      const char *obj_path,
				      const char *interface,
				      const char *member,
				      const char *args_json, void *ctx);

int pvcm_dbus_subscribe(const char *sender, const char *obj_path,
			const char *interface, const char *signal_name,
			pvcm_dbus_signal_cb_t cb, void *ctx);

int pvcm_dbus_unsubscribe(int sub_id);

#endif /* PANTAVISOR_PVCM_H */
