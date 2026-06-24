/*
 * PVCM Server -- mandatory protocol server task
 *
 * Handles all incoming PVCM frames from pvcm-run (Linux side):
 *  - Responds to HELLO with HELLO_RESP
 *  - Responds to QUERY_STATE with current boot state
 *  - Dispatches other opcodes to registered handlers
 *
 * Runs as a dedicated Zephyr thread, started automatically.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>
#include <pantavisor/pvcm_transport.h>

LOG_MODULE_REGISTER(pvcm_server, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_PANTAVISOR_BRIDGE
/* HTTP client/server callbacks (from pvcm_client.c) */
extern void pvcm_client_on_http_req(const uint8_t *buf, int len);
extern void pvcm_client_on_http_data(const uint8_t *buf, int len);
extern void pvcm_client_on_http_end(const uint8_t *buf, int len);
extern bool pvcm_client_has_pending_http(uint8_t stream_id);
extern void pvcm_fs_on_resp(const uint8_t *buf, int len);
extern void pvcm_fs_on_data(const uint8_t *buf, int len);
extern void pvcm_fs_on_end(const uint8_t *buf, int len);
extern void pvcm_echo_on_resp(const uint8_t *buf, int len);
extern void pvcm_client_on_invoke_req(const uint8_t *buf, int len);
extern void pvcm_client_on_invoke_data(const uint8_t *buf, int len);
extern void pvcm_client_on_invoke_end(const uint8_t *buf, int len);
#endif

#ifdef CONFIG_PANTAVISOR_DBUS
/* D-Bus callbacks (from pvcm_dbus.c) */
extern void pvcm_dbus_on_call_resp(const uint8_t *buf, int len);
extern void pvcm_dbus_on_signal(const uint8_t *buf, int len);
extern void pvcm_dbus_on_data(const uint8_t *buf, int len);
#endif

#define PVCM_SERVER_STACK_SIZE  4096
#define PVCM_SERVER_PRIORITY    7

static const struct pvcm_transport *transport;

static void handle_hello(void)
{
	pvcm_hello_resp_t resp = {
		.op = PVCM_OP_HELLO_RESP,
		.protocol_version = PVCM_PROTOCOL_VERSION,
		.baudrate = PVCM_DEFAULT_BAUDRATE,
		.max_msg_size = 512,
		.mcu_fw_version = 1,
	};

	LOG_INF("HELLO received, sending HELLO_RESP");
	transport->send_frame(&resp, sizeof(resp) - sizeof(uint32_t));
}

static void handle_query_state(void)
{
	/* TODO: read actual boot state from flash */
	pvcm_state_resp_t resp = {
		.op = PVCM_OP_STATE_RESP,
		.status = PVCM_HEALTH_OK,
		.stable_slot = 0,
		.tryboot_slot = 0,
		.tryboot_pending = 0,
		.tryboot_trying = 0,
		.stable_rev = 1,
		.tryboot_rev = 0,
		.mcu_fw_version = 1,
	};

	LOG_INF("QUERY_STATE received, sending STATE_RESP");
	transport->send_frame(&resp, sizeof(resp) - sizeof(uint32_t));
}

static void handle_commit(void)
{
	LOG_INF("COMMIT received");
	/* TODO: write stable state to flash */

	pvcm_ack_t ack = {
		.op = PVCM_OP_ACK,
		.ref_op = PVCM_OP_COMMIT,
	};
	transport->send_frame(&ack, sizeof(ack) - sizeof(uint32_t));
}

static void handle_set_tryboot(void)
{
	LOG_INF("SET_TRYBOOT received");
	/* TODO: write tryboot state to flash */

	pvcm_ack_t ack = {
		.op = PVCM_OP_ACK,
		.ref_op = PVCM_OP_SET_TRYBOOT,
	};
	transport->send_frame(&ack, sizeof(ack) - sizeof(uint32_t));
}

void pvcm_server_dispatch(const uint8_t *buf, int len)
{
	if (len < 1)
		return;

	uint8_t op = buf[0];

	switch (op) {
	case PVCM_OP_HELLO:
		handle_hello();
		break;
	case PVCM_OP_QUERY_STATE:
		handle_query_state();
		break;
	case PVCM_OP_COMMIT:
		handle_commit();
		break;
	case PVCM_OP_SET_TRYBOOT:
		handle_set_tryboot();
		break;
	case PVCM_OP_ROLLBACK:
		LOG_WRN("ROLLBACK received");
		/* TODO: revert to stable slot */
		break;
#ifdef CONFIG_PANTAVISOR_BRIDGE
	/* HTTP frames — route based on direction */
	case PVCM_OP_HTTP_REQ: {
		const pvcm_http_req_t *hreq = (const pvcm_http_req_t *)buf;
		LOG_INF("HTTP_REQ: dir=%d sid=%d status=%d path=%u hdr=%u body=%u",
			hreq->direction, hreq->stream_id,
			hreq->status_code, hreq->path_len,
			hreq->headers_len, hreq->body_len);
		if (hreq->direction == PVCM_HTTP_DIR_RESPONSE)
			pvcm_client_on_http_req(buf, len);
		else if (hreq->direction == PVCM_HTTP_DIR_INVOKE)
			pvcm_client_on_invoke_req(buf, len);
		break;
	}
	case PVCM_OP_HTTP_DATA: {
		const pvcm_http_data_t *d = (const pvcm_http_data_t *)buf;
		/* route DATA to the correct pending handler by stream_id */
		if (pvcm_client_has_pending_http(d->stream_id))
			pvcm_client_on_http_data(buf, len);
		else
			pvcm_client_on_invoke_data(buf, len);
		break;
	}
	case PVCM_OP_HTTP_END: {
		uint8_t sid = buf[1];
		if (pvcm_client_has_pending_http(sid))
			pvcm_client_on_http_end(buf, len);
		else
			pvcm_client_on_invoke_end(buf, len);
		break;
	}
#endif
#ifdef CONFIG_PANTAVISOR_DBUS
	case PVCM_OP_DBUS_CALL_RESP:
		pvcm_dbus_on_call_resp(buf, len);
		break;
	case PVCM_OP_DBUS_SIGNAL:
		pvcm_dbus_on_signal(buf, len);
		break;
	case PVCM_OP_DBUS_DATA:
		pvcm_dbus_on_data(buf, len);
		break;
#endif
#ifdef CONFIG_PANTAVISOR_FS
	case PVCM_OP_FS_RESP:
		pvcm_fs_on_resp(buf, len);
		break;
	case PVCM_OP_FS_DATA:
		pvcm_fs_on_data(buf, len);
		break;
	case PVCM_OP_FS_END:
		pvcm_fs_on_end(buf, len);
		break;
#endif
	case PVCM_OP_ECHO_RESP:
		pvcm_echo_on_resp(buf, len);
		break;
	default:
		LOG_DBG("unhandled opcode 0x%02x (len=%d)", op, len);
		break;
	}
}

static void pvcm_server_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("PVCM server starting (protocol v%d)", PVCM_PROTOCOL_VERSION);

	transport = pvcm_transport_get();
	if (!transport) {
		LOG_ERR("no transport available");
		return;
	}

	if (transport->init() < 0) {
		LOG_ERR("transport init failed");
		return;
	}

	LOG_INF("transport ready, entering recv loop");

	uint8_t buf[PVCM_MAX_CHUNK_SIZE + 8]; /* max payload + header room */
	while (1) {
		int len = transport->recv_frame(buf, sizeof(buf), 1000);
		if (len > 0) {
			pvcm_server_dispatch(buf, len);
		}
		/* timeout is normal — just loop and let heartbeat run */
	}
}

K_THREAD_DEFINE(pvcm_server, PVCM_SERVER_STACK_SIZE,
		pvcm_server_thread, NULL, NULL, NULL,
		PVCM_SERVER_PRIORITY, 0, 0);
