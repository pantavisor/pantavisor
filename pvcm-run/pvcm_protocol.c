/*
 * pvcm-run protocol handler
 *
 * Implements the Linux side of the PVCM protocol:
 *  - HELLO/HELLO_RESP handshake
 *  - Heartbeat reception and health tracking
 *  - Log forwarding to stdout (pantavisor log server)
 *  - ACK/NACK handling
 *  - Frame dispatch to HTTP bridge and D-Bus bridge
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_protocol.h"
#include "pvcm_bridge.h"
#include "pvcm_dbus_bridge.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static const char *log_level_str(uint8_t level)
{
	switch (level) {
	case PVCM_LOG_ERR: return "ERR";
	case PVCM_LOG_WRN: return "WRN";
	case PVCM_LOG_INF: return "INF";
	case PVCM_LOG_DBG: return "DBG";
	default:           return "???";
	}
}

/*
 * Send HELLO and wait for HELLO_RESP.
 * Uses blocking recv_frame — must be called before the event loop.
 * Returns 0 on success, -1 on error, -2 on timeout.
 */
int pvcm_handshake(struct pvcm_session *s)
{
	pvcm_hello_t hello = {
		.op = PVCM_OP_HELLO,
	};

	fprintf(stdout, "[pvcm-run] sending HELLO\n");

	if (s->transport->send_frame(s->transport, &hello,
				     sizeof(hello) - sizeof(uint32_t)) < 0) {
		fprintf(stderr, "[pvcm-run] failed to send HELLO\n");
		return -1;
	}

	/* wait for HELLO_RESP, skipping any interleaved frames
	 * (heartbeats may arrive before the MCU processes our HELLO) */
	uint8_t buf[256];
	int attempts = 10; /* max frames to skip */

	while (attempts-- > 0) {
		int len = s->transport->recv_frame(s->transport, buf,
						   sizeof(buf), 5000);
		if (len < 0) {
			fprintf(stderr, "[pvcm-run] no HELLO_RESP "
				"(len=%d)\n", len);
			return len;
		}

		if (len >= 1 && buf[0] == PVCM_OP_HELLO_RESP) {
			pvcm_hello_resp_t *resp = (pvcm_hello_resp_t *)buf;
			s->protocol_version = resp->protocol_version;
			s->mcu_fw_version = resp->mcu_fw_version;
			s->connected = true;
			s->last_heartbeat_time = time(NULL);

			fprintf(stdout, "[pvcm-run] MCU connected: "
				"protocol=v%d fw=v%d baudrate=%u\n",
				resp->protocol_version,
				resp->mcu_fw_version,
				resp->baudrate);
			return 0;
		}

		/* not HELLO_RESP — log and keep waiting */
		fprintf(stdout, "[pvcm-run] skipping frame op=0x%02x "
			"during handshake\n", buf[0]);
	}

	fprintf(stderr, "[pvcm-run] HELLO_RESP not received after "
		"skipping %d frames\n", 10);
	return -1;
}

/*
 * Handle one received heartbeat.
 */
static void handle_heartbeat(struct pvcm_session *s, const uint8_t *buf,
			     int len)
{
	if ((size_t)len < sizeof(pvcm_heartbeat_t) - sizeof(uint32_t))
		return;

	const pvcm_heartbeat_t *hb = (const pvcm_heartbeat_t *)buf;
	s->last_health_status = hb->status;
	s->last_heartbeat_uptime = hb->uptime_s;
	s->crash_count = hb->crash_count;
	s->last_heartbeat_time = time(NULL);

	fprintf(stdout, "[pvcm-run] heartbeat: status=%s uptime=%us "
		"crashes=%d\n",
		hb->status == PVCM_HEALTH_OK ? "OK" : "DEGRADED",
		hb->uptime_s, hb->crash_count);
}

/*
 * Handle one received log message.
 * Forwards to stdout with MCU container tag for pantavisor log server.
 */
static void handle_log(struct pvcm_session *s, const uint8_t *buf, int len)
{
	(void)s;
	if ((size_t)len < 4)
		return;

	const pvcm_log_t *log = (const pvcm_log_t *)buf;
	uint16_t msg_len = log->msg_len;
	if (msg_len > sizeof(log->msg))
		msg_len = sizeof(log->msg);

	/* format: [level] module: message */
	fprintf(stdout, "[MCU/%s] %.*s: %.*s\n",
		log_level_str(log->level),
		(int)sizeof(log->module), log->module,
		msg_len, log->msg);
}

/*
 * Try to receive and dispatch one PVCM frame (non-blocking).
 * Returns: >0 frame dispatched, 0 no frame available, <0 error.
 */
int pvcm_dispatch_one(struct pvcm_session *s)
{
	uint8_t buf[1024];

	int len = s->transport->try_recv_frame(s->transport, buf, sizeof(buf));
	if (len <= 0)
		return len;

	uint8_t op = buf[0];

	switch (op) {
	case PVCM_OP_HELLO_RESP:
		/* late hello resp — update session */
		if ((size_t)len >= sizeof(pvcm_hello_resp_t) - sizeof(uint32_t)) {
			pvcm_hello_resp_t *resp = (pvcm_hello_resp_t *)buf;
			s->protocol_version = resp->protocol_version;
			s->mcu_fw_version = resp->mcu_fw_version;
			s->connected = true;
		}
		break;

	case PVCM_EVT_HEARTBEAT:
		handle_heartbeat(s, buf, len);
		break;

	case PVCM_OP_LOG:
		handle_log(s, buf, len);
		break;

	case PVCM_OP_ACK:
		/* generic ACK — nothing to do */
		break;

	case PVCM_OP_NACK:
		if (len >= 3)
			fprintf(stderr, "[pvcm-run] NACK: ref_op=0x%02x "
				"error=%d\n", buf[1], buf[2]);
		break;

	case PVCM_OP_REQUEST_ROLLBACK:
		fprintf(stderr, "[pvcm-run] MCU requested rollback!\n");
		break;

	case PVCM_EVT_FW_PROGRESS:
		if ((size_t)len >= sizeof(pvcm_fw_progress_t) - sizeof(uint32_t)) {
			const pvcm_fw_progress_t *p =
				(const pvcm_fw_progress_t *)buf;
			fprintf(stdout, "[pvcm-run] fw progress: %d%% "
				"(%u/%u)\n",
				p->percent, p->bytes_written,
				p->total_bytes);
		}
		break;

	/* HTTP gateway */
	case PVCM_OP_HTTP_REQ: {
		const pvcm_http_req_t *hreq = (const pvcm_http_req_t *)buf;
		if (hreq->direction == PVCM_HTTP_DIR_REQUEST)
			pvcm_bridge_on_http_req(s->transport, buf, len);
		else if (hreq->direction == PVCM_HTTP_DIR_REPLY)
			pvcm_bridge_on_reply_req(s->transport, buf, len);
		break;
	}
	case PVCM_OP_HTTP_DATA:
		pvcm_bridge_on_http_data(s->transport, buf, len);
		pvcm_bridge_on_reply_data(s->transport, buf, len);
		break;
	case PVCM_OP_HTTP_END:
		pvcm_bridge_on_http_end(s->transport, buf, len);
		pvcm_bridge_on_reply_end(s->transport, buf, len);
		break;

	/* D-Bus gateway */
	case PVCM_OP_DBUS_CALL:
		pvcm_dbus_bridge_on_call(s->transport, buf, len);
		break;
	case PVCM_OP_DBUS_SUBSCRIBE:
		pvcm_dbus_bridge_on_subscribe(s->transport, buf, len);
		break;
	case PVCM_OP_DBUS_UNSUBSCRIBE:
		pvcm_dbus_bridge_on_unsubscribe(s->transport, buf, len);
		break;

	/* Transport ping test — proxy responds with requested total size,
	 * split across multiple ECHO_RESP frames if needed (like HTTP).
	 * ECHO.data_len = total response size requested (can be > frame). */
	case PVCM_OP_ECHO: {
		if ((size_t)len < 4)
			break;
		const pvcm_echo_t *echo = (const pvcm_echo_t *)buf;
		uint16_t total = echo->data_len; /* total bytes to send back */

		fprintf(stdout, "[pvcm-run] PING: seq=%d total=%d\n",
			echo->seq, total);

		/* send response in chunks of up to 400 bytes per frame */
		uint32_t sent = 0;
		uint8_t frag = 0;
		while (sent < total) {
			uint32_t chunk = total - sent;
			if (chunk > 400)
				chunk = 400;

			pvcm_echo_t resp = {
				.op = PVCM_OP_ECHO_RESP,
				.seq = echo->seq,
				.data_len = chunk,
			};
			for (uint32_t i = 0; i < chunk; i++)
				resp.data[i] = (uint8_t)((frag << 4) | (i & 0xF));

			s->transport->send_frame(s->transport, &resp,
						 8 + chunk);
			sent += chunk;
			frag++;
		}

		fprintf(stdout, "[pvcm-run] PING: sent %d bytes in %d frames\n",
			sent, frag);
		break;
	}

	default:
		fprintf(stderr, "[pvcm-run] unhandled opcode 0x%02x "
			"(len=%d)\n", op, len);
		break;
	}

	return 1; /* frame dispatched */
}
