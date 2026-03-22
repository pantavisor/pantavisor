/*
 * pvcm-proxy protocol handler
 *
 * Implements the Linux side of the PVCM protocol:
 *  - HELLO/HELLO_RESP handshake
 *  - Heartbeat reception and health tracking
 *  - Log forwarding to stdout (pantavisor log server)
 *  - ACK/NACK handling
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_protocol.h"
#include "pvcm_bridge.h"

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
 * Returns 0 on success, -1 on error, -2 on timeout.
 */
int pvcm_handshake(struct pvcm_session *s)
{
	pvcm_hello_t hello = {
		.op = PVCM_OP_HELLO,
	};

	fprintf(stdout, "[pvcm-proxy] sending HELLO\n");

	if (s->transport->send_frame(s->transport, &hello,
				     sizeof(hello) - sizeof(uint32_t)) < 0) {
		fprintf(stderr, "[pvcm-proxy] failed to send HELLO\n");
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
			fprintf(stderr, "[pvcm-proxy] no HELLO_RESP "
				"(len=%d)\n", len);
			return len;
		}

		if (len >= 1 && buf[0] == PVCM_OP_HELLO_RESP) {
			pvcm_hello_resp_t *resp = (pvcm_hello_resp_t *)buf;
			s->protocol_version = resp->protocol_version;
			s->mcu_fw_version = resp->mcu_fw_version;
			s->connected = true;

			fprintf(stdout, "[pvcm-proxy] MCU connected: "
				"protocol=v%d fw=v%d baudrate=%u\n",
				resp->protocol_version,
				resp->mcu_fw_version,
				resp->baudrate);
			return 0;
		}

		/* not HELLO_RESP — log and keep waiting */
		fprintf(stdout, "[pvcm-proxy] skipping frame op=0x%02x "
			"during handshake\n", buf[0]);
	}

	fprintf(stderr, "[pvcm-proxy] HELLO_RESP not received after "
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

	fprintf(stdout, "[pvcm-proxy] heartbeat: status=%s uptime=%us "
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
 * Handle MCU requesting rollback.
 */
static void handle_request_rollback(struct pvcm_session *s)
{
	fprintf(stderr, "[pvcm-proxy] MCU requested rollback!\n");
	/* TODO: signal pantavisor to trigger rollback */
}

/*
 * Receive and dispatch one PVCM frame.
 * Returns 0 on success, -1 on error, -2 on timeout.
 */
int pvcm_dispatch_one(struct pvcm_session *s, int timeout_ms)
{
	uint8_t buf[1024];

	int len = s->transport->recv_frame(s->transport, buf, sizeof(buf),
					   timeout_ms);
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
			fprintf(stderr, "[pvcm-proxy] NACK: ref_op=0x%02x "
				"error=%d\n", buf[1], buf[2]);
		break;

	case PVCM_OP_REQUEST_ROLLBACK:
		handle_request_rollback(s);
		break;

	case PVCM_EVT_FW_PROGRESS:
		if ((size_t)len >= sizeof(pvcm_fw_progress_t) - sizeof(uint32_t)) {
			const pvcm_fw_progress_t *p =
				(const pvcm_fw_progress_t *)buf;
			fprintf(stdout, "[pvcm-proxy] fw progress: %d%% "
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

	default:
		fprintf(stderr, "[pvcm-proxy] unhandled opcode 0x%02x "
			"(len=%d)\n", op, len);
		break;
	}

	return 0;
}

/*
 * Main protocol loop. Runs until *running becomes false (SIGTERM).
 * Monitors heartbeat interval — if no heartbeat for 15s, reports
 * degraded status.
 */
int pvcm_run(struct pvcm_session *s, volatile bool *running)
{
	time_t last_heartbeat = time(NULL);
	const int heartbeat_timeout_s = 15;

	fprintf(stdout, "[pvcm-proxy] entering main loop\n");

	while (*running) {
		int ret = pvcm_dispatch_one(s, 1000);

		if (ret == 0) {
			/* got a frame — check if it was a heartbeat */
			if (s->last_heartbeat_uptime > 0)
				last_heartbeat = time(NULL);
		}

		/* check heartbeat timeout */
		time_t now = time(NULL);
		if (now - last_heartbeat > heartbeat_timeout_s) {
			fprintf(stderr, "[pvcm-proxy] heartbeat timeout "
				"(%lds)\n", now - last_heartbeat);
			/* TODO: report to pantavisor as health degraded */
		}
	}

	return 0;
}
