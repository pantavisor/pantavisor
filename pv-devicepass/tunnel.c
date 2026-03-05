/*
 * Copyright (c) 2026 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * WebSocket tunnel client over Unix socket or TCP.
 *
 * Implements minimal WebSocket framing (RFC 6455) for text frames only.
 * No external WebSocket library dependency — just enough for JSON
 * command/response exchange with a tunnel server.
 *
 * Supports two connection modes:
 *   Unix socket: target starts with "/" (e.g. "/run/tunnel.sock")
 *   TCP:         target is "host:port" (e.g. "10.0.3.10:8080")
 *
 * After WebSocket upgrade, performs challenge-response authentication:
 *   Hub -> Client: {"type":"auth_challenge","challenge":"<hex>"}
 *   Client -> Hub: {"type":"auth_response","address":"0x...","signature":"0x<rsv>"}
 *   Hub -> Client: {"type":"auth_result","status":"ok","guardian":"0x..."}
 *
 * Protocol (after auth):
 *   Server -> Client: {"id":"req-1","method":"GET","path":"/containers","body":null}
 *   Client -> Server: {"id":"req-1","status":200,"body":[...]}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <jsmn/jsmnutil.h>

#include "tunnel.h"
#include "agent-ops.h"
#include "../utils/json.h"

#define TUNNEL_RECONNECT_SEC 5
#define TUNNEL_WS_KEY "dGhlIHNhbXBsZSBub25jZQ=="

/* Auth states */
#define AUTH_STATE_WAIT_CHALLENGE 0
#define AUTH_STATE_WAIT_RESULT 1
#define AUTH_STATE_AUTHENTICATED 2

/* Tunnel client state */
struct tunnel_state {
	struct event_base *base;
	char *target;     /* Unix socket path or "host:port" */
	int is_tcp;       /* 0=Unix socket, 1=TCP */
	char *tcp_host;   /* parsed host (TCP only) */
	int tcp_port;     /* parsed port (TCP only) */
	struct bufferevent *bev;
	struct event *reconnect_timer;
	int ws_connected; /* 0=HTTP upgrade pending, 1=WebSocket ready */
	struct evbuffer *frame_buf; /* accumulates partial WebSocket frames */
	/* Identity */
	char *device_key_path;
	char *device_address;
	/* Auth */
	int auth_state;
	char *guardian_address;
};

static struct tunnel_state *g_tunnel;

/* --- Minimal WebSocket framing --- */

/*
 * Encode a WebSocket text frame with client masking (RFC 6455 Section 5.3).
 * Returns malloc'd buffer with frame, sets *out_len.
 */
static unsigned char *ws_encode_frame(const char *payload, size_t payload_len,
				      size_t *out_len)
{
	/* Calculate frame size: 1 (fin+opcode) + 1 (mask+len) + ext_len + 4 (mask) + payload */
	size_t header_len = 2 + 4; /* base header + mask key */
	if (payload_len >= 126 && payload_len <= 0xFFFF)
		header_len += 2;
	else if (payload_len > 0xFFFF)
		header_len += 8;

	unsigned char *frame = malloc(header_len + payload_len);
	if (!frame)
		return NULL;

	size_t pos = 0;

	/* FIN + text opcode (0x81) */
	frame[pos++] = 0x81;

	/* Mask bit set (0x80) + payload length */
	if (payload_len < 126) {
		frame[pos++] = 0x80 | (unsigned char)payload_len;
	} else if (payload_len <= 0xFFFF) {
		frame[pos++] = 0x80 | 126;
		frame[pos++] = (payload_len >> 8) & 0xFF;
		frame[pos++] = payload_len & 0xFF;
	} else {
		frame[pos++] = 0x80 | 127;
		for (int i = 7; i >= 0; i--)
			frame[pos++] = (payload_len >> (8 * i)) & 0xFF;
	}

	/* Generate mask key */
	unsigned char mask[4];
	unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(size_t)frame;
	mask[0] = seed & 0xFF;
	mask[1] = (seed >> 8) & 0xFF;
	mask[2] = (seed >> 16) & 0xFF;
	mask[3] = (seed >> 24) & 0xFF;
	memcpy(frame + pos, mask, 4);
	pos += 4;

	/* Masked payload */
	for (size_t i = 0; i < payload_len; i++)
		frame[pos + i] = (unsigned char)payload[i] ^ mask[i % 4];

	*out_len = pos + payload_len;
	return frame;
}

/*
 * Try to decode a WebSocket frame from the buffer.
 * Returns payload length on success (payload points into buf),
 * 0 if more data needed, -1 on error.
 * Sets *payload and *payload_len, *frame_len to total consumed bytes.
 */
static int ws_decode_frame(const unsigned char *buf, size_t buf_len,
			   char **payload, size_t *payload_len,
			   size_t *frame_len)
{
	if (buf_len < 2)
		return 0;

	/* unsigned char fin = (buf[0] >> 7) & 1; */
	unsigned char opcode = buf[0] & 0x0F;
	unsigned char masked = (buf[1] >> 7) & 1;
	size_t len = buf[1] & 0x7F;
	size_t pos = 2;

	if (len == 126) {
		if (buf_len < 4)
			return 0;
		len = ((size_t)buf[2] << 8) | buf[3];
		pos = 4;
	} else if (len == 127) {
		if (buf_len < 10)
			return 0;
		len = 0;
		for (int i = 0; i < 8; i++)
			len = (len << 8) | buf[2 + i];
		pos = 10;
	}

	unsigned char mask[4] = { 0 };
	if (masked) {
		if (buf_len < pos + 4)
			return 0;
		memcpy(mask, buf + pos, 4);
		pos += 4;
	}

	if (buf_len < pos + len)
		return 0;

	/* Connection close frame */
	if (opcode == 0x08) {
		*frame_len = pos + len;
		return -1;
	}

	/* Ping — respond with pong */
	if (opcode == 0x09) {
		*frame_len = pos + len;
		*payload = NULL;
		*payload_len = 0;
		return 2; /* signal: ping */
	}

	/* Pong — ignore */
	if (opcode == 0x0A) {
		*frame_len = pos + len;
		*payload = NULL;
		*payload_len = 0;
		return 3; /* signal: pong, ignore */
	}

	/* Text frame (opcode 1) or continuation (0) */
	char *data = malloc(len + 1);
	if (!data)
		return -1;

	for (size_t i = 0; i < len; i++) {
		if (masked)
			data[i] = (char)(buf[pos + i] ^ mask[i % 4]);
		else
			data[i] = (char)buf[pos + i];
	}
	data[len] = '\0';

	*payload = data;
	*payload_len = len;
	*frame_len = pos + len;
	return 1;
}

/* --- Auth: sign challenge using ethsign + keccak256sum --- */

/*
 * Sign an auth challenge using external tools.
 * challenge_hex: hex string of the 32-byte challenge
 * Returns malloc'd JSON string for auth_response, or NULL on error.
 */
static char *auth_sign_challenge(struct tunnel_state *ts,
				 const char *challenge_hex)
{
	char cmd[1024];
	char hash_hex[65];
	char sig_hex[131];
	FILE *fp;

	/* Step 1: hash the challenge bytes: keccak256sum --hex */
	snprintf(cmd, sizeof(cmd), "echo -n '%s' | keccak256sum --hex",
		 challenge_hex);
	fp = popen(cmd, "r");
	if (!fp) {
		fprintf(stderr, "tunnel: popen(keccak256sum) failed\n");
		return NULL;
	}
	if (!fgets(hash_hex, sizeof(hash_hex), fp)) {
		fprintf(stderr, "tunnel: keccak256sum produced no output\n");
		pclose(fp);
		return NULL;
	}
	pclose(fp);

	/* Trim trailing whitespace */
	size_t hlen = strlen(hash_hex);
	while (hlen > 0 &&
	       (hash_hex[hlen - 1] == '\n' || hash_hex[hlen - 1] == ' '))
		hash_hex[--hlen] = '\0';

	/* Step 2: sign the hash: ethsign sign --key <path> <hash> */
	snprintf(cmd, sizeof(cmd), "ethsign sign --key %s %s",
		 ts->device_key_path, hash_hex);
	fp = popen(cmd, "r");
	if (!fp) {
		fprintf(stderr, "tunnel: popen(ethsign) failed\n");
		return NULL;
	}
	if (!fgets(sig_hex, sizeof(sig_hex), fp)) {
		fprintf(stderr, "tunnel: ethsign produced no output\n");
		pclose(fp);
		return NULL;
	}
	pclose(fp);

	/* Trim trailing whitespace */
	size_t slen = strlen(sig_hex);
	while (slen > 0 &&
	       (sig_hex[slen - 1] == '\n' || sig_hex[slen - 1] == ' '))
		sig_hex[--slen] = '\0';

	/* Build auth_response JSON */
	size_t resp_size = 256 + strlen(ts->device_address) + slen;
	char *resp = malloc(resp_size);
	if (!resp)
		return NULL;

	snprintf(resp, resp_size,
		 "{\"type\":\"auth_response\","
		 "\"address\":\"%s\","
		 "\"signature\":\"%s\"}",
		 ts->device_address, sig_hex);

	return resp;
}

/* --- Tunnel operation result callback --- */

struct tunnel_op_ctx {
	char *request_id;
};

static void tunnel_op_result(int status, const char *body, size_t body_len,
			     void *ctx)
{
	struct tunnel_op_ctx *tctx = ctx;

	if (!g_tunnel || !g_tunnel->bev) {
		free(tctx->request_id);
		free(tctx);
		return;
	}

	/* Build JSON response: {"id":"...","status":NNN,"body":...} */
	size_t resp_size = 64 + strlen(tctx->request_id) + body_len;
	char *resp = malloc(resp_size);
	if (!resp) {
		free(tctx->request_id);
		free(tctx);
		return;
	}

	int resp_len;
	if (body && body_len > 0)
		resp_len = snprintf(resp, resp_size,
				    "{\"id\":\"%s\",\"status\":%d,\"body\":%s}",
				    tctx->request_id, status, body);
	else
		resp_len = snprintf(resp, resp_size,
				    "{\"id\":\"%s\",\"status\":%d,\"body\":null}",
				    tctx->request_id, status);

	/* Encode as WebSocket frame and send */
	size_t frame_len;
	unsigned char *frame = ws_encode_frame(resp, resp_len, &frame_len);
	if (frame) {
		bufferevent_write(g_tunnel->bev, frame, frame_len);
		free(frame);
	}

	free(resp);
	free(tctx->request_id);
	free(tctx);
}

/* --- Tunnel command dispatch --- */

static void tunnel_handle_command(const char *json_str, size_t json_len)
{
	jsmntok_t *tokv;
	int tokc;

	if (jsmnutil_parse_json(json_str, &tokv, &tokc) < 0) {
		fprintf(stderr, "tunnel: failed to parse command JSON\n");
		return;
	}

	char *id = pv_json_get_value(json_str, "id", tokv, tokc);
	char *method = pv_json_get_value(json_str, "method", tokv, tokc);
	char *path = pv_json_get_value(json_str, "path", tokv, tokc);
	char *body = pv_json_get_value(json_str, "body", tokv, tokc);

	if (!id || !method || !path) {
		fprintf(stderr, "tunnel: incomplete command (need id, method, path)\n");
		free(id);
		free(method);
		free(path);
		free(body);
		free(tokv);
		return;
	}

	/* "null" body should be treated as no body */
	size_t body_len = 0;
	if (body && strcmp(body, "null") != 0)
		body_len = strlen(body);
	else {
		free(body);
		body = NULL;
	}

	struct tunnel_op_ctx *tctx = calloc(1, sizeof(*tctx));
	if (!tctx) {
		free(id);
		free(method);
		free(path);
		free(body);
		free(tokv);
		return;
	}
	tctx->request_id = id; /* takes ownership */

	agent_op_dispatch(g_tunnel->base, method, path, body, body_len,
			  tunnel_op_result, tctx);

	free(method);
	free(path);
	free(body);
	free(tokv);
}

/* --- Auth message handling --- */

static void tunnel_handle_auth_message(struct tunnel_state *ts,
				       const char *json_str, size_t json_len)
{
	jsmntok_t *tokv;
	int tokc;

	if (jsmnutil_parse_json(json_str, &tokv, &tokc) < 0) {
		fprintf(stderr, "tunnel: failed to parse auth JSON\n");
		return;
	}

	char *type = pv_json_get_value(json_str, "type", tokv, tokc);
	if (!type) {
		free(tokv);
		return;
	}

	if (ts->auth_state == AUTH_STATE_WAIT_CHALLENGE &&
	    strcmp(type, "auth_challenge") == 0) {
		char *challenge =
			pv_json_get_value(json_str, "challenge", tokv, tokc);
		if (!challenge) {
			fprintf(stderr,
				"tunnel: auth_challenge missing challenge field\n");
			free(type);
			free(tokv);
			return;
		}

		printf("tunnel: received auth challenge, signing...\n");

		char *response = auth_sign_challenge(ts, challenge);
		free(challenge);

		if (!response) {
			fprintf(stderr,
				"tunnel: failed to sign auth challenge\n");
			free(type);
			free(tokv);
			return;
		}

		/* Send auth_response */
		size_t frame_len;
		unsigned char *frame =
			ws_encode_frame(response, strlen(response), &frame_len);
		if (frame) {
			bufferevent_write(ts->bev, frame, frame_len);
			free(frame);
		}
		free(response);

		ts->auth_state = AUTH_STATE_WAIT_RESULT;
		printf("tunnel: sent auth_response for %s\n",
		       ts->device_address);

	} else if (ts->auth_state == AUTH_STATE_WAIT_RESULT &&
		   strcmp(type, "auth_result") == 0) {
		char *status =
			pv_json_get_value(json_str, "status", tokv, tokc);
		if (!status) {
			free(type);
			free(tokv);
			return;
		}

		if (strcmp(status, "ok") == 0) {
			char *guardian = pv_json_get_value(json_str, "guardian",
							  tokv, tokc);
			ts->auth_state = AUTH_STATE_AUTHENTICATED;
			free(ts->guardian_address);
			ts->guardian_address = guardian; /* takes ownership */
			printf("tunnel: authenticated! guardian: %s\n",
			       guardian ? guardian : "unknown");
		} else if (strcmp(status, "not_claimed") == 0) {
			char *msg = pv_json_get_value(json_str, "message",
						      tokv, tokc);
			fprintf(stderr,
				"tunnel: device not claimed on-chain: %s\n",
				msg ? msg : "");
			free(msg);
			/* Will reconnect via event_cb when hub closes */
		} else {
			char *msg = pv_json_get_value(json_str, "message",
						      tokv, tokc);
			fprintf(stderr, "tunnel: auth rejected: %s\n",
				msg ? msg : "");
			free(msg);
		}
		free(status);
	}

	free(type);
	free(tokv);
}

/* --- Bufferevent callbacks --- */

static void tunnel_read_cb(struct bufferevent *bev, void *arg)
{
	struct tunnel_state *ts = arg;
	struct evbuffer *input = bufferevent_get_input(bev);

	if (!ts->ws_connected) {
		/* Waiting for HTTP 101 upgrade response */
		size_t len = evbuffer_get_length(input);
		char *data = malloc(len + 1);
		if (!data)
			return;
		evbuffer_copyout(input, data, len);
		data[len] = '\0';

		/* Look for end of HTTP response headers */
		char *end = strstr(data, "\r\n\r\n");
		if (!end) {
			free(data);
			return; /* need more data */
		}

		/* Check for 101 Switching Protocols */
		if (strstr(data, "101") != NULL) {
			size_t header_len = (end - data) + 4;
			evbuffer_drain(input, header_len);
			ts->ws_connected = 1;
			ts->auth_state = AUTH_STATE_WAIT_CHALLENGE;
			printf("tunnel: WebSocket connected to %s\n",
			       ts->target);
		} else {
			fprintf(stderr,
				"tunnel: upgrade failed, response: %.*s\n",
				(int)(end - data), data);
			free(data);
			bufferevent_free(bev);
			ts->bev = NULL;
			return;
		}
		free(data);
	}

	/* Process WebSocket frames */
	while (ts->ws_connected) {
		size_t avail = evbuffer_get_length(input);
		if (avail == 0)
			break;

		unsigned char *buf = evbuffer_pullup(input, avail);
		if (!buf)
			break;

		char *payload = NULL;
		size_t payload_len = 0;
		size_t frame_len = 0;
		int ret = ws_decode_frame(buf, avail, &payload, &payload_len,
					  &frame_len);

		if (ret == 0)
			break; /* need more data */

		if (ret < 0) {
			/* Close frame or error */
			fprintf(stderr, "tunnel: received close frame\n");
			evbuffer_drain(input, frame_len);
			bufferevent_free(bev);
			ts->bev = NULL;
			ts->ws_connected = 0;
			ts->auth_state = AUTH_STATE_WAIT_CHALLENGE;
			return;
		}

		evbuffer_drain(input, frame_len);

		if (ret == 1 && payload) {
			if (ts->auth_state != AUTH_STATE_AUTHENTICATED) {
				/* Auth phase: handle challenge/result */
				tunnel_handle_auth_message(ts, payload,
							   payload_len);
			} else {
				/* Normal operation: dispatch command */
				tunnel_handle_command(payload, payload_len);
			}
			free(payload);
		} else if (ret == 2) {
			/* Ping — send pong (empty payload) */
			unsigned char pong[2] = { 0x8A, 0x80 };
			unsigned char mask[4] = { 0, 0, 0, 0 };
			unsigned char pong_frame[6];
			memcpy(pong_frame, pong, 2);
			memcpy(pong_frame + 2, mask, 4);
			bufferevent_write(bev, pong_frame, 6);
		}
		/* ret == 3: pong, ignore */
	}
}

static void tunnel_connect(struct tunnel_state *ts);

static void tunnel_reconnect_cb(evutil_socket_t fd, short event, void *arg)
{
	struct tunnel_state *ts = arg;
	tunnel_connect(ts);
}

static void schedule_reconnect(struct tunnel_state *ts)
{
	if (!ts->reconnect_timer) {
		ts->reconnect_timer =
			evtimer_new(ts->base, tunnel_reconnect_cb, ts);
	}
	if (ts->reconnect_timer) {
		struct timeval tv = { TUNNEL_RECONNECT_SEC, 0 };
		evtimer_add(ts->reconnect_timer, &tv);
		printf("tunnel: reconnecting in %d seconds\n",
		       TUNNEL_RECONNECT_SEC);
	}
}

static void tunnel_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct tunnel_state *ts = arg;

	if (events & BEV_EVENT_CONNECTED) {
		/* Send WebSocket upgrade request */
		const char *host = ts->is_tcp ? ts->tcp_host : "localhost";
		struct evbuffer *out = bufferevent_get_output(bev);
		evbuffer_add_printf(
			out,
			"GET /tunnel HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Key: %s\r\n"
			"Sec-WebSocket-Version: 13\r\n"
			"\r\n",
			host, TUNNEL_WS_KEY);
		return;
	}

	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		if (events & BEV_EVENT_ERROR)
			fprintf(stderr, "tunnel: connection error: %s\n",
				strerror(errno));
		else
			fprintf(stderr, "tunnel: connection closed\n");

		bufferevent_free(bev);
		ts->bev = NULL;
		ts->ws_connected = 0;
		ts->auth_state = AUTH_STATE_WAIT_CHALLENGE;
		schedule_reconnect(ts);
	}
}

/* --- Connection --- */

static void tunnel_connect(struct tunnel_state *ts)
{
	ts->bev = bufferevent_socket_new(ts->base, -1,
					 BEV_OPT_CLOSE_ON_FREE);
	if (!ts->bev) {
		fprintf(stderr, "tunnel: bufferevent_socket_new() failed\n");
		schedule_reconnect(ts);
		return;
	}

	bufferevent_setcb(ts->bev, tunnel_read_cb, NULL, tunnel_event_cb, ts);
	bufferevent_enable(ts->bev, EV_READ | EV_WRITE);

	int rc;
	if (ts->is_tcp) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(ts->tcp_port);
		if (inet_pton(AF_INET, ts->tcp_host, &sin.sin_addr) != 1) {
			fprintf(stderr, "tunnel: invalid address: %s\n",
				ts->tcp_host);
			bufferevent_free(ts->bev);
			ts->bev = NULL;
			schedule_reconnect(ts);
			return;
		}
		rc = bufferevent_socket_connect(ts->bev,
						(struct sockaddr *)&sin,
						sizeof(sin));
	} else {
		struct sockaddr_un sun;
		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		strncpy(sun.sun_path, ts->target,
			sizeof(sun.sun_path) - 1);
		rc = bufferevent_socket_connect(ts->bev,
						(struct sockaddr *)&sun,
						sizeof(sun));
	}

	if (rc < 0) {
		fprintf(stderr, "tunnel: connect to %s failed: %s\n",
			ts->target, strerror(errno));
		bufferevent_free(ts->bev);
		ts->bev = NULL;
		schedule_reconnect(ts);
	}
}

/* --- Public API --- */

int tunnel_init(struct event_base *base, const char *target,
		const char *key_path, const char *address)
{
	if (g_tunnel) {
		fprintf(stderr, "tunnel: already initialized\n");
		return -1;
	}

	g_tunnel = calloc(1, sizeof(*g_tunnel));
	if (!g_tunnel)
		return -1;

	g_tunnel->base = base;
	g_tunnel->target = strdup(target);
	g_tunnel->device_key_path = key_path ? strdup(key_path) : NULL;
	g_tunnel->device_address = address ? strdup(address) : NULL;
	g_tunnel->auth_state = AUTH_STATE_WAIT_CHALLENGE;

	if (!g_tunnel->target) {
		free(g_tunnel);
		g_tunnel = NULL;
		return -1;
	}

	/* Detect Unix socket vs TCP: paths start with "/" */
	if (target[0] == '/') {
		g_tunnel->is_tcp = 0;
		printf("tunnel: connecting to unix:%s\n", target);
	} else {
		/* Parse "host:port" */
		const char *colon = strrchr(target, ':');
		if (!colon || colon == target) {
			fprintf(stderr,
				"tunnel: invalid target '%s' "
				"(expected /path or host:port)\n",
				target);
			free(g_tunnel->target);
			free(g_tunnel->device_key_path);
			free(g_tunnel->device_address);
			free(g_tunnel);
			g_tunnel = NULL;
			return -1;
		}
		g_tunnel->is_tcp = 1;
		g_tunnel->tcp_host = strndup(target, colon - target);
		g_tunnel->tcp_port = atoi(colon + 1);
		if (g_tunnel->tcp_port <= 0 || g_tunnel->tcp_port > 65535) {
			fprintf(stderr, "tunnel: invalid port in '%s'\n",
				target);
			free(g_tunnel->tcp_host);
			free(g_tunnel->target);
			free(g_tunnel->device_key_path);
			free(g_tunnel->device_address);
			free(g_tunnel);
			g_tunnel = NULL;
			return -1;
		}
		printf("tunnel: connecting to tcp:%s:%d\n",
		       g_tunnel->tcp_host, g_tunnel->tcp_port);
	}

	if (g_tunnel->device_address)
		printf("tunnel: device identity: %s\n", g_tunnel->device_address);

	tunnel_connect(g_tunnel);
	return 0;
}

void tunnel_shutdown(void)
{
	if (!g_tunnel)
		return;

	if (g_tunnel->bev)
		bufferevent_free(g_tunnel->bev);
	if (g_tunnel->reconnect_timer)
		event_free(g_tunnel->reconnect_timer);
	if (g_tunnel->frame_buf)
		evbuffer_free(g_tunnel->frame_buf);
	free(g_tunnel->tcp_host);
	free(g_tunnel->target);
	free(g_tunnel->device_key_path);
	free(g_tunnel->device_address);
	free(g_tunnel->guardian_address);
	free(g_tunnel);
	g_tunnel = NULL;
}

const char *tunnel_get_guardian(void)
{
	if (!g_tunnel)
		return NULL;
	if (g_tunnel->auth_state != AUTH_STATE_AUTHENTICATED)
		return NULL;
	return g_tunnel->guardian_address;
}
