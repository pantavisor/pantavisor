/*
 * pvcm-proxy D-Bus bridge
 *
 * Forwards PVCM DBUS_CALL frames to the Linux system D-Bus via
 * libdbus-1.  Signal subscriptions are managed via D-Bus match
 * rules; matching signals are forwarded to the MCU as DBUS_SIGNAL
 * frames.
 *
 * Threading:
 *   - D-Bus dispatch runs in a dedicated thread (signals, async)
 *   - DBUS_CALL handling is synchronous (send_with_reply_and_block)
 *     from the PVCM dispatch context — safe because pvcm_dispatch_one
 *     runs single-threaded
 *   - Signal delivery calls send_frame from the D-Bus thread; the
 *     transport write() is atomic for small frames
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_dbus_bridge.h"

#include <dbus/dbus.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static DBusConnection *dbus_conn;
static struct pvcm_transport *bridge_transport;

/* ---- signal subscriptions ---- */

#define MAX_SUBS 16

struct dbus_sub {
	uint8_t sub_id;
	bool active;
	char sender[64];
	char path[128];
	char interface[128];
	char member[64];
	char match_rule[512];
};

static struct dbus_sub subs[MAX_SUBS];

/* ---- null-separated field packing/unpacking ---- */

/*
 * Unpack null-separated fields from buf.
 * Returns number of fields found.
 */
static int unpack_fields(const char *buf, size_t buf_len,
			 const char **ptrs, int max_fields)
{
	int count = 0;
	size_t off = 0;

	while (off < buf_len && count < max_fields) {
		ptrs[count++] = buf + off;
		while (off < buf_len && buf[off] != '\0')
			off++;
		off++;
	}

	return count;
}

/*
 * Pack null-separated fields into buf.
 * Returns total bytes, or -1 on overflow.
 */
static int pack_fields(char *buf, size_t buf_size, ...)
{
	va_list ap;
	va_start(ap, buf_size);
	size_t off = 0;

	const char *field;
	while ((field = va_arg(ap, const char *)) != NULL) {
		size_t len = strlen(field);
		if (off + len + 1 > buf_size) {
			va_end(ap);
			return -1;
		}
		memcpy(buf + off, field, len);
		off += len;
		buf[off++] = '\0';
	}

	va_end(ap);
	return (int)off;
}

/* ---- D-Bus → JSON serialization ---- */

/*
 * Serialize a single D-Bus argument to JSON, appending to buf.
 * Returns bytes written, or -1 on overflow.
 */
static int dbus_arg_to_json(DBusMessageIter *iter, char *buf, size_t buf_size)
{
	int type = dbus_message_iter_get_arg_type(iter);
	int n = 0;

	switch (type) {
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
	case DBUS_TYPE_SIGNATURE: {
		const char *val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "\"%s\"", val);
		break;
	}
	case DBUS_TYPE_INT32: {
		dbus_int32_t val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%d", val);
		break;
	}
	case DBUS_TYPE_UINT32: {
		dbus_uint32_t val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%u", val);
		break;
	}
	case DBUS_TYPE_INT64: {
		dbus_int64_t val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%lld", (long long)val);
		break;
	}
	case DBUS_TYPE_UINT64: {
		dbus_uint64_t val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%llu", (unsigned long long)val);
		break;
	}
	case DBUS_TYPE_BOOLEAN: {
		dbus_bool_t val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%s", val ? "true" : "false");
		break;
	}
	case DBUS_TYPE_DOUBLE: {
		double val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%g", val);
		break;
	}
	case DBUS_TYPE_BYTE: {
		unsigned char val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%u", val);
		break;
	}
	case DBUS_TYPE_INT16: {
		dbus_int16_t val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%d", val);
		break;
	}
	case DBUS_TYPE_UINT16: {
		dbus_uint16_t val;
		dbus_message_iter_get_basic(iter, &val);
		n = snprintf(buf, buf_size, "%u", val);
		break;
	}
	case DBUS_TYPE_ARRAY: {
		DBusMessageIter sub;
		dbus_message_iter_recurse(iter, &sub);

		/* check if dict entries (a{...}) */
		if (dbus_message_iter_get_arg_type(&sub) == DBUS_TYPE_DICT_ENTRY) {
			n = snprintf(buf, buf_size, "{");
			bool first = true;
			while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
				DBusMessageIter entry;
				dbus_message_iter_recurse(&sub, &entry);

				if (!first && n < (int)buf_size)
					buf[n++] = ',';
				first = false;

				int r = dbus_arg_to_json(&entry, buf + n, buf_size - n);
				if (r < 0) return -1;
				n += r;

				if (n < (int)buf_size)
					buf[n++] = ':';

				dbus_message_iter_next(&entry);
				r = dbus_arg_to_json(&entry, buf + n, buf_size - n);
				if (r < 0) return -1;
				n += r;

				dbus_message_iter_next(&sub);
			}
			if (n < (int)buf_size)
				buf[n++] = '}';
		} else {
			n = snprintf(buf, buf_size, "[");
			bool first = true;
			while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
				if (!first && n < (int)buf_size)
					buf[n++] = ',';
				first = false;

				int r = dbus_arg_to_json(&sub, buf + n, buf_size - n);
				if (r < 0) return -1;
				n += r;

				dbus_message_iter_next(&sub);
			}
			if (n < (int)buf_size)
				buf[n++] = ']';
		}
		break;
	}
	case DBUS_TYPE_VARIANT: {
		DBusMessageIter sub;
		dbus_message_iter_recurse(iter, &sub);
		n = dbus_arg_to_json(&sub, buf, buf_size);
		break;
	}
	case DBUS_TYPE_STRUCT: {
		DBusMessageIter sub;
		dbus_message_iter_recurse(iter, &sub);
		n = snprintf(buf, buf_size, "[");
		bool first = true;
		while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {
			if (!first && n < (int)buf_size)
				buf[n++] = ',';
			first = false;
			int r = dbus_arg_to_json(&sub, buf + n, buf_size - n);
			if (r < 0) return -1;
			n += r;
			dbus_message_iter_next(&sub);
		}
		if (n < (int)buf_size)
			buf[n++] = ']';
		break;
	}
	default:
		n = snprintf(buf, buf_size, "null");
		break;
	}

	if (n < 0 || n >= (int)buf_size)
		return -1;
	return n;
}

/*
 * Serialize all D-Bus reply args to a JSON value.
 * Single arg: just the value. Multiple args: JSON array.
 */
static int dbus_reply_to_json(DBusMessage *reply, char *buf, size_t buf_size)
{
	DBusMessageIter iter;
	if (!dbus_message_iter_init(reply, &iter)) {
		/* no arguments */
		buf[0] = '\0';
		return 0;
	}

	/* count args */
	DBusMessageIter count_iter;
	dbus_message_iter_init(reply, &count_iter);
	int nargs = 0;
	while (dbus_message_iter_get_arg_type(&count_iter) != DBUS_TYPE_INVALID) {
		nargs++;
		dbus_message_iter_next(&count_iter);
	}

	if (nargs == 1) {
		return dbus_arg_to_json(&iter, buf, buf_size);
	}

	/* multiple args — wrap in array */
	int n = 0;
	if (buf_size < 2) return -1;
	buf[n++] = '[';

	bool first = true;
	while (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INVALID) {
		if (!first && n < (int)buf_size)
			buf[n++] = ',';
		first = false;

		int r = dbus_arg_to_json(&iter, buf + n, buf_size - n);
		if (r < 0) return -1;
		n += r;

		dbus_message_iter_next(&iter);
	}

	if (n < (int)buf_size)
		buf[n++] = ']';
	if (n < (int)buf_size)
		buf[n] = '\0';

	return n;
}

/* ---- JSON → D-Bus argument marshalling ---- */

/*
 * Simple JSON arg parser: append args from JSON array to D-Bus message.
 * Supports: strings, integers, booleans, doubles.
 * Input must be a JSON array: '["hello", 42, true]'
 */
static int json_args_to_dbus(DBusMessage *msg, const char *json)
{
	if (!json || json[0] == '\0')
		return 0;

	/* skip leading whitespace and '[' */
	const char *p = json;
	while (*p == ' ' || *p == '\t') p++;
	if (*p != '[')
		return -1;
	p++;

	while (*p) {
		while (*p == ' ' || *p == ',' || *p == '\t') p++;
		if (*p == ']' || *p == '\0')
			break;

		if (*p == '"') {
			/* string */
			p++;
			const char *start = p;
			while (*p && *p != '"') p++;
			size_t len = p - start;
			char val[256];
			if (len >= sizeof(val)) len = sizeof(val) - 1;
			memcpy(val, start, len);
			val[len] = '\0';
			if (*p == '"') p++;
			dbus_message_append_args(msg,
				DBUS_TYPE_STRING, &(const char *){val},
				DBUS_TYPE_INVALID);
		} else if (*p == 't' && strncmp(p, "true", 4) == 0) {
			dbus_bool_t v = TRUE;
			dbus_message_append_args(msg,
				DBUS_TYPE_BOOLEAN, &v,
				DBUS_TYPE_INVALID);
			p += 4;
		} else if (*p == 'f' && strncmp(p, "false", 5) == 0) {
			dbus_bool_t v = FALSE;
			dbus_message_append_args(msg,
				DBUS_TYPE_BOOLEAN, &v,
				DBUS_TYPE_INVALID);
			p += 5;
		} else if (*p == '-' || (*p >= '0' && *p <= '9')) {
			/* number — check for decimal point */
			const char *start = p;
			bool is_float = false;
			if (*p == '-') p++;
			while (*p >= '0' && *p <= '9') p++;
			if (*p == '.') { is_float = true; p++; while (*p >= '0' && *p <= '9') p++; }

			if (is_float) {
				double v = strtod(start, NULL);
				dbus_message_append_args(msg,
					DBUS_TYPE_DOUBLE, &v,
					DBUS_TYPE_INVALID);
			} else {
				dbus_int32_t v = (dbus_int32_t)strtol(start, NULL, 10);
				dbus_message_append_args(msg,
					DBUS_TYPE_INT32, &v,
					DBUS_TYPE_INVALID);
			}
		} else {
			/* skip unknown */
			p++;
		}
	}

	return 0;
}

/* ---- signal filter ---- */

static DBusHandlerResult signal_filter(DBusConnection *conn,
				       DBusMessage *msg, void *data)
{
	(void)conn;
	(void)data;

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	const char *sender = dbus_message_get_sender(msg);
	const char *path = dbus_message_get_path(msg);
	const char *iface = dbus_message_get_interface(msg);
	const char *member = dbus_message_get_member(msg);

	if (!sender) sender = "";
	if (!path) path = "";
	if (!iface) iface = "";
	if (!member) member = "";

	/* check against subscriptions */
	for (int i = 0; i < MAX_SUBS; i++) {
		if (!subs[i].active)
			continue;

		/* match fields — empty means match all */
		if (subs[i].sender[0] && strcmp(subs[i].sender, sender) != 0)
			continue;
		if (subs[i].path[0] && strcmp(subs[i].path, path) != 0)
			continue;
		if (subs[i].interface[0] && strcmp(subs[i].interface, iface) != 0)
			continue;
		if (subs[i].member[0] && strcmp(subs[i].member, member) != 0)
			continue;

		/* match — serialize and send */
		char args_json[200] = "";
		dbus_reply_to_json(msg, args_json, sizeof(args_json));

		pvcm_dbus_signal_t sig = {
			.op = PVCM_OP_DBUS_SIGNAL,
			.sub_id = subs[i].sub_id,
		};

		int dlen = pack_fields(sig.data, sizeof(sig.data),
				       sender, path, iface, member,
				       args_json, NULL);
		if (dlen < 0) {
			fprintf(stderr, "[dbus-bridge] signal data too long\n");
			continue;
		}
		sig.data_len = (uint16_t)dlen;

		bridge_transport->send_frame(bridge_transport, &sig, 4 + dlen);

		fprintf(stdout, "[dbus-bridge] signal: %s.%s → sub_id=%d\n",
			iface, member, subs[i].sub_id);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* ---- public API ---- */

int pvcm_dbus_bridge_init(struct pvcm_transport *t,
			   const char *socket_path)
{
	if (!socket_path || socket_path[0] == '\0') {
		fprintf(stdout, "[dbus-bridge] no socket path, D-Bus disabled\n");
		return 0;
	}

	bridge_transport = t;
	memset(subs, 0, sizeof(subs));

	/* connect to D-Bus via unix socket */
	char address[512];
	snprintf(address, sizeof(address), "unix:path=%s", socket_path);

	DBusError err;
	dbus_error_init(&err);

	dbus_conn = dbus_connection_open(address, &err);
	if (!dbus_conn) {
		fprintf(stderr, "[dbus-bridge] connect failed: %s: %s\n",
			err.name, err.message);
		dbus_error_free(&err);
		return -1;
	}

	if (!dbus_bus_register(dbus_conn, &err)) {
		fprintf(stderr, "[dbus-bridge] register failed: %s: %s\n",
			err.name, err.message);
		dbus_error_free(&err);
		dbus_connection_unref(dbus_conn);
		dbus_conn = NULL;
		return -1;
	}

	/* install signal filter — signals are delivered when
	 * pvcm_dbus_bridge_poll() is called from the main loop */
	dbus_connection_add_filter(dbus_conn, signal_filter, NULL, NULL);

	fprintf(stdout, "[dbus-bridge] connected to %s\n", socket_path);
	return 0;
}

int pvcm_dbus_bridge_on_call(struct pvcm_transport *t,
			     const uint8_t *buf, int len)
{
	if (!dbus_conn) {
		fprintf(stderr, "[dbus-bridge] CALL but D-Bus not connected\n");
		/* send error response */
		pvcm_dbus_call_resp_t resp = {
			.op = PVCM_OP_DBUS_CALL_RESP,
			.req_id = buf[1],
			.error = PVCM_DBUS_ERR_FAILED,
		};
		const char *msg = "D-Bus not connected";
		resp.data_len = (uint16_t)strlen(msg);
		memcpy(resp.data, msg, resp.data_len);
		t->send_frame(t, &resp, 6 + resp.data_len);
		return -1;
	}

	const pvcm_dbus_call_t *call = (const pvcm_dbus_call_t *)buf;

	/* unpack: dest\0path\0iface\0member[\0args_json] */
	const char *fields[5] = { "", "", "", "", "" };
	int nf = unpack_fields(call->data, call->data_len, fields, 5);

	if (nf < 4) {
		fprintf(stderr, "[dbus-bridge] CALL: need 4 fields, got %d\n", nf);
		pvcm_dbus_call_resp_t resp = {
			.op = PVCM_OP_DBUS_CALL_RESP,
			.req_id = call->req_id,
			.error = PVCM_DBUS_ERR_ARGS,
		};
		const char *msg = "need dest, path, iface, member";
		resp.data_len = (uint16_t)strlen(msg);
		memcpy(resp.data, msg, resp.data_len);
		t->send_frame(t, &resp, 6 + resp.data_len);
		return -1;
	}

	const char *dest = fields[0];
	const char *obj_path = fields[1];
	const char *iface = fields[2];
	const char *member = fields[3];
	const char *args_json = nf > 4 ? fields[4] : NULL;

	fprintf(stdout, "[dbus-bridge] CALL: %s %s %s.%s args=%s\n",
		dest, obj_path, iface, member,
		args_json ? args_json : "(none)");

	/* build D-Bus method call */
	DBusMessage *msg_call = dbus_message_new_method_call(
		dest, obj_path, iface, member);
	if (!msg_call) {
		pvcm_dbus_call_resp_t resp = {
			.op = PVCM_OP_DBUS_CALL_RESP,
			.req_id = call->req_id,
			.error = PVCM_DBUS_ERR_FAILED,
		};
		const char *emsg = "failed to create message";
		resp.data_len = (uint16_t)strlen(emsg);
		memcpy(resp.data, emsg, resp.data_len);
		t->send_frame(t, &resp, 6 + resp.data_len);
		return -1;
	}

	/* append args if any */
	if (args_json && args_json[0]) {
		if (json_args_to_dbus(msg_call, args_json) < 0) {
			dbus_message_unref(msg_call);
			pvcm_dbus_call_resp_t resp = {
				.op = PVCM_OP_DBUS_CALL_RESP,
				.req_id = call->req_id,
				.error = PVCM_DBUS_ERR_ARGS,
			};
			const char *emsg = "failed to parse args JSON";
			resp.data_len = (uint16_t)strlen(emsg);
			memcpy(resp.data, emsg, resp.data_len);
			t->send_frame(t, &resp, 6 + resp.data_len);
			return -1;
		}
	}

	/* send and wait for reply (10s timeout) */
	DBusError err;
	dbus_error_init(&err);

	DBusMessage *reply = dbus_connection_send_with_reply_and_block(
		dbus_conn, msg_call, 10000, &err);
	dbus_message_unref(msg_call);

	pvcm_dbus_call_resp_t resp = {
		.op = PVCM_OP_DBUS_CALL_RESP,
		.req_id = call->req_id,
	};

	if (!reply) {
		fprintf(stderr, "[dbus-bridge] CALL failed: %s: %s\n",
			err.name, err.message);

		resp.error = PVCM_DBUS_ERR_FAILED;
		if (strstr(err.name, "ServiceUnknown"))
			resp.error = PVCM_DBUS_ERR_NO_SERVICE;
		else if (strstr(err.name, "UnknownMethod"))
			resp.error = PVCM_DBUS_ERR_NO_METHOD;
		else if (strstr(err.name, "Timeout") || strstr(err.name, "NoReply"))
			resp.error = PVCM_DBUS_ERR_TIMEOUT;

		int elen = snprintf(resp.data, sizeof(resp.data),
				    "%s: %s", err.name, err.message);
		if (elen < 0) elen = 0;
		if (elen > (int)sizeof(resp.data) - 1)
			elen = sizeof(resp.data) - 1;
		resp.data_len = (uint16_t)elen;

		dbus_error_free(&err);
		t->send_frame(t, &resp, 6 + resp.data_len);
		return -1;
	}

	/* serialize reply to JSON */
	resp.error = PVCM_DBUS_OK;
	int json_len = dbus_reply_to_json(reply, resp.data, sizeof(resp.data) - 1);
	if (json_len < 0) json_len = 0;
	resp.data[json_len] = '\0';
	resp.data_len = (uint16_t)json_len;

	dbus_message_unref(reply);

	fprintf(stdout, "[dbus-bridge] CALL result: %.*s\n",
		(int)resp.data_len, resp.data);

	t->send_frame(t, &resp, 6 + resp.data_len);
	return 0;
}

int pvcm_dbus_bridge_on_subscribe(struct pvcm_transport *t,
				  const uint8_t *buf, int len)
{
	if (!dbus_conn) {
		fprintf(stderr, "[dbus-bridge] SUBSCRIBE but D-Bus not connected\n");
		return -1;
	}

	const pvcm_dbus_sub_t *sub = (const pvcm_dbus_sub_t *)buf;

	/* find free slot */
	int slot = -1;
	for (int i = 0; i < MAX_SUBS; i++) {
		if (!subs[i].active) {
			slot = i;
			break;
		}
	}
	if (slot < 0) {
		fprintf(stderr, "[dbus-bridge] no free subscription slot\n");
		return -1;
	}

	/* unpack: sender\0path\0iface\0signal */
	const char *fields[4] = { "", "", "", "" };
	unpack_fields(sub->data, sub->data_len, fields, 4);

	struct dbus_sub *s = &subs[slot];
	s->sub_id = sub->sub_id;
	snprintf(s->sender, sizeof(s->sender), "%s", fields[0]);
	snprintf(s->path, sizeof(s->path), "%s", fields[1]);
	snprintf(s->interface, sizeof(s->interface), "%s", fields[2]);
	snprintf(s->member, sizeof(s->member), "%s", fields[3]);

	/* build match rule */
	int off = snprintf(s->match_rule, sizeof(s->match_rule), "type='signal'");
	if (s->sender[0])
		off += snprintf(s->match_rule + off, sizeof(s->match_rule) - off,
				",sender='%s'", s->sender);
	if (s->path[0])
		off += snprintf(s->match_rule + off, sizeof(s->match_rule) - off,
				",path='%s'", s->path);
	if (s->interface[0])
		off += snprintf(s->match_rule + off, sizeof(s->match_rule) - off,
				",interface='%s'", s->interface);
	if (s->member[0])
		off += snprintf(s->match_rule + off, sizeof(s->match_rule) - off,
				",member='%s'", s->member);

	DBusError err;
	dbus_error_init(&err);
	dbus_bus_add_match(dbus_conn, s->match_rule, &err);
	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "[dbus-bridge] add_match failed: %s\n", err.message);
		dbus_error_free(&err);
		return -1;
	}

	s->active = true;

	fprintf(stdout, "[dbus-bridge] subscribed: sub_id=%d rule=%s\n",
		s->sub_id, s->match_rule);
	return 0;
}

int pvcm_dbus_bridge_on_unsubscribe(struct pvcm_transport *t,
				    const uint8_t *buf, int len)
{
	if (!dbus_conn)
		return -1;

	uint8_t sub_id = buf[1];

	for (int i = 0; i < MAX_SUBS; i++) {
		if (subs[i].active && subs[i].sub_id == sub_id) {
			DBusError err;
			dbus_error_init(&err);
			dbus_bus_remove_match(dbus_conn, subs[i].match_rule, &err);
			dbus_error_free(&err);

			subs[i].active = false;
			fprintf(stdout, "[dbus-bridge] unsubscribed: sub_id=%d\n",
				sub_id);
			return 0;
		}
	}

	fprintf(stderr, "[dbus-bridge] unsubscribe: sub_id=%d not found\n",
		sub_id);
	return -1;
}

/*
 * Poll for pending D-Bus signals. Called from the main loop
 * (pvcm_run) on each iteration. Non-blocking — dispatches
 * any queued signals via the filter callback.
 */
void pvcm_dbus_bridge_poll(void)
{
	if (!dbus_conn)
		return;

	/* non-blocking: read anything available, dispatch signals.
	 * Returns TRUE if connected, FALSE if disconnected. */
	dbus_connection_read_write_dispatch(dbus_conn, 0);
}

void pvcm_dbus_bridge_cleanup(void)
{
	if (!dbus_conn)
		return;

	/* remove all subscriptions */
	for (int i = 0; i < MAX_SUBS; i++) {
		if (subs[i].active) {
			DBusError err;
			dbus_error_init(&err);
			dbus_bus_remove_match(dbus_conn, subs[i].match_rule, &err);
			dbus_error_free(&err);
			subs[i].active = false;
		}
	}

	dbus_connection_unref(dbus_conn);
	dbus_conn = NULL;

	fprintf(stdout, "[dbus-bridge] cleaned up\n");
}
