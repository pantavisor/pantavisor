/*
 * pvcm-proxy D-Bus bridge
 *
 * Bridges PVCM DBUS_CALL/SUBSCRIBE frames to the Linux system D-Bus.
 *
 * Architecture:
 *   - We own the Unix socket to the D-Bus daemon (no DBusConnection)
 *   - AUTH EXTERNAL handshake done manually (3 text lines)
 *   - libdbus used ONLY for type marshalling: dbus_message_marshal()
 *     and dbus_message_demarshal() convert between DBusMessage objects
 *     and wire bytes. This can be replaced with custom marshalling later.
 *   - Single-threaded: poll() called from main loop for signal delivery
 *   - Works standalone (direct system bus) or via xconnect D-Bus proxy
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_dbus_bridge.h"

#include <dbus/dbus.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>

#include <event2/event.h>

/* D-Bus socket fd — we own this, not libdbus */
static int dbus_fd = -1;
static struct pvcm_transport *bridge_transport;
static uint32_t next_serial = 1;
static char unique_name[64]; /* our bus name, e.g. ":1.42" */

/* read buffer for incoming D-Bus messages */
#define DBUS_READ_BUF_SIZE 65536
static uint8_t dbus_read_buf[DBUS_READ_BUF_SIZE];
static size_t dbus_read_len;

/* pending D-Bus method calls — async, one at a time */
#define MAX_PENDING_CALLS 4

struct pending_dbus_call {
	uint32_t serial;       /* D-Bus serial we sent */
	uint8_t pvcm_req_id;   /* PVCM req_id to respond with */
	bool active;
	struct event *timeout_ev;
};

static struct pending_dbus_call pending_calls[MAX_PENDING_CALLS];

/* ---- signal subscriptions ---- */

#define MAX_SUBS 16

struct dbus_sub {
	uint8_t sub_id;
	bool active;
	char sender[64];
	char path[128];
	char interface[128];
	char member[64];
};

static struct dbus_sub subs[MAX_SUBS];

/* ---- null-separated field packing/unpacking ---- */

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

/* ---- D-Bus → JSON serialization (uses libdbus iterators) ---- */

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

static int dbus_reply_to_json(DBusMessage *reply, char *buf, size_t buf_size)
{
	DBusMessageIter iter;
	if (!dbus_message_iter_init(reply, &iter)) {
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

	if (nargs == 1)
		return dbus_arg_to_json(&iter, buf, buf_size);

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

	if (n < (int)buf_size) buf[n++] = ']';
	if (n < (int)buf_size) buf[n] = '\0';
	return n;
}

/* ---- JSON → D-Bus argument marshalling ---- */

static int json_args_to_dbus(DBusMessage *msg, const char *json)
{
	if (!json || json[0] == '\0')
		return 0;

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
				DBUS_TYPE_BOOLEAN, &v, DBUS_TYPE_INVALID);
			p += 4;
		} else if (*p == 'f' && strncmp(p, "false", 5) == 0) {
			dbus_bool_t v = FALSE;
			dbus_message_append_args(msg,
				DBUS_TYPE_BOOLEAN, &v, DBUS_TYPE_INVALID);
			p += 5;
		} else if (*p == '-' || (*p >= '0' && *p <= '9')) {
			const char *start = p;
			bool is_float = false;
			if (*p == '-') p++;
			while (*p >= '0' && *p <= '9') p++;
			if (*p == '.') { is_float = true; p++;
				while (*p >= '0' && *p <= '9') p++; }

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
			/* bare word — treat as unquoted string
			 * (common when Zephyr shell strips quotes) */
			const char *start = p;
			while (*p && *p != ',' && *p != ']' &&
			       *p != ' ' && *p != '\t')
				p++;
			size_t len = p - start;
			char val[256];
			if (len >= sizeof(val)) len = sizeof(val) - 1;
			memcpy(val, start, len);
			val[len] = '\0';
			dbus_message_append_args(msg,
				DBUS_TYPE_STRING, &(const char *){val},
				DBUS_TYPE_INVALID);
		}
	}

	return 0;
}

/* ---- raw D-Bus wire I/O ---- */

/*
 * Read a line from the D-Bus socket (for AUTH handshake).
 * Returns line length (excluding \r\n), or -1 on error.
 */
static int dbus_read_line(char *buf, size_t buf_size, int timeout_ms)
{
	size_t off = 0;

	while (off < buf_size - 1) {
		struct pollfd pfd = { .fd = dbus_fd, .events = POLLIN };
		int ret = poll(&pfd, 1, timeout_ms);
		if (ret <= 0)
			return -1;

		char c;
		ssize_t n = read(dbus_fd, &c, 1);
		if (n <= 0)
			return -1;

		if (c == '\n') {
			/* strip trailing \r */
			if (off > 0 && buf[off - 1] == '\r')
				off--;
			buf[off] = '\0';
			return (int)off;
		}
		buf[off++] = c;
	}

	return -1;
}

/*
 * Write all bytes to the D-Bus socket.
 */
static int dbus_write_all(const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(dbus_fd, p + off, len - off);
		if (n <= 0)
			return -1;
		off += n;
	}

	return 0;
}

/*
 * Send a marshalled D-Bus message on the wire.
 * Uses dbus_message_marshal() from libdbus for type serialization.
 */
static int dbus_send_msg(DBusMessage *msg)
{
	uint32_t serial = next_serial++;
	dbus_message_set_serial(msg, serial);

	char *raw = NULL;
	int raw_len = 0;

	if (!dbus_message_marshal(msg, &raw, &raw_len)) {
		fprintf(stderr, "[dbus-bridge] marshal failed\n");
		return -1;
	}

	int ret = dbus_write_all(raw, raw_len);
	dbus_free(raw);

	if (ret < 0) {
		fprintf(stderr, "[dbus-bridge] write failed: %m\n");
		return -1;
	}

	return (int)serial;
}

/*
 * Try to read and demarshal one D-Bus message from the socket.
 * Non-blocking if no data available. Returns message or NULL.
 */
static DBusMessage *dbus_recv_msg(int timeout_ms)
{
	/* try to complete a message from buffered data first */
	while (1) {
		if (dbus_read_len >= 16) {
			int needed = dbus_message_demarshal_bytes_needed(
				(const char *)dbus_read_buf, dbus_read_len);
			if (needed > 0 && (size_t)needed <= dbus_read_len) {
				DBusError err;
				dbus_error_init(&err);
				DBusMessage *msg = dbus_message_demarshal(
					(const char *)dbus_read_buf,
					needed, &err);
				/* consume the bytes */
				dbus_read_len -= needed;
				if (dbus_read_len > 0)
					memmove(dbus_read_buf,
						dbus_read_buf + needed,
						dbus_read_len);
				if (msg)
					return msg;
				fprintf(stderr, "[dbus-bridge] demarshal: %s\n",
					err.message);
				dbus_error_free(&err);
				return NULL;
			}
		}

		/* need more data */
		struct pollfd pfd = { .fd = dbus_fd, .events = POLLIN };
		int ret = poll(&pfd, 1, timeout_ms);
		if (ret <= 0)
			return NULL;

		ssize_t n = read(dbus_fd, dbus_read_buf + dbus_read_len,
				 DBUS_READ_BUF_SIZE - dbus_read_len);
		if (n <= 0)
			return NULL;
		dbus_read_len += n;

		/* after first read, don't wait again — process what we have */
		timeout_ms = 0;
	}
}

/*
 * Send a method call and wait for the reply.
 * Returns the reply message (caller must unref), or NULL on error.
 */
static DBusMessage *dbus_call_method(DBusMessage *msg, int timeout_ms)
{
	int serial = dbus_send_msg(msg);
	if (serial < 0)
		return NULL;

	/* read messages until we get a reply matching our serial */
	int elapsed = 0;
	while (elapsed < timeout_ms) {
		int wait = timeout_ms - elapsed;
		if (wait > 1000) wait = 1000;

		DBusMessage *reply = dbus_recv_msg(wait);
		elapsed += wait;

		if (!reply)
			continue;

		int type = dbus_message_get_type(reply);
		uint32_t reply_serial = dbus_message_get_reply_serial(reply);

		if ((type == DBUS_MESSAGE_TYPE_METHOD_RETURN ||
		     type == DBUS_MESSAGE_TYPE_ERROR) &&
		    reply_serial == (uint32_t)serial) {
			return reply;
		}

		/* not our reply — might be a signal, handle it */
		if (type == DBUS_MESSAGE_TYPE_SIGNAL)
			; /* TODO: dispatch to signal handler inline */

		dbus_message_unref(reply);
	}

	return NULL;
}

/* ---- AUTH handshake ---- */

static int dbus_auth(void)
{
	/* send NUL byte (required by D-Bus spec) */
	char nul = '\0';
	if (write(dbus_fd, &nul, 1) != 1)
		return -1;

	/* AUTH EXTERNAL with our UID in hex */
	char uid_str[32];
	snprintf(uid_str, sizeof(uid_str), "%u", (unsigned)getuid());

	char hex_uid[64];
	size_t off = 0;
	for (int i = 0; uid_str[i]; i++)
		off += snprintf(hex_uid + off, sizeof(hex_uid) - off,
				"%02x", (unsigned char)uid_str[i]);

	char auth_cmd[128];
	int len = snprintf(auth_cmd, sizeof(auth_cmd),
			   "AUTH EXTERNAL %s\r\n", hex_uid);
	if (dbus_write_all(auth_cmd, len) < 0)
		return -1;

	/* read OK <guid> */
	char line[256];
	if (dbus_read_line(line, sizeof(line), 5000) < 0)
		return -1;

	if (strncmp(line, "OK ", 3) != 0) {
		fprintf(stderr, "[dbus-bridge] AUTH failed: %s\n", line);
		return -1;
	}

	/* send BEGIN */
	if (dbus_write_all("BEGIN\r\n", 7) < 0)
		return -1;

	fprintf(stdout, "[dbus-bridge] AUTH OK\n");
	return 0;
}

/* ---- Hello() — get our unique bus name ---- */

static int dbus_hello(void)
{
	DBusMessage *msg = dbus_message_new_method_call(
		"org.freedesktop.DBus",
		"/org/freedesktop/DBus",
		"org.freedesktop.DBus",
		"Hello");
	if (!msg)
		return -1;

	DBusMessage *reply = dbus_call_method(msg, 5000);
	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr, "[dbus-bridge] Hello() failed\n");
		return -1;
	}

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		fprintf(stderr, "[dbus-bridge] Hello() error\n");
		dbus_message_unref(reply);
		return -1;
	}

	const char *name = NULL;
	dbus_message_get_args(reply, NULL,
			      DBUS_TYPE_STRING, &name,
			      DBUS_TYPE_INVALID);
	if (name)
		snprintf(unique_name, sizeof(unique_name), "%s", name);

	fprintf(stdout, "[dbus-bridge] Hello: %s\n", unique_name);
	dbus_message_unref(reply);
	return 0;
}

/* ---- signal handling ---- */

static void handle_signal(DBusMessage *msg)
{
	const char *sender = dbus_message_get_sender(msg);
	const char *path = dbus_message_get_path(msg);
	const char *iface = dbus_message_get_interface(msg);
	const char *member = dbus_message_get_member(msg);

	if (!sender) sender = "";
	if (!path) path = "";
	if (!iface) iface = "";
	if (!member) member = "";

	for (int i = 0; i < MAX_SUBS; i++) {
		if (!subs[i].active)
			continue;

		if (subs[i].sender[0] && strcmp(subs[i].sender, sender) != 0)
			continue;
		if (subs[i].path[0] && strcmp(subs[i].path, path) != 0)
			continue;
		if (subs[i].interface[0] && strcmp(subs[i].interface, iface) != 0)
			continue;
		if (subs[i].member[0] && strcmp(subs[i].member, member) != 0)
			continue;

		char args_json[200] = "";
		dbus_reply_to_json(msg, args_json, sizeof(args_json));

		pvcm_dbus_signal_t sig = {
			.op = PVCM_OP_DBUS_SIGNAL,
			.sub_id = subs[i].sub_id,
		};

		int dlen = pack_fields(sig.data, sizeof(sig.data),
				       sender, path, iface, member,
				       args_json, NULL);
		if (dlen < 0)
			continue;
		sig.data_len = (uint16_t)dlen;

		bridge_transport->send_frame(bridge_transport, &sig, 4 + dlen);

		fprintf(stdout, "[dbus-bridge] signal: %s.%s → sub_id=%d\n",
			iface, member, subs[i].sub_id);
	}
}

/* ---- AddMatch helper ---- */

static int dbus_add_match(const char *rule)
{
	DBusMessage *msg = dbus_message_new_method_call(
		"org.freedesktop.DBus",
		"/org/freedesktop/DBus",
		"org.freedesktop.DBus",
		"AddMatch");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
		DBUS_TYPE_STRING, &rule,
		DBUS_TYPE_INVALID);

	DBusMessage *reply = dbus_call_method(msg, 5000);
	dbus_message_unref(msg);

	if (!reply)
		return -1;

	int ret = 0;
	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		ret = -1;

	dbus_message_unref(reply);
	return ret;
}

static int dbus_remove_match(const char *rule)
{
	DBusMessage *msg = dbus_message_new_method_call(
		"org.freedesktop.DBus",
		"/org/freedesktop/DBus",
		"org.freedesktop.DBus",
		"RemoveMatch");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
		DBUS_TYPE_STRING, &rule,
		DBUS_TYPE_INVALID);

	/* fire and forget — don't wait for reply */
	dbus_send_msg(msg);
	dbus_message_unref(msg);
	return 0;
}

/* ---- public API ---- */

static struct event *dbus_read_ev;
static struct event_base *dbus_event_base;

/*
 * Handle a D-Bus method return or error matching a pending call.
 * Builds the PVCM CALL_RESP frame and sends it to the MCU.
 */
static void handle_dbus_reply(struct pending_dbus_call *pc, DBusMessage *reply)
{
	pvcm_dbus_call_resp_t resp = {
		.op = PVCM_OP_DBUS_CALL_RESP,
		.req_id = pc->pvcm_req_id,
	};

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_name = dbus_message_get_error_name(reply);
		if (!err_name) err_name = "Unknown";

		resp.error = PVCM_DBUS_ERR_FAILED;
		if (strstr(err_name, "ServiceUnknown"))
			resp.error = PVCM_DBUS_ERR_NO_SERVICE;
		else if (strstr(err_name, "UnknownMethod"))
			resp.error = PVCM_DBUS_ERR_NO_METHOD;

		const char *err_msg = NULL;
		dbus_message_get_args(reply, NULL,
			DBUS_TYPE_STRING, &err_msg, DBUS_TYPE_INVALID);

		int elen = snprintf(resp.data, sizeof(resp.data),
				    "%s: %s", err_name,
				    err_msg ? err_msg : "");
		if (elen < 0) elen = 0;
		if (elen > (int)sizeof(resp.data) - 1)
			elen = sizeof(resp.data) - 1;
		resp.data_len = (uint16_t)elen;

		fprintf(stderr, "[dbus-bridge] CALL error: %s\n", resp.data);
	} else {
		int json_len = dbus_reply_to_json(reply, resp.data,
						  sizeof(resp.data) - 1);
		if (json_len < 0) {
			resp.error = PVCM_DBUS_ERR_TRUNCATED;
			int elen = snprintf(resp.data, sizeof(resp.data),
					    "reply exceeds %zu byte frame limit",
					    sizeof(resp.data) - 1);
			resp.data_len = (uint16_t)elen;
			fprintf(stderr, "[dbus-bridge] CALL truncated: %s\n",
				resp.data);
		} else {
			resp.error = PVCM_DBUS_OK;
			resp.data[json_len] = '\0';
			resp.data_len = (uint16_t)json_len;
			fprintf(stdout, "[dbus-bridge] CALL result: %.*s\n",
				(int)resp.data_len, resp.data);
		}
	}

	bridge_transport->send_frame(bridge_transport, &resp,
				     6 + resp.data_len);

	/* clean up pending call */
	if (pc->timeout_ev) {
		evtimer_del(pc->timeout_ev);
		event_free(pc->timeout_ev);
		pc->timeout_ev = NULL;
	}
	pc->active = false;
}

/* D-Bus call timeout callback */
static void dbus_call_timeout_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	struct pending_dbus_call *pc = arg;

	if (!pc->active)
		return;

	fprintf(stderr, "[dbus-bridge] CALL timeout (req_id=%d serial=%u)\n",
		pc->pvcm_req_id, pc->serial);

	pvcm_dbus_call_resp_t resp = {
		.op = PVCM_OP_DBUS_CALL_RESP,
		.req_id = pc->pvcm_req_id,
		.error = PVCM_DBUS_ERR_TIMEOUT,
	};
	const char *emsg = "D-Bus call timeout";
	resp.data_len = (uint16_t)strlen(emsg);
	memcpy(resp.data, emsg, resp.data_len);
	bridge_transport->send_frame(bridge_transport, &resp,
				     6 + resp.data_len);

	pc->timeout_ev = NULL;
	pc->active = false;
}

/* libevent callback: dbus_fd is readable — dispatch signals and replies */
static void dbus_read_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	(void)arg;

	if (dbus_fd < 0)
		return;

	/* drain all available messages */
	for (;;) {
		DBusMessage *msg = dbus_recv_msg(0);
		if (!msg)
			break;

		int type = dbus_message_get_type(msg);

		if (type == DBUS_MESSAGE_TYPE_SIGNAL) {
			handle_signal(msg);
		} else if (type == DBUS_MESSAGE_TYPE_METHOD_RETURN ||
			   type == DBUS_MESSAGE_TYPE_ERROR) {
			uint32_t reply_serial =
				dbus_message_get_reply_serial(msg);
			bool handled = false;
			for (int i = 0; i < MAX_PENDING_CALLS; i++) {
				if (pending_calls[i].active &&
				    pending_calls[i].serial == reply_serial) {
					handle_dbus_reply(&pending_calls[i],
							  msg);
					handled = true;
					break;
				}
			}
			if (!handled) {
				/* orphaned reply — from Hello() or AddMatch,
				 * or stale call. Just ignore. */
			}
		}

		dbus_message_unref(msg);
	}
}

int pvcm_dbus_bridge_init(struct event_base *base,
			   struct pvcm_transport *t,
			   const char *socket_path)
{
	if (!socket_path || socket_path[0] == '\0') {
		fprintf(stdout, "[dbus-bridge] no socket path, D-Bus disabled\n");
		return 0;
	}

	bridge_transport = t;
	memset(subs, 0, sizeof(subs));
	dbus_read_len = 0;
	next_serial = 1;

	/* connect to D-Bus unix socket */
	dbus_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (dbus_fd < 0) {
		fprintf(stderr, "[dbus-bridge] socket() failed: %m\n");
		return -1;
	}

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

	if (connect(dbus_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "[dbus-bridge] connect(%s) failed: %m\n",
			socket_path);
		close(dbus_fd);
		dbus_fd = -1;
		return -1;
	}

	/* AUTH EXTERNAL handshake (blocking — before event loop) */
	if (dbus_auth() < 0) {
		close(dbus_fd);
		dbus_fd = -1;
		return -1;
	}

	/* Hello() to get unique name (blocking — before event loop) */
	if (dbus_hello() < 0) {
		close(dbus_fd);
		dbus_fd = -1;
		return -1;
	}

	/* register read event for async signal and reply delivery */
	dbus_event_base = base;
	if (base) {
		dbus_read_ev = event_new(base, dbus_fd,
					 EV_READ | EV_PERSIST,
					 dbus_read_cb, NULL);
		event_add(dbus_read_ev, NULL);
	}

	fprintf(stdout, "[dbus-bridge] connected to %s as %s\n",
		socket_path, unique_name);
	return 0;
}

int pvcm_dbus_bridge_on_call(struct pvcm_transport *t,
			     const uint8_t *buf, int len)
{
	if (dbus_fd < 0) {
		pvcm_dbus_call_resp_t resp = {
			.op = PVCM_OP_DBUS_CALL_RESP,
			.req_id = buf[1],
			.error = PVCM_DBUS_ERR_FAILED,
		};
		const char *emsg = "D-Bus not connected";
		resp.data_len = (uint16_t)strlen(emsg);
		memcpy(resp.data, emsg, resp.data_len);
		t->send_frame(t, &resp, 6 + resp.data_len);
		return -1;
	}

	const pvcm_dbus_call_t *call = (const pvcm_dbus_call_t *)buf;

	const char *fields[5] = { "", "", "", "", "" };
	int nf = unpack_fields(call->data, call->data_len, fields, 5);

	if (nf < 4) {
		pvcm_dbus_call_resp_t resp = {
			.op = PVCM_OP_DBUS_CALL_RESP,
			.req_id = call->req_id,
			.error = PVCM_DBUS_ERR_ARGS,
		};
		const char *emsg = "need dest, path, iface, member";
		resp.data_len = (uint16_t)strlen(emsg);
		memcpy(resp.data, emsg, resp.data_len);
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

	/* build D-Bus message — libdbus for type marshalling only */
	DBusMessage *msg = dbus_message_new_method_call(
		dest, obj_path, iface, member);
	if (!msg) {
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

	if (args_json && args_json[0]) {
		if (json_args_to_dbus(msg, args_json) < 0) {
			dbus_message_unref(msg);
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

	/* find a free pending call slot */
	struct pending_dbus_call *pc = NULL;
	for (int i = 0; i < MAX_PENDING_CALLS; i++) {
		if (!pending_calls[i].active) {
			pc = &pending_calls[i];
			break;
		}
	}
	if (!pc) {
		dbus_message_unref(msg);
		pvcm_dbus_call_resp_t resp = {
			.op = PVCM_OP_DBUS_CALL_RESP,
			.req_id = call->req_id,
			.error = PVCM_DBUS_ERR_FAILED,
		};
		const char *emsg = "too many pending D-Bus calls";
		resp.data_len = (uint16_t)strlen(emsg);
		memcpy(resp.data, emsg, resp.data_len);
		t->send_frame(t, &resp, 6 + resp.data_len);
		return -1;
	}

	/* send message asynchronously — reply arrives via dbus_read_cb */
	int serial = dbus_send_msg(msg);
	dbus_message_unref(msg);

	if (serial < 0) {
		pvcm_dbus_call_resp_t resp = {
			.op = PVCM_OP_DBUS_CALL_RESP,
			.req_id = call->req_id,
			.error = PVCM_DBUS_ERR_FAILED,
		};
		const char *emsg = "failed to send D-Bus message";
		resp.data_len = (uint16_t)strlen(emsg);
		memcpy(resp.data, emsg, resp.data_len);
		t->send_frame(t, &resp, 6 + resp.data_len);
		return -1;
	}

	/* register pending call */
	pc->serial = (uint32_t)serial;
	pc->pvcm_req_id = call->req_id;
	pc->active = true;

	/* start 10s timeout */
	if (dbus_event_base) {
		pc->timeout_ev = evtimer_new(dbus_event_base,
					     dbus_call_timeout_cb, pc);
		struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
		evtimer_add(pc->timeout_ev, &tv);
	}

	return 0;
}

int pvcm_dbus_bridge_on_subscribe(struct pvcm_transport *t,
				  const uint8_t *buf, int len)
{
	if (dbus_fd < 0)
		return -1;

	const pvcm_dbus_sub_t *sub = (const pvcm_dbus_sub_t *)buf;

	int slot = -1;
	for (int i = 0; i < MAX_SUBS; i++) {
		if (!subs[i].active) {
			slot = i;
			break;
		}
	}
	if (slot < 0)
		return -1;

	const char *fields[4] = { "", "", "", "" };
	unpack_fields(sub->data, sub->data_len, fields, 4);

	struct dbus_sub *s = &subs[slot];
	s->sub_id = sub->sub_id;
	snprintf(s->sender, sizeof(s->sender), "%s", fields[0]);
	snprintf(s->path, sizeof(s->path), "%s", fields[1]);
	snprintf(s->interface, sizeof(s->interface), "%s", fields[2]);
	snprintf(s->member, sizeof(s->member), "%s", fields[3]);

	/* build and send AddMatch */
	char rule[512];
	int off = snprintf(rule, sizeof(rule), "type='signal'");
	if (s->sender[0])
		off += snprintf(rule + off, sizeof(rule) - off,
				",sender='%s'", s->sender);
	if (s->path[0])
		off += snprintf(rule + off, sizeof(rule) - off,
				",path='%s'", s->path);
	if (s->interface[0])
		off += snprintf(rule + off, sizeof(rule) - off,
				",interface='%s'", s->interface);
	if (s->member[0])
		off += snprintf(rule + off, sizeof(rule) - off,
				",member='%s'", s->member);

	if (dbus_add_match(rule) < 0) {
		fprintf(stderr, "[dbus-bridge] AddMatch failed\n");
		return -1;
	}

	s->active = true;

	fprintf(stdout, "[dbus-bridge] subscribed: sub_id=%d rule=%s\n",
		s->sub_id, rule);
	return 0;
}

int pvcm_dbus_bridge_on_unsubscribe(struct pvcm_transport *t,
				    const uint8_t *buf, int len)
{
	if (dbus_fd < 0)
		return -1;

	uint8_t sub_id = buf[1];

	for (int i = 0; i < MAX_SUBS; i++) {
		if (subs[i].active && subs[i].sub_id == sub_id) {
			/* build match rule for removal */
			char rule[512];
			int off = snprintf(rule, sizeof(rule), "type='signal'");
			if (subs[i].sender[0])
				off += snprintf(rule + off, sizeof(rule) - off,
						",sender='%s'", subs[i].sender);
			if (subs[i].path[0])
				off += snprintf(rule + off, sizeof(rule) - off,
						",path='%s'", subs[i].path);
			if (subs[i].interface[0])
				off += snprintf(rule + off, sizeof(rule) - off,
						",interface='%s'", subs[i].interface);
			if (subs[i].member[0])
				off += snprintf(rule + off, sizeof(rule) - off,
						",member='%s'", subs[i].member);

			dbus_remove_match(rule);
			subs[i].active = false;
			fprintf(stdout, "[dbus-bridge] unsubscribed: sub_id=%d\n",
				sub_id);
			return 0;
		}
	}

	return -1;
}

void pvcm_dbus_bridge_cleanup(void)
{
	if (dbus_read_ev) {
		event_free(dbus_read_ev);
		dbus_read_ev = NULL;
	}

	for (int i = 0; i < MAX_PENDING_CALLS; i++) {
		if (pending_calls[i].timeout_ev) {
			evtimer_del(pending_calls[i].timeout_ev);
			event_free(pending_calls[i].timeout_ev);
			pending_calls[i].timeout_ev = NULL;
		}
		pending_calls[i].active = false;
	}

	memset(subs, 0, sizeof(subs));

	if (dbus_fd >= 0) {
		close(dbus_fd);
		dbus_fd = -1;
	}

	dbus_event_base = NULL;
	fprintf(stdout, "[dbus-bridge] cleaned up\n");
}
