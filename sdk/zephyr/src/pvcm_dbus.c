/*
 * PVCM D-Bus Gateway Client — async, streaming, no size limits
 *
 * All D-Bus calls are async: pvcm_dbus_call() sends and returns
 * immediately. Responses arrive via callback on the server thread.
 *
 * Wire format: metadata header + DBUS_DATA frames.
 * Data is dynamically allocated — no fixed buffers.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>
#include <pantavisor/pvcm_transport.h>

#include <string.h>

LOG_MODULE_REGISTER(pvcm_dbus, CONFIG_LOG_DEFAULT_LEVEL);

/* ---- Pending D-Bus calls ---- */

#define MAX_DBUS_PENDING 4

struct dbus_pending_call {
	uint8_t req_id;
	bool active;
	pvcm_dbus_cb_t cb;
	void *ctx;
	uint32_t expected;     /* total data_len from CALL_RESP */
	uint8_t error;
	char *data;            /* k_malloc'd result buffer */
	size_t data_len;
};

static struct dbus_pending_call dbus_calls[MAX_DBUS_PENDING];
static uint8_t next_req_id = 1;

/* ---- Signal subscriptions ---- */

#define MAX_DBUS_SUBS 16

static struct {
	uint8_t sub_id;
	bool active;
	pvcm_dbus_signal_cb_t cb;
	void *ctx;
	/* pending signal data assembly */
	uint32_t expected;
	char *data;
	size_t data_len;
} dbus_subs[MAX_DBUS_SUBS];

static uint8_t next_sub_id = 1;

/* ---- Field packing ---- */

static int pack_fields(char *buf, size_t buf_size,
		       const char *f1, const char *f2,
		       const char *f3, const char *f4,
		       const char *f5)
{
	const char *fields[] = { f1, f2, f3, f4, f5 };
	size_t off = 0;

	for (int i = 0; i < 5; i++) {
		if (!fields[i])
			break;
		size_t len = strlen(fields[i]);
		if (off + len + 1 > buf_size)
			return -ENOMEM;
		memcpy(buf + off, fields[i], len);
		off += len;
		buf[off++] = '\0';
	}

	return (int)off;
}

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

/* Send data as DBUS_DATA frames */
static void send_dbus_data_frames(const struct pvcm_transport *t,
				  uint8_t id, const char *data, size_t len)
{
	size_t off = 0;
	while (off < len) {
		pvcm_dbus_data_t frame = {
			.op = PVCM_OP_DBUS_DATA,
			.id = id,
		};
		size_t chunk = len - off;
		if (chunk > PVCM_MAX_CHUNK_SIZE)
			chunk = PVCM_MAX_CHUNK_SIZE;
		frame.len = (uint16_t)chunk;
		memcpy(frame.data, data + off, chunk);
		t->send_frame(&frame, 4 + chunk);
		off += chunk;
	}
}

/* ---- Response handlers (called from server thread) ---- */

void pvcm_dbus_on_call_resp(const uint8_t *buf, int len)
{
	const pvcm_dbus_call_resp_t *resp = (const pvcm_dbus_call_resp_t *)buf;

	/* find matching pending call */
	struct dbus_pending_call *pc = NULL;
	for (int i = 0; i < MAX_DBUS_PENDING; i++) {
		if (dbus_calls[i].active &&
		    dbus_calls[i].req_id == resp->req_id) {
			pc = &dbus_calls[i];
			break;
		}
	}
	if (!pc)
		return;

	pc->error = resp->error;
	pc->expected = resp->data_len;

	if (resp->data_len > 0) {
		pc->data = k_malloc(resp->data_len + 1);
		if (pc->data)
			pc->data[0] = '\0';
	}
	pc->data_len = 0;

	/* if no data expected, deliver immediately */
	if (resp->data_len == 0) {
		if (pc->cb) {
			pc->cb(pc->error, "", 0, pc->ctx);
		}
		k_free(pc->data);
		pc->data = NULL;
		pc->active = false;
	}
}

void pvcm_dbus_on_signal(const uint8_t *buf, int len)
{
	const pvcm_dbus_signal_t *sig = (const pvcm_dbus_signal_t *)buf;

	for (int i = 0; i < MAX_DBUS_SUBS; i++) {
		if (!dbus_subs[i].active || dbus_subs[i].sub_id != sig->sub_id)
			continue;

		/* allocate buffer for signal data */
		k_free(dbus_subs[i].data);
		dbus_subs[i].expected = sig->data_len;
		dbus_subs[i].data_len = 0;

		if (sig->data_len > 0) {
			dbus_subs[i].data = k_malloc(sig->data_len + 1);
			if (dbus_subs[i].data)
				dbus_subs[i].data[0] = '\0';
		} else {
			dbus_subs[i].data = NULL;
			/* empty signal — deliver immediately */
			dbus_subs[i].cb("", "", "", "", "",
					dbus_subs[i].ctx);
		}
		return;
	}

	LOG_WRN("signal for unknown sub_id=%d", sig->sub_id);
}

/*
 * DBUS_DATA — accumulate data for pending call response or signal.
 */
void pvcm_dbus_on_data(const uint8_t *buf, int len)
{
	if (len < 4)
		return;

	const pvcm_dbus_data_t *d = (const pvcm_dbus_data_t *)buf;
	size_t chunk = d->len;

	/* check pending calls */
	for (int i = 0; i < MAX_DBUS_PENDING; i++) {
		struct dbus_pending_call *pc = &dbus_calls[i];
		if (!pc->active || pc->req_id != d->id || !pc->data)
			continue;

		if (pc->data_len + chunk > pc->expected)
			chunk = pc->expected - pc->data_len;
		memcpy(pc->data + pc->data_len, d->data, chunk);
		pc->data_len += chunk;
		pc->data[pc->data_len] = '\0';

		/* all data received? deliver */
		if (pc->data_len >= pc->expected) {
			if (pc->cb) {
				pc->cb(pc->error, pc->data, pc->data_len,
				       pc->ctx);
			}
			k_free(pc->data);
			pc->data = NULL;
			pc->active = false;
		}
		return;
	}

	/* check pending signals */
	for (int i = 0; i < MAX_DBUS_SUBS; i++) {
		if (!dbus_subs[i].active || dbus_subs[i].sub_id != d->id ||
		    !dbus_subs[i].data)
			continue;

		if (dbus_subs[i].data_len + chunk > dbus_subs[i].expected)
			chunk = dbus_subs[i].expected - dbus_subs[i].data_len;
		memcpy(dbus_subs[i].data + dbus_subs[i].data_len,
		       d->data, chunk);
		dbus_subs[i].data_len += chunk;
		dbus_subs[i].data[dbus_subs[i].data_len] = '\0';

		/* all data? unpack and deliver */
		if (dbus_subs[i].data_len >= dbus_subs[i].expected) {
			const char *fields[5] = { "", "", "", "", "" };
			unpack_fields(dbus_subs[i].data,
				      dbus_subs[i].data_len, fields, 5);

			dbus_subs[i].cb(fields[0], fields[1], fields[2],
					fields[3], fields[4],
					dbus_subs[i].ctx);

			k_free(dbus_subs[i].data);
			dbus_subs[i].data = NULL;
		}
		return;
	}
}

/* ---- Public API (async) ---- */

int pvcm_dbus_call(const char *dest, const char *obj_path,
		   const char *interface, const char *member,
		   const char *args_json,
		   pvcm_dbus_cb_t cb, void *ctx)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	/* find free slot */
	struct dbus_pending_call *pc = NULL;
	for (int i = 0; i < MAX_DBUS_PENDING; i++) {
		if (!dbus_calls[i].active) {
			pc = &dbus_calls[i];
			break;
		}
	}
	if (!pc)
		return -ENOMEM;

	uint8_t rid = next_req_id++;
	if (next_req_id == 0)
		next_req_id = 1;

	/* pack fields into dynamic buffer */
	size_t total = strlen(dest) + strlen(obj_path) + strlen(interface) +
		       strlen(member) + (args_json ? strlen(args_json) : 0) + 5;
	char *packed = k_malloc(total);
	if (!packed)
		return -ENOMEM;

	int dlen = pack_fields(packed, total, dest, obj_path, interface,
			       member, args_json);
	if (dlen < 0) {
		k_free(packed);
		return -ENOMEM;
	}

	/* setup pending */
	memset(pc, 0, sizeof(*pc));
	pc->req_id = rid;
	pc->active = true;
	pc->cb = cb;
	pc->ctx = ctx;

	/* send CALL metadata */
	pvcm_dbus_call_t call = {
		.op = PVCM_OP_DBUS_CALL,
		.req_id = rid,
		.data_len = (uint16_t)dlen,
	};
	t->send_frame(&call, sizeof(call) - sizeof(uint32_t));

	/* send data */
	send_dbus_data_frames(t, rid, packed, dlen);
	k_free(packed);

	LOG_INF("D-Bus call: %s %s %s.%s (async, req_id=%d)",
		dest, obj_path, interface, member, rid);

	return 0;
}

int pvcm_dbus_subscribe(const char *sender, const char *obj_path,
			const char *interface, const char *signal_name,
			pvcm_dbus_signal_cb_t cb, void *ctx)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	int slot = -1;
	for (int i = 0; i < MAX_DBUS_SUBS; i++) {
		if (!dbus_subs[i].active) {
			slot = i;
			break;
		}
	}
	if (slot < 0)
		return -ENOMEM;

	uint8_t sid = next_sub_id++;
	if (next_sub_id == 0)
		next_sub_id = 1;

	/* pack fields */
	size_t total = (sender ? strlen(sender) : 0) +
		       (obj_path ? strlen(obj_path) : 0) +
		       (interface ? strlen(interface) : 0) +
		       (signal_name ? strlen(signal_name) : 0) + 4;
	char *packed = k_malloc(total);
	if (!packed)
		return -ENOMEM;

	int dlen = pack_fields(packed, total,
			       sender ? sender : "",
			       obj_path ? obj_path : "",
			       interface ? interface : "",
			       signal_name ? signal_name : "",
			       NULL);
	if (dlen < 0) {
		k_free(packed);
		return -ENOMEM;
	}

	/* register before sending */
	dbus_subs[slot].sub_id = sid;
	dbus_subs[slot].cb = cb;
	dbus_subs[slot].ctx = ctx;
	dbus_subs[slot].active = true;
	dbus_subs[slot].data = NULL;

	/* send SUBSCRIBE metadata */
	pvcm_dbus_sub_t sub = {
		.op = PVCM_OP_DBUS_SUBSCRIBE,
		.sub_id = sid,
		.data_len = (uint16_t)dlen,
	};
	t->send_frame(&sub, sizeof(sub) - sizeof(uint32_t));

	/* send data */
	send_dbus_data_frames(t, sid, packed, dlen);
	k_free(packed);

	LOG_INF("D-Bus subscribe: sub_id=%d (async)", sid);

	return sid;
}

int pvcm_dbus_unsubscribe(int sub_id)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	for (int i = 0; i < MAX_DBUS_SUBS; i++) {
		if (dbus_subs[i].active &&
		    dbus_subs[i].sub_id == (uint8_t)sub_id) {
			dbus_subs[i].active = false;
			k_free(dbus_subs[i].data);
			dbus_subs[i].data = NULL;

			pvcm_dbus_unsub_t unsub = {
				.op = PVCM_OP_DBUS_UNSUBSCRIBE,
				.sub_id = (uint8_t)sub_id,
			};
			t->send_frame(&unsub,
				      sizeof(unsub) - sizeof(uint32_t));

			LOG_INF("D-Bus unsubscribe: sub_id=%d", sub_id);
			return 0;
		}
	}

	return -ENOENT;
}
