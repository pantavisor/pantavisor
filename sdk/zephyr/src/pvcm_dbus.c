/*
 * PVCM D-Bus Gateway Client
 *
 * Implements pvcm_dbus_call() and pvcm_dbus_subscribe() by translating
 * to DBUS_CALL/SUBSCRIBE/UNSUBSCRIBE frames.  Responses and signals
 * are delivered by the server dispatch thread.
 *
 * Follows the same pattern as pvcm_client.c (HTTP):
 *   - Single in-flight call (mutex-protected)
 *   - Semaphore-based request/response pairing
 *   - Callback array for signal subscriptions
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

static K_SEM_DEFINE(dbus_resp_sem, 0, 1);
static K_MUTEX_DEFINE(dbus_mutex);

/* pending method call (single in-flight for simplicity) */
static struct {
	uint8_t req_id;
	bool active;
	bool complete;
	uint8_t error;
	char result[248];
	size_t result_len;
} dbus_pending;

static uint8_t next_req_id = 1;

/* signal subscriptions */
#define MAX_DBUS_SUBS 16

static struct {
	uint8_t sub_id;
	bool active;
	pvcm_dbus_signal_cb_t cb;
	void *ctx;
} dbus_subs[MAX_DBUS_SUBS];

static uint8_t next_sub_id = 1;

/*
 * Pack null-separated fields into a data buffer.
 * Returns total bytes written, or negative on overflow.
 */
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

/*
 * Unpack null-separated fields from a data buffer.
 * Fills ptrs[] with up to max_fields pointers into buf.
 * Returns number of fields found.
 */
static int unpack_fields(const char *buf, size_t buf_len,
			 const char **ptrs, int max_fields)
{
	int count = 0;
	size_t off = 0;

	while (off < buf_len && count < max_fields) {
		ptrs[count++] = buf + off;
		/* advance past null terminator */
		while (off < buf_len && buf[off] != '\0')
			off++;
		off++; /* skip the null */
	}

	return count;
}

/*
 * Called by server thread when DBUS_CALL_RESP arrives.
 */
void pvcm_dbus_on_call_resp(const uint8_t *buf, int len)
{
	const pvcm_dbus_call_resp_t *resp = (const pvcm_dbus_call_resp_t *)buf;

	if (!dbus_pending.active || resp->req_id != dbus_pending.req_id)
		return;

	dbus_pending.error = resp->error;

	size_t dlen = resp->data_len;
	if (dlen > sizeof(dbus_pending.result) - 1)
		dlen = sizeof(dbus_pending.result) - 1;

	if (dlen > 0)
		memcpy(dbus_pending.result, resp->data, dlen);
	dbus_pending.result[dlen] = '\0';
	dbus_pending.result_len = dlen;
	dbus_pending.complete = true;

	k_sem_give(&dbus_resp_sem);
}

/*
 * Called by server thread when DBUS_SIGNAL arrives.
 */
void pvcm_dbus_on_signal(const uint8_t *buf, int len)
{
	const pvcm_dbus_signal_t *sig = (const pvcm_dbus_signal_t *)buf;

	/* find matching subscription */
	for (int i = 0; i < MAX_DBUS_SUBS; i++) {
		if (!dbus_subs[i].active || dbus_subs[i].sub_id != sig->sub_id)
			continue;

		/* unpack signal data: sender\0path\0iface\0member\0args_json */
		const char *fields[5] = { "", "", "", "", "" };
		int nf = unpack_fields(sig->data, sig->data_len, fields, 5);
		(void)nf;

		dbus_subs[i].cb(fields[0], fields[1], fields[2],
				fields[3], fields[4], dbus_subs[i].ctx);
		return;
	}

	LOG_WRN("signal for unknown sub_id=%d", sig->sub_id);
}

/*
 * Core D-Bus method call implementation.
 */
static int do_dbus_call(const char *dest, const char *obj_path,
			const char *interface, const char *member,
			const char *args_json,
			pvcm_dbus_cb_t cb, void *ctx)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	k_mutex_lock(&dbus_mutex, K_FOREVER);

	uint8_t rid = next_req_id++;
	if (next_req_id == 0)
		next_req_id = 1;

	/* set up pending response */
	dbus_pending.req_id = rid;
	dbus_pending.active = true;
	dbus_pending.complete = false;
	dbus_pending.error = 0;
	dbus_pending.result_len = 0;
	k_sem_reset(&dbus_resp_sem);

	/* build DBUS_CALL frame */
	pvcm_dbus_call_t call = {
		.op = PVCM_OP_DBUS_CALL,
		.req_id = rid,
	};

	int dlen = pack_fields(call.data, sizeof(call.data),
			       dest, obj_path, interface, member,
			       args_json);
	if (dlen < 0) {
		LOG_ERR("D-Bus call fields too long");
		dbus_pending.active = false;
		k_mutex_unlock(&dbus_mutex);
		return -ENOMEM;
	}
	call.data_len = (uint16_t)dlen;

	t->send_frame(&call, 4 + dlen); /* op + req_id + data_len + data */

	LOG_INF("D-Bus call: %s %s %s.%s", dest, obj_path, interface, member);

	/* wait for response from server thread */
	int ret = k_sem_take(&dbus_resp_sem, K_SECONDS(10));

	dbus_pending.active = false;

	if (ret != 0) {
		LOG_ERR("D-Bus call timeout: %s.%s", interface, member);
		k_mutex_unlock(&dbus_mutex);
		return -ETIMEDOUT;
	}

	LOG_INF("D-Bus response: error=%d len=%zu",
		dbus_pending.error, dbus_pending.result_len);

	if (cb) {
		cb(dbus_pending.error, dbus_pending.result,
		   dbus_pending.result_len, ctx);
	}

	k_mutex_unlock(&dbus_mutex);
	return 0;
}

int pvcm_dbus_call(const char *dest, const char *obj_path,
		   const char *interface, const char *member,
		   const char *args_json,
		   pvcm_dbus_cb_t cb, void *ctx)
{
	return do_dbus_call(dest, obj_path, interface, member,
			    args_json, cb, ctx);
}

int pvcm_dbus_subscribe(const char *sender, const char *obj_path,
			const char *interface, const char *signal_name,
			pvcm_dbus_signal_cb_t cb, void *ctx)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	/* find free slot */
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

	/* build DBUS_SUBSCRIBE frame */
	pvcm_dbus_sub_t sub = {
		.op = PVCM_OP_DBUS_SUBSCRIBE,
		.sub_id = sid,
	};

	int dlen = pack_fields(sub.data, sizeof(sub.data),
			       sender ? sender : "",
			       obj_path ? obj_path : "",
			       interface ? interface : "",
			       signal_name ? signal_name : "",
			       NULL);
	if (dlen < 0)
		return -ENOMEM;
	sub.data_len = (uint16_t)dlen;

	/* register before sending so we don't miss the first signal */
	dbus_subs[slot].sub_id = sid;
	dbus_subs[slot].cb = cb;
	dbus_subs[slot].ctx = ctx;
	dbus_subs[slot].active = true;

	t->send_frame(&sub, 4 + dlen);

	LOG_INF("D-Bus subscribe: sub_id=%d %s %s.%s",
		sid, obj_path ? obj_path : "*",
		interface ? interface : "*",
		signal_name ? signal_name : "*");

	return sid;
}

int pvcm_dbus_unsubscribe(int sub_id)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t)
		return -ENODEV;

	/* find and deactivate */
	for (int i = 0; i < MAX_DBUS_SUBS; i++) {
		if (dbus_subs[i].active && dbus_subs[i].sub_id == (uint8_t)sub_id) {
			dbus_subs[i].active = false;

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
