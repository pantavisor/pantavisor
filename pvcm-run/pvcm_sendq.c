/*
 * pvcm-run send queue — async frame sending via libevent
 *
 * Callers enqueue PVCM wire frames (sync+len+payload+crc).
 * A libevent write event drains the queue when the transport fd
 * is writable. No blocking in any callback.
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>

/* ---- Queue entry ---- */

struct sendq_entry {
	struct sendq_entry *next;
	size_t len;
	uint8_t data[];  /* flexible array — wire frame bytes */
};

/* ---- Queue state ---- */

static struct sendq_entry *q_head;
static struct sendq_entry *q_tail;
static int q_count;
static int q_max = 256; /* max queued frames — backpressure limit */

static struct event *write_ev;
static struct pvcm_transport *write_transport;

/* CRC32 (same as transport implementations) */
static uint32_t crc32_table[256];
static int crc32_init_done;

static void crc32_init(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1) ? 0xEDB88320 ^ (c >> 1) : c >> 1;
		crc32_table[i] = c;
	}
	crc32_init_done = 1;
}

static uint32_t crc32_calc(const void *data, size_t len)
{
	if (!crc32_init_done)
		crc32_init();
	const uint8_t *p = data;
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; i++)
		crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}

/* ---- Enqueue ---- */

static int sendq_enqueue(const uint8_t *wire_frame, size_t wire_len)
{
	if (q_count >= q_max)
		return -1; /* backpressure */

	struct sendq_entry *e = malloc(sizeof(*e) + wire_len);
	if (!e)
		return -1;

	e->next = NULL;
	e->len = wire_len;
	memcpy(e->data, wire_frame, wire_len);

	if (q_tail)
		q_tail->next = e;
	else
		q_head = e;
	q_tail = e;
	q_count++;

	/* enable write event to drain */
	if (write_ev)
		event_add(write_ev, NULL);

	return 0;
}

/* ---- Write event callback ---- */

static void write_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)what;
	(void)arg;

	while (q_head) {
		struct sendq_entry *e = q_head;

		ssize_t n = write(fd, e->data, e->len);
		if (n == (ssize_t)e->len) {
			/* sent — dequeue */
			q_head = e->next;
			if (!q_head)
				q_tail = NULL;
			q_count--;
			free(e);
			continue;
		}

		if (n < 0 && (errno == ENOMEM || errno == EAGAIN)) {
			/* vring full — stop, libevent will re-trigger
			 * when fd is writable again */
			return;
		}

		/* real error or partial write */
		if (n >= 0)
			fprintf(stderr, "[sendq] partial write: %zd/%zu\n",
				n, e->len);
		else
			fprintf(stderr, "[sendq] write error: %m\n");

		/* drop the frame */
		q_head = e->next;
		if (!q_head)
			q_tail = NULL;
		q_count--;
		free(e);
	}

	/* queue drained — disable write event until next enqueue */
	if (write_ev)
		event_del(write_ev);
}

/* ---- Public: send_frame via queue ---- */

int pvcm_sendq_send_frame(struct pvcm_transport *t,
			   const void *payload, size_t len)
{
	/* build wire frame: sync + len + payload + crc */
	size_t wire_len = 4 + len + 4;
	uint8_t *frame = malloc(wire_len);
	if (!frame)
		return -1;

	frame[0] = PVCM_SYNC_BYTE_0;
	frame[1] = PVCM_SYNC_BYTE_1;
	frame[2] = len & 0xFF;
	frame[3] = (len >> 8) & 0xFF;
	memcpy(&frame[4], payload, len);

	uint32_t crc = crc32_calc(payload, len);
	frame[4 + len + 0] = crc & 0xFF;
	frame[4 + len + 1] = (crc >> 8) & 0xFF;
	frame[4 + len + 2] = (crc >> 16) & 0xFF;
	frame[4 + len + 3] = (crc >> 24) & 0xFF;

	int ret = sendq_enqueue(frame, wire_len);
	free(frame);

	if (ret < 0) {
		fprintf(stderr, "[sendq] queue full (%d frames)\n", q_count);
		return -1;
	}

	return 0;
}

/* ---- Setup ---- */

int pvcm_transport_setup_write_event(struct pvcm_transport *t,
				     struct event_base *base)
{
	write_transport = t;

	/* override send_frame to use the queue */
	t->send_frame = pvcm_sendq_send_frame;

	/* register write event — starts disabled, enabled on enqueue */
	write_ev = event_new(base, t->fd, EV_WRITE | EV_PERSIST,
			     write_cb, NULL);

	return 0;
}
