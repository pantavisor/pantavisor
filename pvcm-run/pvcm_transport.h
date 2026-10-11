/*
 * pvcm-run transport abstraction
 *
 * Send path is queue-based: send_frame enqueues, libevent write
 * event drains. No blocking in any callback.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_TRANSPORT_H
#define PVCM_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

struct event_base;

struct pvcm_transport {
	int fd;
	const char *name;
	int (*open)(struct pvcm_transport *t, const char *device,
		    uint32_t baudrate);
	/* enqueue a frame for async sending. Returns 0 or -1 (queue full) */
	int (*send_frame)(struct pvcm_transport *t, const void *payload,
			  size_t len);
	/* blocking recv with timeout — used during handshake only */
	int (*recv_frame)(struct pvcm_transport *t, void *payload,
			  size_t max_len, int timeout_ms);
	/* non-blocking recv — used in event loop */
	int (*try_recv_frame)(struct pvcm_transport *t, void *payload,
			      size_t max_len);
	void (*close)(struct pvcm_transport *t);
};

/* Register write event with libevent for async send queue draining.
 * Call after handshake, before event_base_dispatch. */
int pvcm_transport_setup_write_event(struct pvcm_transport *t,
				     struct event_base *base);

extern struct pvcm_transport pvcm_transport_uart;
extern struct pvcm_transport pvcm_transport_rpmsg;

#endif
