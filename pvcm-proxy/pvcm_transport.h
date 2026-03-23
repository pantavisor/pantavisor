/*
 * pvcm-proxy transport abstraction
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_TRANSPORT_H
#define PVCM_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

struct pvcm_transport {
	int fd;
	const char *name;
	int (*open)(struct pvcm_transport *t, const char *device,
		    uint32_t baudrate);
	int (*send_frame)(struct pvcm_transport *t, const void *payload,
			  size_t len);
	int (*recv_frame)(struct pvcm_transport *t, void *payload,
			  size_t max_len, int timeout_ms);
	void (*close)(struct pvcm_transport *t);
};

extern struct pvcm_transport pvcm_transport_uart;
extern struct pvcm_transport pvcm_transport_rpmsg;

#endif
