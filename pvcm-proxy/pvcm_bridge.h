/*
 * pvcm-proxy HTTP bridge
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_BRIDGE_H
#define PVCM_BRIDGE_H

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"

#include <stddef.h>

/* Initialize the HTTP bridge with the transport */
int pvcm_bridge_init(struct pvcm_transport *t);

/* Handle incoming HTTP frames from MCU (outbound requests) */
int pvcm_bridge_on_http_req(struct pvcm_transport *t,
			    const uint8_t *buf, int len);
int pvcm_bridge_on_http_data(struct pvcm_transport *t,
			     const uint8_t *buf, int len);
int pvcm_bridge_on_http_end(struct pvcm_transport *t,
			    const uint8_t *buf, int len);

/* Start HTTP listener for inbound requests to MCU (runs in thread) */
int pvcm_bridge_start_listener(struct pvcm_transport *t, int port);

/* Handle REPLY frames from MCU (responses to inbound requests) */
int pvcm_bridge_on_reply_req(struct pvcm_transport *t,
			     const uint8_t *buf, int len);
int pvcm_bridge_on_reply_data(struct pvcm_transport *t,
			      const uint8_t *buf, int len);
int pvcm_bridge_on_reply_end(struct pvcm_transport *t,
			     const uint8_t *buf, int len);

#endif
