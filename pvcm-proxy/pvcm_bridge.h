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

/* Handle incoming HTTP frames from MCU */
int pvcm_bridge_on_http_req(struct pvcm_transport *t,
			    const uint8_t *buf, int len);
int pvcm_bridge_on_http_data(struct pvcm_transport *t,
			     const uint8_t *buf, int len);
int pvcm_bridge_on_http_end(struct pvcm_transport *t,
			    const uint8_t *buf, int len);

#endif
