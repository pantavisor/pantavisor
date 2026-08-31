/*
 * pvcm-run protocol handler
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_RUN_PROTOCOL_H
#define PVCM_RUN_PROTOCOL_H

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"

#include <stdbool.h>
#include <time.h>

struct pvcm_session {
	struct pvcm_transport *transport;
	bool connected;
	uint8_t protocol_version;
	uint8_t mcu_fw_version;
	uint32_t last_heartbeat_uptime;
	uint8_t last_health_status;
	uint8_t crash_count;
	time_t last_heartbeat_time;
};

/* Blocking handshake — call before event loop starts */
int pvcm_handshake(struct pvcm_session *s);

/*
 * Try to receive and dispatch one PVCM frame (non-blocking).
 * Uses transport->try_recv_frame().
 * Returns: >0 frame dispatched, 0 no frame available, <0 error.
 */
int pvcm_dispatch_one(struct pvcm_session *s);

#endif
