/*
 * pvcm-proxy protocol handler
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_PROXY_PROTOCOL_H
#define PVCM_PROXY_PROTOCOL_H

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"

#include <stdbool.h>

struct pvcm_session {
	struct pvcm_transport *transport;
	bool connected;
	uint8_t protocol_version;
	uint8_t mcu_fw_version;
	uint32_t last_heartbeat_uptime;
	uint8_t last_health_status;
	uint8_t crash_count;
};

int pvcm_handshake(struct pvcm_session *s);
int pvcm_dispatch_one(struct pvcm_session *s, int timeout_ms);
int pvcm_run(struct pvcm_session *s, volatile bool *running);

#endif
