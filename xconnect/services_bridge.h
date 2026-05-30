/*
 * Copyright (c) 2026 Pantacor Ltd.
 * SPDX-License-Identifier: MIT
 */
#ifndef PVX_SERVICES_BRIDGE_H
#define PVX_SERVICES_BRIDGE_H

#include <stdint.h>

// Bring up (idempotent) / tear down the pv-services bridge.
int pvx_services_bridge_up(void);
void pvx_services_bridge_down(void);

// Add/remove a ClusterIP /32 on the bridge so Tier-2 userspace proxies can
// bind to it. cluster_ip_n is in network byte order. Idempotent.
int pvx_services_bridge_add_ip(uint32_t cluster_ip_n);
int pvx_services_bridge_del_ip(uint32_t cluster_ip_n);

#endif
