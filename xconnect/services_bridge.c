/*
 * Copyright (c) 2026 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
//
// pv-services bridge
// ------------------
//
// Owns the pv-services bridge interface that Tier-2 (userspace proxy)
// services bind their ClusterIPs onto. Tier-1 (DNAT) services don't strictly
// need the bridge — kernel PREROUTING DNAT happens before the routing
// decision — but we always bring it up so:
//   (a) ClusterIP /32s have a stable home for Tier-2 listeners,
//   (b) the IPAM mental model (bridge per pool) carries over to services,
//   (c) v2 'services' pools in device.json can attach real interfaces here.
//
// We deliberately keep this implementation tiny and shell-driven: bridge
// management on Yocto BSPs is reliably done via `ip` from iproute2 (already
// pulled in by IPAM). Mirroring IPAM's `system()`-based NAT setup keeps the
// surface consistent and avoids dragging in libnl just for one bridge.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "include/xconnect.h"
#include "services_bridge.h"
#include "../utils/sysctl.h"

#define PVX_BRIDGE_NAME "pv-services"

static int run(const char *cmd)
{
	int rc = system(cmd);
	if (rc != 0)
		fprintf(stderr,
			"pvx-bridge: command failed (rc=%d): %s\n", rc, cmd);
	return rc;
}

// Idempotent: safe to call repeatedly. Returns 0 on success.
int pvx_services_bridge_up(void)
{
	char cmd[256];

	// Create bridge if it doesn't exist. `ip link add` returns nonzero
	// when the iface already exists, which is fine — we follow with
	// `set ... up` so the steady state is the same.
	snprintf(cmd, sizeof(cmd),
		 "ip link add name %s type bridge 2>/dev/null; "
		 "ip link set %s up 2>/dev/null",
		 PVX_BRIDGE_NAME, PVX_BRIDGE_NAME);
	run(cmd);

	// Sanity: confirm the bridge is now up. If not, surface as error.
	snprintf(cmd, sizeof(cmd),
		 "ip link show %s up >/dev/null 2>&1", PVX_BRIDGE_NAME);
	if (system(cmd) != 0) {
		fprintf(stderr,
			"pvx-bridge: %s did not come up\n", PVX_BRIDGE_NAME);
		return -1;
	}

	// Kernel forward path (TCP→TCP DNAT) needs ip_forward. IPAM enables
	// it conditionally on NAT-pool presence; we enable unconditionally
	// here since service-IP forwarding is always on.
	if (pv_sysctl_write("/proc/sys/net/ipv4/ip_forward", "1\n") != 0)
		fprintf(stderr,
			"pvx-bridge: could not enable ip_forward (errno=%d %s)\n",
			errno, strerror(errno));

	fprintf(stderr, "pvx-bridge: %s is up\n", PVX_BRIDGE_NAME);
	return 0;
}

void pvx_services_bridge_down(void)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd),
		 "ip link set %s down 2>/dev/null; "
		 "ip link delete %s 2>/dev/null",
		 PVX_BRIDGE_NAME, PVX_BRIDGE_NAME);
	run(cmd);
}

static void ip_to_str(uint32_t ip_n, char *out, size_t outlen)
{
	struct in_addr a = { .s_addr = ip_n };
	const char *p = inet_ntoa(a);
	strncpy(out, p ? p : "0.0.0.0", outlen - 1);
	out[outlen - 1] = '\0';
}

int pvx_services_bridge_add_ip(uint32_t cluster_ip_n)
{
	if (!cluster_ip_n)
		return -1;
	char ip[INET_ADDRSTRLEN];
	ip_to_str(cluster_ip_n, ip, sizeof(ip));

	// /32 host route. Already-assigned is fine (treated as success).
	char cmd[256];
	snprintf(cmd, sizeof(cmd),
		 "ip addr add %s/32 dev %s 2>/dev/null; "
		 "ip addr show dev %s | grep -q ' %s/32'",
		 ip, PVX_BRIDGE_NAME, PVX_BRIDGE_NAME, ip);
	int rc = system(cmd);
	if (rc != 0) {
		fprintf(stderr,
			"pvx-bridge: failed to ensure %s/32 on %s\n", ip,
			PVX_BRIDGE_NAME);
		return -1;
	}
	return 0;
}

int pvx_services_bridge_del_ip(uint32_t cluster_ip_n)
{
	if (!cluster_ip_n)
		return -1;
	char ip[INET_ADDRSTRLEN];
	ip_to_str(cluster_ip_n, ip, sizeof(ip));

	char cmd[256];
	snprintf(cmd, sizeof(cmd),
		 "ip addr del %s/32 dev %s 2>/dev/null", ip, PVX_BRIDGE_NAME);
	system(cmd);
	return 0;
}
