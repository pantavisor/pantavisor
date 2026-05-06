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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "include/xconnect.h"

// FNV-1a 32-bit. Not cryptographic; just a stable, well-distributed hash so
// deterministic ClusterIP derivation survives reboots without on-disk state.
static uint32_t fnv1a(const char *s)
{
	uint32_t h = 0x811c9dc5u;
	for (; *s; s++) {
		h ^= (unsigned char)*s;
		h *= 0x01000193u;
	}
	return h;
}

// ClusterIP range default: 198.18.0.0/15 (RFC 2544 benchmark range).
//
// Why not 169.254.0.0/16? avahi-daemon, NetworkManager IPv4LL, and other
// zeroconf machinery actively use it; on a host with avahi we'd see ARP
// fights, mDNS leakage, and IPv4LL probes claiming the same addresses.
//
// Why not 10.0.0.0/8 / 172.16/12 / 192.168/16? Conflicts with site networks
// and with IPAM pool defaults already used by pantavisor deployments.
//
// Why not 100.64.0.0/10? It's CGNAT, but more importantly Tailscale uses it
// for its mesh; pantavisor devices commonly run Tailscale (lab nodes have
// 100.x.y.z addresses).
//
// 198.18.0.0/15 is RFC 2544 reserved for inter-network benchmarking, not
// routable on the public internet, and not consumed by any common userland
// service. 131k addresses are plenty for service name hashing.
//
// Override path: pantavisor.config key `xconnect.services.cidr` (see
// PV_XCONNECT_SERVICES_CIDR in the pantavisor config schema). Pantavisor
// exports this into the daemon environment as PV_XCONNECT_SERVICES_CIDR
// before spawning pv-xconnect. v2 will move the authoritative knob into
// device.json `services` block when explicit service pools land.
#define PVX_DEFAULT_CIDR "198.18.0.0/15"

// Resolved at first use. host-byte-order subnet+host-mask. host_mask = ~netmask
// so we can & it with hash bits to derive the host portion in one shot.
static uint32_t g_subnet_host = 0; // network address, host byte order
static uint32_t g_host_mask_host = 0; // 1-bits = host portion
static int g_resolved = 0;

// Parse "A.B.C.D/N" into host-order net + host_mask. Returns 0 on success.
static int parse_cidr(const char *s, uint32_t *net_out, uint32_t *host_mask_out)
{
	if (!s || !s[0])
		return -1;

	char buf[64];
	strncpy(buf, s, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	char *slash = strchr(buf, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	int prefix = atoi(slash + 1);
	if (prefix < 0 || prefix > 32)
		return -1;

	struct in_addr a;
	if (inet_aton(buf, &a) == 0)
		return -1;

	uint32_t net_host = ntohl(a.s_addr);
	uint32_t netmask = (prefix == 0) ? 0u : (~0u << (32 - prefix));
	*net_out = net_host & netmask;
	*host_mask_out = ~netmask;
	return 0;
}

static void resolve_range(void)
{
	if (g_resolved)
		return;

	const char *env = getenv("PV_XCONNECT_SERVICES_CIDR");
	if (env && env[0]) {
		if (parse_cidr(env, &g_subnet_host, &g_host_mask_host) == 0) {
			fprintf(stderr,
				"pvx-services: ClusterIP range from env: %s\n",
				env);
			g_resolved = 1;
			return;
		}
		fprintf(stderr,
			"pvx-services: invalid PV_XCONNECT_SERVICES_CIDR=%s, falling back to default %s\n",
			env, PVX_DEFAULT_CIDR);
	}

	if (parse_cidr(PVX_DEFAULT_CIDR, &g_subnet_host, &g_host_mask_host) !=
	    0) {
		// Should be unreachable - default is a constant.
		fprintf(stderr, "pvx-services: built-in default CIDR is broken\n");
		g_subnet_host = 0;
		g_host_mask_host = 0xfffffffeu;
	}
	g_resolved = 1;
}

uint32_t pvx_service_clusterip(const char *service_name)
{
	if (!service_name || !service_name[0])
		return 0;

	resolve_range();

	uint32_t h = fnv1a(service_name);
	uint32_t host_part = h & g_host_mask_host;

	// Avoid the all-zeros (network) and all-ones (broadcast) host parts
	// inside the configured range. Everything in between is fair game.
	if (host_part == 0)
		host_part = 1;
	if (host_part == g_host_mask_host)
		host_part = g_host_mask_host - 1;

	uint32_t ip_host = g_subnet_host | host_part;
	return htonl(ip_host);
}

char *pvx_service_hostname(const char *service_name)
{
	if (!service_name || !service_name[0])
		return NULL;

	size_t n = strlen(service_name) + sizeof(".pv.local");
	char *out = malloc(n);
	if (!out)
		return NULL;
	snprintf(out, n, "%s.pv.local", service_name);
	return out;
}
