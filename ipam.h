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

#ifndef PV_IPAM_H
#define PV_IPAM_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "utils/list.h"

// Pool types
typedef enum { POOL_TYPE_BRIDGE, POOL_TYPE_MACVLAN } pv_pool_type_t;

// IP lease - tracks allocated IPs
struct pv_ip_lease {
	char *container_name;
	uint32_t ip; // Network byte order
	bool in_use;
	struct dl_list list; // pv_ip_lease
};

// IP pool - defines a network pool from device.json
struct pv_ip_pool {
	char *name; // Pool name (e.g., "internal")
	pv_pool_type_t type; // bridge or macvlan
	char *bridge; // Bridge interface name (for type=bridge)
	char *parent; // Parent interface (for type=macvlan)
	uint32_t subnet; // Subnet address (network byte order)
	uint32_t mask; // Subnet mask (network byte order)
	uint32_t gateway; // Gateway IP (network byte order)
	bool nat; // Enable NAT
	bool bridge_created; // Bridge already created
	uint32_t next_ip; // Next IP to allocate (host byte order)
	struct dl_list leases; // pv_ip_lease
	struct dl_list list; // pv_ip_pool
};

// Platform network mode
typedef enum {
	NET_MODE_NONE, // No network config (use static lxc.container.conf)
	NET_MODE_HOST, // Host namespace
	NET_MODE_POOL // Pool-based dynamic
} pv_net_mode_t;

// Platform network interface config
struct pv_platform_network_iface {
	char *name; // Container-side interface (e.g., "eth0")
	char *pool; // Pool name from device.json
	char *ipv4_address; // Assigned IP in CIDR notation
	char *ipv4_gateway; // Gateway IP
	char *bridge; // Host bridge name
	char *veth_host; // Host-side veth name
	char *mac_address; // MAC address
	char *static_ip; // Static IP override from run.json (optional)
	char *static_mac; // Static MAC override from run.json (optional)
	struct dl_list list; // pv_platform_network_iface
};

// Platform network config (from run.json)
struct pv_platform_network {
	pv_net_mode_t mode;
	char *hostname;
	struct dl_list interfaces; // pv_platform_network_iface
};

// Global IPAM state
struct pv_ipam {
	struct dl_list pools; // pv_ip_pool
	bool initialized;
};

// Initialize IPAM subsystem
int pv_ipam_init(void);

// Cleanup IPAM subsystem
void pv_ipam_free(void);

// Get global IPAM instance
struct pv_ipam *pv_ipam_get(void);

// Add a pool from device.json
struct pv_ip_pool *pv_ipam_add_pool(const char *name, pv_pool_type_t type,
				    const char *bridge_or_parent,
				    const char *subnet_cidr,
				    const char *gateway, bool nat);

// Find a pool by name
struct pv_ip_pool *pv_ipam_find_pool(const char *name);

// Allocate an IP from a pool for a container
// Returns allocated IP in CIDR notation (e.g., "10.0.3.2/24") or NULL on failure
char *pv_ipam_allocate(const char *pool_name, const char *container_name);

// Reserve a specific IP in a pool (for static configs)
// Returns 0 on success, -1 if IP already taken or not in pool
int pv_ipam_reserve(const char *pool_name, const char *container_name,
		    const char *ip_cidr);

// Release an IP back to the pool
void pv_ipam_release(const char *pool_name, const char *container_name);

// Get the lease for a container in a pool
struct pv_ip_lease *pv_ipam_get_lease(const char *pool_name,
				      const char *container_name);

// Setup bridges for all pools (called during init)
int pv_ipam_setup_bridges(void);

// Generate deterministic MAC address from container name
// Returns MAC in format "02:pv:XX:XX:XX:XX"
char *pv_ipam_generate_mac(uint32_t ip);

// Parse CIDR notation (e.g., "10.0.3.0/24") into subnet and mask
int pv_ipam_parse_cidr(const char *cidr, uint32_t *subnet, uint32_t *mask);

// Format IP address to string
char *pv_ipam_ip_to_str(uint32_t ip);

// Check if IP is in subnet
bool pv_ipam_ip_in_subnet(uint32_t ip, uint32_t subnet, uint32_t mask);

// Create platform network config
struct pv_platform_network *pv_platform_network_new(pv_net_mode_t mode);

// Free platform network config
void pv_platform_network_free(struct pv_platform_network *net);

// Add interface to platform network
struct pv_platform_network_iface *
pv_platform_network_add_iface(struct pv_platform_network *net, const char *name,
			      const char *pool);

#endif // PV_IPAM_H
