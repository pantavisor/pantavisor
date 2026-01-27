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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/sockios.h>

#include "ipam.h"
#include "config.h"
#include "utils/str.h"

#define MODULE_NAME "ipam"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

// Global IPAM state
static struct pv_ipam ipam_state = { .initialized = false };

int pv_ipam_init(void)
{
	if (ipam_state.initialized)
		return 0;

	dl_list_init(&ipam_state.pools);
	ipam_state.initialized = true;

	pv_log(INFO, "IPAM subsystem initialized");
	return 0;
}

void pv_ipam_free(void)
{
	struct pv_ip_pool *pool, *pool_tmp;
	struct pv_ip_lease *lease, *lease_tmp;

	dl_list_for_each_safe(pool, pool_tmp, &ipam_state.pools,
			      struct pv_ip_pool, list)
	{
		dl_list_for_each_safe(lease, lease_tmp, &pool->leases,
				      struct pv_ip_lease, list)
		{
			dl_list_del(&lease->list);
			if (lease->container_name)
				free(lease->container_name);
			free(lease);
		}
		dl_list_del(&pool->list);
		if (pool->name)
			free(pool->name);
		if (pool->bridge)
			free(pool->bridge);
		if (pool->parent)
			free(pool->parent);
		free(pool);
	}

	ipam_state.initialized = false;
	pv_log(INFO, "IPAM subsystem freed");
}

struct pv_ipam *pv_ipam_get(void)
{
	return &ipam_state;
}

int pv_ipam_parse_cidr(const char *cidr, uint32_t *subnet, uint32_t *mask)
{
	char *cidr_copy, *slash;
	int prefix_len;
	struct in_addr addr;

	if (!cidr || !subnet || !mask)
		return -1;

	cidr_copy = strdup(cidr);
	if (!cidr_copy)
		return -1;

	slash = strchr(cidr_copy, '/');
	if (!slash) {
		free(cidr_copy);
		return -1;
	}

	*slash = '\0';
	prefix_len = atoi(slash + 1);

	if (prefix_len < 0 || prefix_len > 32) {
		free(cidr_copy);
		return -1;
	}

	if (inet_pton(AF_INET, cidr_copy, &addr) != 1) {
		free(cidr_copy);
		return -1;
	}

	*subnet = addr.s_addr;

	if (prefix_len == 0)
		*mask = 0;
	else
		*mask = htonl(~((1 << (32 - prefix_len)) - 1));

	free(cidr_copy);
	return 0;
}

char *pv_ipam_ip_to_str(uint32_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	return strdup(inet_ntoa(addr));
}

bool pv_ipam_ip_in_subnet(uint32_t ip, uint32_t subnet, uint32_t mask)
{
	return (ip & mask) == (subnet & mask);
}

struct pv_ip_pool *pv_ipam_add_pool(const char *name, pv_pool_type_t type,
				    const char *bridge_or_parent,
				    const char *subnet_cidr,
				    const char *gateway, bool nat)
{
	struct pv_ip_pool *pool;
	uint32_t subnet, mask;
	struct in_addr gw_addr;

	if (!name || !bridge_or_parent || !subnet_cidr || !gateway) {
		pv_log(ERROR, "invalid pool parameters");
		return NULL;
	}

	if (pv_ipam_parse_cidr(subnet_cidr, &subnet, &mask) < 0) {
		pv_log(ERROR, "invalid subnet CIDR: %s", subnet_cidr);
		return NULL;
	}

	if (inet_pton(AF_INET, gateway, &gw_addr) != 1) {
		pv_log(ERROR, "invalid gateway IP: %s", gateway);
		return NULL;
	}

	// Check if pool already exists
	if (pv_ipam_find_pool(name)) {
		pv_log(WARN, "pool '%s' already exists", name);
		return NULL;
	}

	pool = calloc(1, sizeof(struct pv_ip_pool));
	if (!pool)
		return NULL;

	pool->name = strdup(name);
	pool->type = type;
	pool->subnet = subnet;
	pool->mask = mask;
	pool->gateway = gw_addr.s_addr;
	pool->nat = nat;
	pool->bridge_created = false;

	if (type == POOL_TYPE_BRIDGE)
		pool->bridge = strdup(bridge_or_parent);
	else
		pool->parent = strdup(bridge_or_parent);

	// Start allocating from gateway + 1
	pool->next_ip = ntohl(gw_addr.s_addr) + 1;

	dl_list_init(&pool->leases);
	dl_list_init(&pool->list);
	dl_list_add_tail(&ipam_state.pools, &pool->list);

	pv_log(INFO, "added pool '%s': type=%s, subnet=%s, gateway=%s, nat=%s",
	       name, type == POOL_TYPE_BRIDGE ? "bridge" : "macvlan",
	       subnet_cidr, gateway, nat ? "yes" : "no");

	return pool;
}

struct pv_ip_pool *pv_ipam_find_pool(const char *name)
{
	struct pv_ip_pool *pool;

	if (!name)
		return NULL;

	dl_list_for_each(pool, &ipam_state.pools, struct pv_ip_pool, list)
	{
		if (strcmp(pool->name, name) == 0)
			return pool;
	}

	return NULL;
}

static bool is_ip_available(struct pv_ip_pool *pool, uint32_t ip)
{
	struct pv_ip_lease *lease;

	// Check if IP is the gateway
	if (ip == pool->gateway)
		return false;

	// Check if IP is in existing leases
	dl_list_for_each(lease, &pool->leases, struct pv_ip_lease, list)
	{
		if (lease->ip == ip)
			return false;
	}

	return true;
}

char *pv_ipam_allocate(const char *pool_name, const char *container_name)
{
	struct pv_ip_pool *pool;
	struct pv_ip_lease *lease, *existing;
	uint32_t ip, ip_net;
	uint32_t broadcast, max_ip;
	char *result;
	int prefix_len;
	uint32_t mask_host;

	pool = pv_ipam_find_pool(pool_name);
	if (!pool) {
		pv_log(ERROR, "pool '%s' not found", pool_name);
		return NULL;
	}

	// Check if container already has a lease
	existing = pv_ipam_get_lease(pool_name, container_name);
	if (existing) {
		// Reuse existing lease
		char *ip_str = pv_ipam_ip_to_str(existing->ip);
		mask_host = ntohl(pool->mask);
		prefix_len = __builtin_popcount(mask_host);
		result = malloc(strlen(ip_str) + 4);
		sprintf(result, "%s/%d", ip_str, prefix_len);
		free(ip_str);
		pv_log(DEBUG, "reusing existing lease for %s: %s",
		       container_name, result);
		return result;
	}

	// Calculate broadcast address
	broadcast = pool->subnet | ~pool->mask;
	max_ip = ntohl(broadcast) - 1; // Last usable IP

	// Find next available IP
	ip = pool->next_ip;
	while (ip <= max_ip) {
		ip_net = htonl(ip);
		if (is_ip_available(pool, ip_net)) {
			// Found available IP
			lease = calloc(1, sizeof(struct pv_ip_lease));
			if (!lease)
				return NULL;

			lease->container_name = strdup(container_name);
			lease->ip = ip_net;
			lease->in_use = true;
			dl_list_init(&lease->list);
			dl_list_add_tail(&pool->leases, &lease->list);

			// Update next_ip cursor
			pool->next_ip = ip + 1;

			// Format result as CIDR
			char *ip_str = pv_ipam_ip_to_str(ip_net);
			mask_host = ntohl(pool->mask);
			prefix_len = __builtin_popcount(mask_host);
			result = malloc(strlen(ip_str) + 4);
			sprintf(result, "%s/%d", ip_str, prefix_len);
			free(ip_str);

			pv_log(INFO, "allocated %s to %s from pool %s", result,
			       container_name, pool_name);
			return result;
		}
		ip++;
	}

	pv_log(ERROR, "no available IPs in pool '%s'", pool_name);
	return NULL;
}

int pv_ipam_reserve(const char *pool_name, const char *container_name,
		    const char *ip_cidr)
{
	struct pv_ip_pool *pool;
	struct pv_ip_lease *lease;
	uint32_t ip, mask;
	struct in_addr addr;
	char *ip_only, *slash;

	pool = pv_ipam_find_pool(pool_name);
	if (!pool) {
		pv_log(ERROR, "pool '%s' not found", pool_name);
		return -1;
	}

	// Parse IP from CIDR
	ip_only = strdup(ip_cidr);
	slash = strchr(ip_only, '/');
	if (slash)
		*slash = '\0';

	if (inet_pton(AF_INET, ip_only, &addr) != 1) {
		pv_log(ERROR, "invalid IP: %s", ip_only);
		free(ip_only);
		return -1;
	}
	ip = addr.s_addr;
	free(ip_only);

	// Check if IP is in pool subnet
	if (!pv_ipam_ip_in_subnet(ip, pool->subnet, pool->mask)) {
		pv_log(ERROR, "IP %s not in pool '%s' subnet", ip_cidr,
		       pool_name);
		return -1;
	}

	// Check if IP is available
	if (!is_ip_available(pool, ip)) {
		pv_log(ERROR, "IP %s already in use in pool '%s'", ip_cidr,
		       pool_name);
		return -1;
	}

	// Create lease
	lease = calloc(1, sizeof(struct pv_ip_lease));
	if (!lease)
		return -1;

	lease->container_name = strdup(container_name);
	lease->ip = ip;
	lease->in_use = true;
	dl_list_init(&lease->list);
	dl_list_add_tail(&pool->leases, &lease->list);

	pv_log(INFO, "reserved %s for %s in pool %s", ip_cidr, container_name,
	       pool_name);
	return 0;
}

void pv_ipam_release(const char *pool_name, const char *container_name)
{
	struct pv_ip_pool *pool;
	struct pv_ip_lease *lease, *tmp;

	pool = pv_ipam_find_pool(pool_name);
	if (!pool)
		return;

	dl_list_for_each_safe(lease, tmp, &pool->leases, struct pv_ip_lease,
			      list)
	{
		if (strcmp(lease->container_name, container_name) == 0) {
			char *ip_str = pv_ipam_ip_to_str(lease->ip);
			pv_log(INFO, "released %s from %s in pool %s", ip_str,
			       container_name, pool_name);
			free(ip_str);

			dl_list_del(&lease->list);
			free(lease->container_name);
			free(lease);
			return;
		}
	}
}

struct pv_ip_lease *pv_ipam_get_lease(const char *pool_name,
				      const char *container_name)
{
	struct pv_ip_pool *pool;
	struct pv_ip_lease *lease;

	pool = pv_ipam_find_pool(pool_name);
	if (!pool)
		return NULL;

	dl_list_for_each(lease, &pool->leases, struct pv_ip_lease, list)
	{
		if (strcmp(lease->container_name, container_name) == 0)
			return lease;
	}

	return NULL;
}

char *pv_ipam_generate_mac(uint32_t ip_net)
{
	char *mac;
	uint32_t ip;

	if (!ip_net)
		return NULL;

	// Convert from network byte order to host byte order
	ip = ntohl(ip_net);

	// Format: 02:00:XX:XX:XX:XX where XX:XX:XX:XX is the IP address octets
	// 02 = locally administered, unicast
	// Using IP ensures uniqueness within pool (IPs are unique)
	// Example: IP 10.0.5.2 → MAC 02:00:0a:00:05:02
	mac = malloc(18);
	if (!mac)
		return NULL;

	snprintf(mac, 18, "02:00:%02x:%02x:%02x:%02x", (ip >> 24) & 0xff,
		 (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);

	return mac;
}

static int setup_bridge(struct pv_ip_pool *pool)
{
	int fd, sockfd, ret = 0;
	struct ifreq ifr;
	struct sockaddr_in sai;
	char *gateway_str;
	uint32_t mask_host;
	int prefix_len;

	if (!pool || pool->type != POOL_TYPE_BRIDGE || !pool->bridge)
		return -1;

	if (pool->bridge_created)
		return 0;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(ERROR, "unable to create socket: %s", strerror(errno));
		return -1;
	}

	// Create bridge
	ret = ioctl(fd, SIOCBRADDBR, pool->bridge);
	if (ret < 0 && errno != EEXIST) {
		pv_log(ERROR, "unable to create bridge %s: %s", pool->bridge,
		       strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	// Configure bridge IP
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		pv_log(ERROR, "unable to create dgram socket: %s",
		       strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pool->bridge, IFNAMSIZ - 1);

	// Set IP address
	memset(&sai, 0, sizeof(sai));
	sai.sin_family = AF_INET;
	sai.sin_addr.s_addr = pool->gateway;
	memcpy(&ifr.ifr_addr, &sai, sizeof(sai));

	ret = ioctl(sockfd, SIOCSIFADDR, &ifr);
	if (ret < 0) {
		gateway_str = pv_ipam_ip_to_str(pool->gateway);
		pv_log(ERROR, "unable to set IP %s on %s: %s", gateway_str,
		       pool->bridge, strerror(errno));
		free(gateway_str);
		close(sockfd);
		return -1;
	}

	// Set netmask
	memset(&sai, 0, sizeof(sai));
	sai.sin_family = AF_INET;
	sai.sin_addr.s_addr = pool->mask;
	memcpy(&ifr.ifr_addr, &sai, sizeof(sai));

	ret = ioctl(sockfd, SIOCSIFNETMASK, &ifr);
	if (ret < 0) {
		pv_log(ERROR, "unable to set netmask on %s: %s", pool->bridge,
		       strerror(errno));
		close(sockfd);
		return -1;
	}

	// Bring interface up
	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		pv_log(ERROR, "unable to get flags for %s: %s", pool->bridge,
		       strerror(errno));
		close(sockfd);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		pv_log(ERROR, "unable to bring up %s: %s", pool->bridge,
		       strerror(errno));
		close(sockfd);
		return -1;
	}

	close(sockfd);

	pool->bridge_created = true;

	gateway_str = pv_ipam_ip_to_str(pool->gateway);
	mask_host = ntohl(pool->mask);
	prefix_len = __builtin_popcount(mask_host);
	pv_log(INFO, "created bridge %s with IP %s/%d", pool->bridge,
	       gateway_str, prefix_len);
	free(gateway_str);

	return 0;
}

static int setup_nat(struct pv_ip_pool *pool)
{
	char cmd[512];
	char *subnet_str;
	uint32_t mask_host;
	int prefix_len;
	int ret;

	if (!pool || !pool->nat)
		return 0;

	subnet_str = pv_ipam_ip_to_str(pool->subnet);
	mask_host = ntohl(pool->mask);
	prefix_len = __builtin_popcount(mask_host);

	// Enable IP forwarding
	ret = system("echo 1 > /proc/sys/net/ipv4/ip_forward");
	if (ret != 0) {
		pv_log(WARN, "failed to enable IP forwarding");
	}

	// Try iptables first, fall back to nftables
	snprintf(
		cmd, sizeof(cmd),
		"iptables -t nat -C POSTROUTING -s %s/%d ! -o %s -j MASQUERADE 2>/dev/null || "
		"iptables -t nat -A POSTROUTING -s %s/%d ! -o %s -j MASQUERADE 2>/dev/null",
		subnet_str, prefix_len, pool->bridge, subnet_str, prefix_len,
		pool->bridge);

	ret = system(cmd);
	if (ret != 0) {
		// Try nftables
		snprintf(
			cmd, sizeof(cmd),
			"nft add table nat 2>/dev/null; "
			"nft add chain nat postrouting { type nat hook postrouting priority 100 \\; } 2>/dev/null; "
			"nft add rule nat postrouting ip saddr %s/%d oifname != \"%s\" masquerade 2>/dev/null",
			subnet_str, prefix_len, pool->bridge);
		ret = system(cmd);
		if (ret != 0) {
			pv_log(WARN, "failed to setup NAT for pool %s",
			       pool->name);
		} else {
			pv_log(INFO, "setup NAT (nftables) for pool %s",
			       pool->name);
		}
	} else {
		pv_log(INFO, "setup NAT (iptables) for pool %s", pool->name);
	}

	free(subnet_str);
	return 0;
}

int pv_ipam_setup_bridges(void)
{
	struct pv_ip_pool *pool;
	int ret = 0;

	dl_list_for_each(pool, &ipam_state.pools, struct pv_ip_pool, list)
	{
		if (pool->type == POOL_TYPE_BRIDGE) {
			if (setup_bridge(pool) < 0)
				ret = -1;
			if (pool->nat)
				setup_nat(pool);
		}
	}

	return ret;
}

struct pv_platform_network *pv_platform_network_new(pv_net_mode_t mode)
{
	struct pv_platform_network *net;

	net = calloc(1, sizeof(struct pv_platform_network));
	if (!net)
		return NULL;

	net->mode = mode;
	dl_list_init(&net->interfaces);

	return net;
}

void pv_platform_network_free(struct pv_platform_network *net)
{
	struct pv_platform_network_iface *iface, *tmp;

	if (!net)
		return;

	dl_list_for_each_safe(iface, tmp, &net->interfaces,
			      struct pv_platform_network_iface, list)
	{
		dl_list_del(&iface->list);
		if (iface->name)
			free(iface->name);
		if (iface->pool)
			free(iface->pool);
		if (iface->ipv4_address)
			free(iface->ipv4_address);
		if (iface->ipv4_gateway)
			free(iface->ipv4_gateway);
		if (iface->bridge)
			free(iface->bridge);
		if (iface->veth_host)
			free(iface->veth_host);
		if (iface->mac_address)
			free(iface->mac_address);
		if (iface->static_ip)
			free(iface->static_ip);
		if (iface->static_mac)
			free(iface->static_mac);
		free(iface);
	}

	if (net->hostname)
		free(net->hostname);
	free(net);
}

struct pv_platform_network_iface *
pv_platform_network_add_iface(struct pv_platform_network *net, const char *name,
			      const char *pool)
{
	struct pv_platform_network_iface *iface;

	if (!net || !name || !pool)
		return NULL;

	iface = calloc(1, sizeof(struct pv_platform_network_iface));
	if (!iface)
		return NULL;

	iface->name = strdup(name);
	iface->pool = strdup(pool);
	dl_list_init(&iface->list);
	dl_list_add_tail(&net->interfaces, &iface->list);

	return iface;
}
