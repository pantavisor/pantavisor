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
#ifndef PV_XCONNECT_H
#define PV_XCONNECT_H

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>

// We use the same list implementation as pantavisor if available
#include "../../utils/list.h"

// Transport classification of a link endpoint.
// PVX_TRANSPORT_UNIX  - unix-domain socket (legacy default; provider_socket carries path)
// PVX_TRANSPORT_TCP   - IP/TCP service (provider_ip:provider_port carries endpoint)
typedef enum {
	PVX_TRANSPORT_UNIX = 0,
	PVX_TRANSPORT_TCP = 1,
} pvx_transport_t;

struct pvx_link {
	char *consumer;
	int consumer_pid;
	char *provider;
	int provider_pid;
	char *name;
	char *type;
	char *role;
	char *interface;
	char *provider_socket;
	char *consumer_socket; // Virtual socket path

	// Service / IP layer (added with services-IP feature).
	// cluster_ip is the stable virtual IP minted from the service name;
	// provider_ip/provider_port is the live backend (looked up via IPAM
	// when pv-ctrl builds the graph). Both sides use network-byte-order
	// uint32_t for IPv4. Zero means "not set".
	uint32_t cluster_ip;
	uint16_t cluster_port;
	uint32_t provider_ip;
	uint16_t provider_port;
	pvx_transport_t provider_transport;
	pvx_transport_t consumer_transport;

	// Last error message recorded by reconcile/plugins on a failed link
	// establishment. Heap-allocated, owned by pvx_link, NULL when healthy.
	// Surfaces via the status endpoint so pantavisor can gate container
	// health on link establishment.
	char *last_error;

	struct pvx_plugin *plugin;
	struct evconnlistener *listener;
	void *plugin_data;
	bool established; // Track if link setup completed
	bool data_plane_up; // Plugin's on_link_added succeeded; don't redo it
	struct dl_list list;
};

struct pvx_plugin {
	const char *type;
	int (*init)(void);
	int (*on_link_added)(struct pvx_link *link);
	int (*on_link_removed)(struct pvx_link *link);

	// Callback when a new client connects to the virtual socket
	void (*on_accept)(struct evconnlistener *listener, evutil_socket_t fd,
			  struct sockaddr *address, int socklen, void *arg);
};

// Core Helpers
struct event_base *pvx_get_base(void);
int pvx_helper_inject_unix_socket(const char *path, int pid);
int pvx_helper_inject_devnode(const char *target_path, int consumer_pid,
			      const char *source_path, int provider_pid);

// Inject (or remove) a single line in /etc/hosts inside the consumer's mount
// namespace. Returns 0 on success, -1 on any failure (read-only fs, missing
// /etc/hosts, EPERM, setns failure, etc). Callers MUST treat -1 as a hard
// link-establishment failure: a consumer with broken DNS for a wired service
// is not a working consumer, and the link must surface unhealthy so pantavisor
// can apply its standard rollback policy.
int pvx_helper_inject_hosts_entry(int consumer_pid, const char *hostname,
				  uint32_t ipv4_network_order);
int pvx_helper_remove_hosts_entry(int consumer_pid, const char *hostname);

// Service / ClusterIP helpers (services.c).
//
// Compute the stable virtual ClusterIP for a service name. Deterministic:
// FNV-1a over the name, mapped into 198.18.0.0/15 (RFC 2544 benchmark
// range, not routable, no userland conflicts — see services.c for why
// we avoid 169.254/16 and the RFC1918 / CGNAT ranges). Same name always
// yields the same IP across reboots, so no persistence is required.
// Returns the IP in network byte order, or 0 if name is NULL/empty.
uint32_t pvx_service_clusterip(const char *service_name);

// Compute the stable hostname for a service: "<name>.pv.local".
// Caller frees. Returns NULL on allocation failure or empty input.
char *pvx_service_hostname(const char *service_name);

#endif
