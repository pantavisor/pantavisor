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
// pvx tcp plugin — service ClusterIP proxy
// ----------------------------------------
//
// One listener per established service link, bound to ClusterIP:cluster_port
// on the host (the IP lives on the pv-services bridge). On accept, we open a
// connection to the backend — TCP if provider_transport == PVX_TRANSPORT_TCP,
// unix-socket via /proc/<provider_pid>/root<provider_socket> if UNIX — and
// bidirectionally pump bytes.
//
// Same proxy session shape as plugins/rest.c and plugins/unix.c; the only
// new thing here is the bind-to-ClusterIP and the choice of backend AF_*.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "../include/xconnect.h"
#include "../services_bridge.h"
#include "../services_nft.h"

#define MODULE_NAME "pvx-tcp"

struct tcp_proxy_session {
	struct bufferevent *be_client;
	struct bufferevent *be_provider;
	int client_eof;
	int provider_eof;
};

static void session_check_close(struct tcp_proxy_session *s)
{
	if (s->client_eof && s->provider_eof) {
		if (s->be_client)
			bufferevent_free(s->be_client);
		if (s->be_provider)
			bufferevent_free(s->be_provider);
		free(s);
	}
}

static void session_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct tcp_proxy_session *s = arg;
	if (events & BEV_EVENT_ERROR) {
		s->client_eof = s->provider_eof = 1;
		session_check_close(s);
		return;
	}
	if (events & BEV_EVENT_EOF) {
		if (bev == s->be_client)
			s->client_eof = 1;
		else
			s->provider_eof = 1;
		bufferevent_disable(bev, EV_READ);
		session_check_close(s);
	}
}

static void session_read_cb(struct bufferevent *bev, void *arg)
{
	struct tcp_proxy_session *s = arg;
	struct bufferevent *other =
		(bev == s->be_client) ? s->be_provider : s->be_client;
	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *dst = bufferevent_get_output(other);
	evbuffer_add_buffer(dst, src);
}

static int connect_backend_tcp(struct bufferevent *be, uint32_t ip_n, uint16_t port)
{
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip_n;
	sin.sin_port = htons(port);
	return bufferevent_socket_connect(be, (struct sockaddr *)&sin,
					  sizeof(sin));
}

static int connect_backend_unix(struct bufferevent *be, int provider_pid,
				const char *socket_path)
{
	if (!socket_path)
		return -1;
	char path[256];
	if (provider_pid > 0)
		snprintf(path, sizeof(path), "/proc/%d/root%s", provider_pid,
			 socket_path);
	else {
		strncpy(path, socket_path, sizeof(path) - 1);
		path[sizeof(path) - 1] = '\0';
	}
	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);
	return bufferevent_socket_connect(be, (struct sockaddr *)&sun,
					  sizeof(sun));
}

static void tcp_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
			  struct sockaddr *address, int socklen, void *arg)
{
	struct pvx_link *link = arg;
	struct event_base *base = pvx_get_base();

	fprintf(stderr,
		"%s: accept on %s for service %s (backend=%s)\n", MODULE_NAME,
		link->consumer ? link->consumer : "?",
		link->name ? link->name : "?",
		link->provider_transport == PVX_TRANSPORT_UNIX ?
			"unix" :
			"tcp");

	struct tcp_proxy_session *s = calloc(1, sizeof(*s));
	if (!s) {
		close(fd);
		return;
	}

	s->be_client = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	s->be_provider =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	int rc;
	if (link->provider_transport == PVX_TRANSPORT_UNIX)
		rc = connect_backend_unix(s->be_provider, link->provider_pid,
					  link->provider_socket);
	else
		rc = connect_backend_tcp(s->be_provider, link->provider_ip,
					 link->provider_port);

	if (rc < 0) {
		fprintf(stderr,
			"%s: backend connect failed for %s/%s\n", MODULE_NAME,
			link->consumer ? link->consumer : "?",
			link->name ? link->name : "?");
		bufferevent_free(s->be_client);
		bufferevent_free(s->be_provider);
		free(s);
		return;
	}

	bufferevent_setcb(s->be_client, session_read_cb, NULL,
			  session_event_cb, s);
	bufferevent_setcb(s->be_provider, session_read_cb, NULL,
			  session_event_cb, s);
	bufferevent_enable(s->be_client, EV_READ | EV_WRITE);
	bufferevent_enable(s->be_provider, EV_READ | EV_WRITE);
}

// True when this link can take the lightweight kernel-forward path: both
// sides are TCP and we have a backend ip:port to DNAT to. Embedded boxes
// shouldn't pay userspace-proxy cost for plain IP-to-IP traffic.
static bool tcp_can_kernel_forward(const struct pvx_link *link)
{
	return link->provider_transport == PVX_TRANSPORT_TCP &&
	       link->consumer_transport == PVX_TRANSPORT_TCP &&
	       link->provider_ip && link->provider_port;
}

static int tcp_on_link_added(struct pvx_link *link)
{
	if (!link->cluster_ip || !link->cluster_port) {
		fprintf(stderr,
			"%s: link %s missing cluster_ip/port — service-IP layer not provisioned by pv-ctrl?\n",
			MODULE_NAME, link->name ? link->name : "?");
		return -1;
	}

	if (pvx_services_bridge_add_ip(link->cluster_ip) != 0)
		return -1;

	// Fast path: kernel DNAT, no userspace listener. Conntrack tracks
	// the rewrite so the consumer experiences a clean ClusterIP-targeted
	// connection; bytes never leave kernel.
	if (tcp_can_kernel_forward(link)) {
		if (pvx_services_nft_add_dnat(link) != 0) {
			fprintf(stderr,
				"%s: nft DNAT install failed for %s/%s\n",
				MODULE_NAME,
				link->consumer ? link->consumer : "?",
				link->name ? link->name : "?");
			pvx_services_bridge_del_ip(link->cluster_ip);
			return -1;
		}
		char ip[INET_ADDRSTRLEN];
		struct in_addr a = { .s_addr = link->cluster_ip };
		inet_ntop(AF_INET, &a, ip, sizeof(ip));
		fprintf(stderr,
			"%s: kernel-forward %s:%u for service %s (consumer=%s)\n",
			MODULE_NAME, ip, link->cluster_port,
			link->name ? link->name : "?",
			link->consumer ? link->consumer : "?");
		return 0;
	}

	// Cross-transport path: userspace proxy bound on ClusterIP.
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("tcp: socket");
		return -1;
	}
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	evutil_make_socket_nonblocking(fd);

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = link->cluster_ip;
	sin.sin_port = htons(link->cluster_port);

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		fprintf(stderr,
			"%s: bind to ClusterIP:%u failed: %s\n", MODULE_NAME,
			link->cluster_port, strerror(errno));
		close(fd);
		return -1;
	}
	if (listen(fd, 16) < 0) {
		perror("tcp: listen");
		close(fd);
		return -1;
	}

	link->listener = evconnlistener_new(
		pvx_get_base(), tcp_on_accept, link,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, fd);
	if (!link->listener) {
		fprintf(stderr,
			"%s: evconnlistener_new failed for %s\n", MODULE_NAME,
			link->name ? link->name : "?");
		close(fd);
		return -1;
	}

	{
		char ip[INET_ADDRSTRLEN];
		struct in_addr a = { .s_addr = link->cluster_ip };
		inet_ntop(AF_INET, &a, ip, sizeof(ip));
		fprintf(stderr,
			"%s: listening on %s:%u for service %s (consumer=%s)\n",
			MODULE_NAME, ip, link->cluster_port,
			link->name ? link->name : "?",
			link->consumer ? link->consumer : "?");
	}
	return 0;
}

static int tcp_on_link_removed(struct pvx_link *link)
{
	if (link->listener) {
		evconnlistener_free(link->listener);
		link->listener = NULL;
	}
	if (link->cluster_ip)
		pvx_services_bridge_del_ip(link->cluster_ip);
	return 0;
}

struct pvx_plugin pvx_plugin_tcp = { .type = "tcp",
				     .on_link_added = tcp_on_link_added,
				     .on_link_removed = tcp_on_link_removed,
				     .on_accept = tcp_on_accept };
