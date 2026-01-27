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
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/xconnect.h"

#define MODULE_NAME "pvx-tcp"

struct tcp_proxy_session {
	struct bufferevent *be_client;
	struct bufferevent *be_provider;
	struct pvx_link *link;
	int client_eof;
	int provider_eof;
};

static void proxy_check_close(struct tcp_proxy_session *session)
{
	if (session->client_eof && session->provider_eof) {
		if (session->be_client)
			bufferevent_free(session->be_client);
		if (session->be_provider)
			bufferevent_free(session->be_provider);
		free(session);
	}
}

static void proxy_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct tcp_proxy_session *session = arg;

	if (events & BEV_EVENT_ERROR) {
		session->client_eof = 1;
		session->provider_eof = 1;
		proxy_check_close(session);
		return;
	}

	if (events & BEV_EVENT_EOF) {
		if (bev == session->be_client) {
			session->client_eof = 1;
			bufferevent_disable(bev, EV_READ);
		} else {
			session->provider_eof = 1;
			bufferevent_disable(bev, EV_READ);
		}
		proxy_check_close(session);
	}
}

static void tcp_read_cb(struct bufferevent *bev, void *arg)
{
	struct tcp_proxy_session *session = arg;
	struct bufferevent *other = (bev == session->be_client) ?
					    session->be_provider :
					    session->be_client;
	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *dst = bufferevent_get_output(other);
	evbuffer_add_buffer(dst, src);
}

// Check if address is TCP format (IP:port) vs Unix socket path
static int is_tcp_address(const char *addr)
{
	if (!addr || addr[0] == '/')
		return 0;
	// TCP address contains colon and no leading slash
	return strchr(addr, ':') != NULL;
}

// Connect to TCP backend (IP:port format)
static int tcp_connect_backend_tcp(struct tcp_proxy_session *session,
				   const char *addr_str)
{
	char host[256];
	int port;

	// Parse "IP:port" format
	const char *colon = strchr(addr_str, ':');
	if (!colon)
		return -1;

	size_t host_len = colon - addr_str;
	if (host_len >= sizeof(host))
		return -1;

	strncpy(host, addr_str, host_len);
	host[host_len] = '\0';
	port = atoi(colon + 1);

	if (port <= 0 || port > 65535)
		return -1;

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	if (inet_pton(AF_INET, host, &sin.sin_addr) <= 0)
		return -1;

	printf("%s: Connecting to TCP backend %s:%d\n", MODULE_NAME, host,
	       port);

	return bufferevent_socket_connect(session->be_provider,
					  (struct sockaddr *)&sin, sizeof(sin));
}

// Connect to Unix socket backend
static int tcp_connect_backend_unix(struct tcp_proxy_session *session,
				    struct pvx_link *link)
{
	char provider_path[256];

	// Build provider socket path
	if (link->provider_pid > 0) {
		snprintf(provider_path, sizeof(provider_path),
			 "/proc/%d/root%s", link->provider_pid,
			 link->provider_socket);
	} else {
		strncpy(provider_path, link->provider_socket,
			sizeof(provider_path) - 1);
		provider_path[sizeof(provider_path) - 1] = '\0';
	}

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

	printf("%s: Connecting to Unix backend %s\n", MODULE_NAME,
	       provider_path);

	return bufferevent_socket_connect(session->be_provider,
					  (struct sockaddr *)&sun, sizeof(sun));
}

static void tcp_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
			  struct sockaddr *address, int socklen, void *arg)
{
	struct pvx_link *link = arg;
	struct event_base *base = pvx_get_base();
	int connect_result;

	if (!link->name || !link->provider_socket) {
		printf("%s: Missing link name or provider_socket\n",
		       MODULE_NAME);
		close(fd);
		return;
	}

	struct tcp_proxy_session *session = calloc(1, sizeof(*session));
	if (!session) {
		close(fd);
		return;
	}

	session->link = link;
	session->be_client =
		bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	session->be_provider =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	// Determine backend type and connect
	if (is_tcp_address(link->provider_socket)) {
		connect_result =
			tcp_connect_backend_tcp(session, link->provider_socket);
	} else {
		connect_result = tcp_connect_backend_unix(session, link);
	}

	if (connect_result < 0) {
		printf("%s: Failed to connect to backend %s\n", MODULE_NAME,
		       link->provider_socket);
		bufferevent_free(session->be_client);
		bufferevent_free(session->be_provider);
		free(session);
		return;
	}

	bufferevent_setcb(session->be_client, tcp_read_cb, NULL, proxy_event_cb,
			  session);
	bufferevent_setcb(session->be_provider, tcp_read_cb, NULL,
			  proxy_event_cb, session);

	bufferevent_enable(session->be_client, EV_READ | EV_WRITE);
	bufferevent_enable(session->be_provider, EV_READ | EV_WRITE);
}

static int tcp_on_link_added(struct pvx_link *link)
{
	struct event_base *base = pvx_get_base();
	int fd;

	if (link->consumer_pid > 0) {
		printf("%s: Injecting TCP listener %s into pid %d\n",
		       MODULE_NAME, link->consumer_socket, link->consumer_pid);
	} else {
		printf("%s: Binding TCP listener %s on host network\n",
		       MODULE_NAME, link->consumer_socket);
	}

	fd = pvx_helper_inject_tcp_socket(link->consumer_socket,
					  link->consumer_pid);
	if (fd < 0)
		return -1;

	link->listener =
		evconnlistener_new(base, tcp_on_accept, link,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, fd);

	if (!link->listener) {
		close(fd);
		return -1;
	}

	return 0;
}

struct pvx_plugin pvx_plugin_tcp = { .type = "tcp",
				     .on_link_added = tcp_on_link_added,
				     .on_accept = tcp_on_accept };
