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
#include "../include/xconnect.h"

#define MODULE_NAME "pvx-rest"

struct rest_proxy_session {
	struct bufferevent *be_client;
	struct bufferevent *be_provider;
	struct pvx_link *link;
	int client_eof;
	int provider_eof;
};

static void proxy_check_close(struct rest_proxy_session *session)
{
	// Only close when both sides have EOF'd or errored
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
	struct rest_proxy_session *session = arg;

	if (events & BEV_EVENT_ERROR) {
		// On error, mark both as done and close
		session->client_eof = 1;
		session->provider_eof = 1;
		proxy_check_close(session);
		return;
	}

	if (events & BEV_EVENT_EOF) {
		// Half-close: one side sent EOF
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

static void rest_read_cb(struct bufferevent *bev, void *arg)
{
	struct rest_proxy_session *session = arg;
	struct bufferevent *other = (bev == session->be_client) ?
					    session->be_provider :
					    session->be_client;
	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *dst = bufferevent_get_output(other);
	evbuffer_add_buffer(dst, src);
}

static void rest_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
			   struct sockaddr *address, int socklen, void *arg)
{
	struct pvx_link *link = arg;
	struct event_base *base = pvx_get_base();
	char provider_path[256];

	if (!link->name || !link->provider_socket) {
		close(fd);
		return;
	}

	printf("%s: Accepted REST connection for service %s from %s (pid %d)\n",
	       MODULE_NAME, link->name,
	       link->consumer ? link->consumer : "unknown", link->consumer_pid);

	// Build provider socket path - use /proc/pid/root/ to access container namespace
	if (link->provider_pid > 0) {
		snprintf(provider_path, sizeof(provider_path),
			 "/proc/%d/root%s", link->provider_pid,
			 link->provider_socket);
	} else {
		strncpy(provider_path, link->provider_socket,
			sizeof(provider_path) - 1);
		provider_path[sizeof(provider_path) - 1] = '\0';
	}
	struct rest_proxy_session *session = calloc(1, sizeof(*session));
	if (!session) {
		fprintf(stderr, "Could not allocate REST proxy session\n");
		close(fd);
		return;
	}

	session->link = link;
	session->be_client =
		bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	session->be_provider =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

	if (bufferevent_socket_connect(session->be_provider,
				       (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		fprintf(stderr, "Could not connect to provider socket %s\n",
			provider_path);
		bufferevent_free(session->be_client);
		bufferevent_free(session->be_provider);
		free(session);
		return;
	}

	bufferevent_setcb(session->be_client, rest_read_cb, NULL,
			  proxy_event_cb, session);
	bufferevent_setcb(session->be_provider, rest_read_cb, NULL,
			  proxy_event_cb, session);

	bufferevent_enable(session->be_client, EV_READ | EV_WRITE);
	bufferevent_enable(session->be_provider, EV_READ | EV_WRITE);
}

static int rest_on_link_added(struct pvx_link *link)
{
	struct event_base *base = pvx_get_base();
	int fd;

	if (link->consumer_pid > 0) {
		printf("%s: Injecting REST socket %s into pid %d\n",
		       MODULE_NAME, link->consumer_socket, link->consumer_pid);
		fd = pvx_helper_inject_unix_socket(link->consumer_socket,
						   link->consumer_pid);
	} else {
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		struct sockaddr_un sun;
		memset(&sun, 0, sizeof(sun));
		sun.sun_family = AF_UNIX;
		strncpy(sun.sun_path, link->consumer_socket,
			sizeof(sun.sun_path) - 1);
		unlink(link->consumer_socket);
		bind(fd, (struct sockaddr *)&sun, sizeof(sun));
		listen(fd, 10);
		evutil_make_socket_nonblocking(fd);
	}

	if (fd < 0)
		return -1;

	link->listener =
		evconnlistener_new(base, rest_on_accept, link,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, fd);

	if (!link->listener) {
		fprintf(stderr, "Could not create listener for %s\n",
			link->consumer_socket);
		close(fd);
		return -1;
	}

	return 0;
}

struct pvx_plugin pvx_plugin_rest = { .type = "rest",
				      .on_link_added = rest_on_link_added,
				      .on_accept = rest_on_accept };