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
	bool headers_injected;
};

static void proxy_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct rest_proxy_session *session = arg;
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(session->be_client);
		bufferevent_free(session->be_provider);
		free(session);
	}
}

static void rest_read_client_cb(struct bufferevent *bev, void *arg)
{
	struct rest_proxy_session *session = arg;
	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *dst = bufferevent_get_output(session->be_provider);

	if (!session->headers_injected) {
		char headers[512];
		snprintf(headers, sizeof(headers),
			 "X-PV-Client: %s\r\nX-PV-Role: %s\r\n",
			 session->link->consumer, session->link->role);
		evbuffer_add(dst, headers, strlen(headers));
		session->headers_injected = true;
	}

	evbuffer_add_buffer(dst, src);
}

static void rest_read_provider_cb(struct bufferevent *bev, void *arg)
{
	struct rest_proxy_session *session = arg;
	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *dst = bufferevent_get_output(session->be_client);
	evbuffer_add_buffer(dst, src);
}

static void rest_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
			   struct sockaddr *address, int socklen, void *arg)
{
	struct pvx_link *link = arg;
	struct event_base *base = pvx_get_base();
	struct rest_proxy_session *session = calloc(1, sizeof(*session));

	printf("%s: Accepted REST connection for service %s from %s (pid %d)\n",
	       MODULE_NAME, link->name, link->consumer, link->consumer_pid);

	session->link = link;
	session->headers_injected = false;
	session->be_client =
		bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	session->be_provider =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, link->provider_socket, sizeof(sun.sun_path) - 1);

	if (bufferevent_socket_connect(session->be_provider,
				       (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		fprintf(stderr, "Could not connect to provider socket %s\n",
			link->provider_socket);
		bufferevent_free(session->be_client);
		bufferevent_free(session->be_provider);
		free(session);
		return;
	}

	bufferevent_setcb(session->be_client, rest_read_client_cb, NULL,
			  proxy_event_cb, session);
	bufferevent_setcb(session->be_provider, rest_read_provider_cb, NULL,
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