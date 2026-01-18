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

#define MODULE_NAME "pvx-wayland"

static void wayland_proxy_event_cb(struct bufferevent *bev, short events,
				   void *arg)
{
	struct bufferevent *other = arg;
	if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		if (other) {
			bufferevent_flush(other, EV_READ | EV_WRITE,
					  BEV_FINISHED);
			bufferevent_free(other);
		}
		bufferevent_free(bev);
	}
}

static void wayland_proxy_read_cb(struct bufferevent *bev, void *arg)
{
	struct bufferevent *other = arg;
	struct evbuffer *src = bufferevent_get_input(bev);
	struct evbuffer *dst = bufferevent_get_output(other);
	evbuffer_add_buffer(dst, src);
}

static void wayland_on_accept(struct evconnlistener *listener,
			      evutil_socket_t fd, struct sockaddr *address,
			      int socklen, void *arg)
{
	struct pvx_link *link = arg;
	struct event_base *base = pvx_get_base();

	printf("%s: Accepted Wayland connection for %s from pid %d\n",
	       MODULE_NAME, link->name, link->consumer_pid);

	struct bufferevent *be_client =
		bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	struct bufferevent *be_provider =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, link->provider_socket, sizeof(sun.sun_path) - 1);

	if (bufferevent_socket_connect(be_provider, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		fprintf(stderr, "Could not connect to compositor socket %s\n",
			link->provider_socket);
		bufferevent_free(be_client);
		bufferevent_free(be_provider);
		return;
	}

	bufferevent_setcb(be_client, wayland_proxy_read_cb, NULL,
			  wayland_proxy_event_cb, be_provider);
	bufferevent_setcb(be_provider, wayland_proxy_read_cb, NULL,
			  wayland_proxy_event_cb, be_client);

	bufferevent_enable(be_client, EV_READ | EV_WRITE);
	bufferevent_enable(be_provider, EV_READ | EV_WRITE);
}

static int wayland_on_link_added(struct pvx_link *link)
{
	struct event_base *base = pvx_get_base();
	int fd;

	printf("%s: Setting up Wayland link for %s\n", MODULE_NAME,
	       link->consumer);

	if (link->consumer_pid > 0) {
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

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	// Note: fd is already bound, but libevent wants to know the address.
	// In this case, we can use evconnlistener_new if we already have the fd.
	link->listener =
		evconnlistener_new(base, wayland_on_accept, link,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, fd);

	return 0;
}

struct pvx_plugin pvx_plugin_wayland = { .type = "wayland",
					 .on_link_added = wayland_on_link_added,
					 .on_accept = wayland_on_accept };
