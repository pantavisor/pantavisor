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
#include "proxy_common.h"

#define MODULE_NAME "pvx-unix"

static void unix_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
			   struct sockaddr *address, int socklen, void *arg)
{
	struct pvx_link *link = arg;
	struct event_base *base = pvx_get_base();
	char provider_path[256];
	(void)listener;
	(void)address;
	(void)socklen;

	if (!link->name || !link->provider_socket) {
		close(fd);
		return;
	}

	printf("%s: Accepted connection for service %s from pid %d\n",
	       MODULE_NAME, link->name, link->consumer_pid);

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

	struct pvx_proxy *p = calloc(1, sizeof(*p));
	if (!p) {
		fprintf(stderr, "Could not allocate proxy session\n");
		close(fd);
		return;
	}

	// DEFER_CALLBACKS keeps bufferevent_socket_connect() from invoking our
	// event callback re-entrantly on an immediate connect failure (which
	// would free the session while we still use it below), and makes
	// freeing a bufferevent from within its own callback safe.
	p->be_client = bufferevent_socket_new(
		base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	p->be_provider = bufferevent_socket_new(
		base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	// Register callbacks before connecting so a deferred error is handled.
	bufferevent_setcb(p->be_client, pvx_proxy_read_cb, NULL,
			  pvx_proxy_event_cb, p);
	bufferevent_setcb(p->be_provider, pvx_proxy_read_cb, NULL,
			  pvx_proxy_event_cb, p);

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

	if (bufferevent_socket_connect(p->be_provider, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		fprintf(stderr, "Could not connect to provider socket %s\n",
			provider_path);
		pvx_proxy_free(p);
		return;
	}

	bufferevent_enable(p->be_client, EV_READ | EV_WRITE);
	bufferevent_enable(p->be_provider, EV_READ | EV_WRITE);
}

static int unix_on_link_added(struct pvx_link *link)
{
	struct event_base *base = pvx_get_base();
	int fd;

	if (link->consumer_pid > 0) {
		printf("%s: Injecting socket %s into pid %d\n", MODULE_NAME,
		       link->consumer_socket, link->consumer_pid);
		fd = pvx_helper_inject_unix_socket(link->consumer_socket,
						   link->consumer_pid);
	} else {
		// Host-side listener
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
		evconnlistener_new(base, unix_on_accept, link,
				   LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
				   -1, fd);

	if (!link->listener) {
		fprintf(stderr, "Could not create listener for %s\n",
			link->consumer_socket);
		close(fd);
		return -1;
	}

	// Survive fd exhaustion instead of busy-looping on accept().
	pvx_listener_set_emfile_backoff(link->listener);

	return 0;
}

struct pvx_plugin pvx_plugin_unix = { .type = "unix",
				      .on_link_added = unix_on_link_added,
				      .on_accept = unix_on_accept };
