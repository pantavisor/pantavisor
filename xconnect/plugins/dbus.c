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

#define MODULE_NAME "pvx-dbus"

struct dbus_proxy_session {
        struct bufferevent *be_client;
        struct bufferevent *be_provider;
        int client_eof;
        int provider_eof;
};

static void proxy_check_close(struct dbus_proxy_session *sess)
{
        if (sess->client_eof && sess->provider_eof) {
                if (sess->be_client)
                        bufferevent_free(sess->be_client);
                if (sess->be_provider)
                        bufferevent_free(sess->be_provider);
                free(sess);
        }
}

static void proxy_event_cb(struct bufferevent *bev, short events, void *arg)
{
        struct dbus_proxy_session *sess = arg;

        if (events & BEV_EVENT_ERROR) {
                sess->client_eof = 1;
                sess->provider_eof = 1;
                proxy_check_close(sess);
                return;
        }

        if (events & BEV_EVENT_EOF) {
                if (bev == sess->be_client) {
                        sess->client_eof = 1;
                        bufferevent_disable(bev, EV_READ);
                } else {
                        sess->provider_eof = 1;
                        bufferevent_disable(bev, EV_READ);
                }
                proxy_check_close(sess);
        }
}

static void proxy_read_cb(struct bufferevent *bev, void *arg)
{
        struct dbus_proxy_session *sess = arg;
        struct bufferevent *other =
                (bev == sess->be_client) ? sess->be_provider : sess->be_client;
        struct evbuffer *src = bufferevent_get_input(bev);
        struct evbuffer *dst = bufferevent_get_output(other);
        evbuffer_add_buffer(dst, src);
}

static void dbus_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
                           struct sockaddr *address, int socklen, void *arg)
{
        struct pvx_link *link = arg;
        struct event_base *base = pvx_get_base();
        char provider_path[256];

        printf("%s: Accepted connection for service %s from pid %d\n",
               MODULE_NAME, link->name, link->consumer_pid);

        if (link->provider_pid > 0) {
                snprintf(provider_path, sizeof(provider_path),
                         "/proc/%d/root%s", link->provider_pid,
                         link->provider_socket);
        } else {
                strncpy(provider_path, link->provider_socket,
                        sizeof(provider_path) - 1);
        }

        struct dbus_proxy_session *sess = calloc(1, sizeof(*sess));
        if (!sess) {
                fprintf(stderr, "Could not allocate proxy session\n");
                close(fd);
                return;
        }

        sess->be_client = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
        sess->be_provider = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

        struct sockaddr_un sun;
        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

        if (bufferevent_socket_connect(sess->be_provider, (struct sockaddr *)&sun,
                                       sizeof(sun)) < 0) {
                fprintf(stderr, "Could not connect to provider socket %s\n",
                        provider_path);
                bufferevent_free(sess->be_client);
                bufferevent_free(sess->be_provider);
                free(sess);
                return;
        }

        bufferevent_setcb(sess->be_client, proxy_read_cb, NULL, proxy_event_cb, sess);
        bufferevent_setcb(sess->be_provider, proxy_read_cb, NULL, proxy_event_cb, sess);

        bufferevent_enable(sess->be_client, EV_READ | EV_WRITE);
        bufferevent_enable(sess->be_provider, EV_READ | EV_WRITE);
}

static int dbus_on_link_added(struct pvx_link *link)
{
        struct event_base *base = pvx_get_base();
        int fd;

        // For D-Bus, we typically inject /run/dbus/system_bus_socket or similar
        if (link->consumer_pid > 0) {
                printf("%s: Injecting socket %s into pid %d\n", MODULE_NAME,
                       link->consumer_socket, link->consumer_pid);
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
                evconnlistener_new(base, dbus_on_accept, link,
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

struct pvx_plugin pvx_plugin_dbus = { .type = "dbus",
                                      .on_link_added = dbus_on_link_added,
                                      .on_accept = dbus_on_accept };
