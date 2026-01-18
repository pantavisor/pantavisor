#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "../include/xconnect.h"

#define MODULE_NAME "pvx-unix"

struct unix_proxy_session {
    struct bufferevent *be_client;
    struct bufferevent *be_provider;
};

static void proxy_event_cb(struct bufferevent *bev, short events, void *arg)
{
    struct bufferevent *other = arg;
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (other) {
            // Send EOF to other side
            bufferevent_flush(other, EV_READ|EV_WRITE, BEV_FINISHED);
            bufferevent_free(other);
        }
        bufferevent_free(bev);
        // Note: we'd need a better way to free the session struct here 
        // if we weren't just passing the other bev as arg.
    }
}

static void proxy_read_cb(struct bufferevent *bev, void *arg)
{
    struct bufferevent *other = arg;
    struct evbuffer *src = bufferevent_get_input(bev);
    struct evbuffer *dst = bufferevent_get_output(other);
    evbuffer_add_buffer(dst, src);
}

static void unix_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
                           struct sockaddr *address, int socklen, void *arg)
{
    struct pvx_link *link = arg;
    struct event_base *base = pvx_get_base();

    printf("%s: Accepted connection for service %s from pid %d\n", MODULE_NAME, link->name, link->consumer_pid);

    struct bufferevent *be_client = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    struct bufferevent *be_provider = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    struct sockaddr_un sun;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, link->provider_socket, sizeof(sun.sun_path) - 1);

    if (bufferevent_socket_connect(be_provider, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        fprintf(stderr, "Could not connect to provider socket %s\n", link->provider_socket);
        bufferevent_free(be_client);
        bufferevent_free(be_provider);
        return;
    }

    bufferevent_setcb(be_client, proxy_read_cb, NULL, proxy_event_cb, be_provider);
    bufferevent_setcb(be_provider, proxy_read_cb, NULL, proxy_event_cb, be_client);

    bufferevent_enable(be_client, EV_READ|EV_WRITE);
    bufferevent_enable(be_provider, EV_READ|EV_WRITE);
}

static int unix_on_link_added(struct pvx_link *link)
{
    struct event_base *base = pvx_get_base();
    int fd;

    if (link->consumer_pid > 0) {
        printf("%s: Injecting socket %s into pid %d\n", MODULE_NAME, link->consumer_socket, link->consumer_pid);
        fd = pvx_helper_inject_unix_socket(link->consumer_socket, link->consumer_pid);
    } else {
        // Host-side listener
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un sun;
        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        strncpy(sun.sun_path, link->consumer_socket, sizeof(sun.sun_path) - 1);
        unlink(link->consumer_socket);
        bind(fd, (struct sockaddr *)&sun, sizeof(sun));
        listen(fd, 10);
        evutil_make_socket_nonblocking(fd);
    }

    if (fd < 0) return -1;

    link->listener = evconnlistener_new(base, unix_on_accept, link,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, fd);

    if (!link->listener) {
        fprintf(stderr, "Could not create listener for %s\n", link->consumer_socket);
        close(fd);
        return -1;
    }

    return 0;
}

struct pvx_plugin pvx_plugin_unix = {
    .type = "unix",
    .on_link_added = unix_on_link_added,
    .on_accept = unix_on_accept
};