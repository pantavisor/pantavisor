#ifndef PV_XCONNECT_H
#define PV_XCONNECT_H

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <stdbool.h>
#include <sys/queue.h>

// We use the same list implementation as pantavisor if available
#include "../../utils/list.h"

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

    struct pvx_plugin *plugin;
    struct evconnlistener *listener;
    void *plugin_data;
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
struct event_base* pvx_get_base(void);
int pvx_helper_inject_unix_socket(const char *path, int pid);

#endif
