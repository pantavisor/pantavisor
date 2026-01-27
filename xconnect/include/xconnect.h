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
	bool established; // Track if link setup completed
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
int pvx_helper_inject_tcp_socket(const char *addr_str, int pid);
int pvx_helper_inject_devnode(const char *target_path, int consumer_pid,
			      const char *source_path, int provider_pid);
#endif
