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
#include <unistd.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "../include/xconnect.h"

#define MODULE_NAME "pvx-http"

struct http_route {
	char *path;
	struct pvx_link *link;
	struct dl_list list;
};

struct http_ingress_server {
	char *listen_addr;
	struct evhttp *http;
	struct dl_list routes;
	struct dl_list list;
};

static struct dl_list g_http_servers;

struct http_proxy_session {
	struct evhttp_request *req;
	struct bufferevent *be_provider;
	struct pvx_link *link;
	char *backend_path;
	bool replied;
};

static void http_provider_event_cb(struct bufferevent *bev, short events,
				   void *arg)
{
	struct http_proxy_session *session = arg;

	if (events & BEV_EVENT_CONNECTED) {
		struct evbuffer *output = bufferevent_get_output(bev);
		const char *cmd_str = "GET";
		switch (evhttp_request_get_command(session->req)) {
		case EVHTTP_REQ_GET:
			cmd_str = "GET";
			break;
		case EVHTTP_REQ_POST:
			cmd_str = "POST";
			break;
		case EVHTTP_REQ_PUT:
			cmd_str = "PUT";
			break;
		case EVHTTP_REQ_DELETE:
			cmd_str = "DELETE";
			break;
		default:
			break;
		}

		evbuffer_add_printf(output, "%s %s HTTP/1.0\r\n", cmd_str,
				    session->backend_path);

		struct evkeyvalq *headers =
			evhttp_request_get_input_headers(session->req);
		struct evkeyval *header;
		TAILQ_FOREACH(header, headers, next)
		{
			if (strcasecmp(header->key, "Host") == 0)
				continue;
			if (strcasecmp(header->key, "Connection") == 0)
				continue;
			evbuffer_add_printf(output, "%s: %s\r\n", header->key,
					    header->value);
		}
		evbuffer_add_printf(output, "Host: localhost\r\n");
		evbuffer_add_printf(output, "Connection: close\r\n\r\n");

		struct evbuffer *input_body =
			evhttp_request_get_input_buffer(session->req);
		if (evbuffer_get_length(input_body) > 0) {
			evbuffer_add_buffer(output, input_body);
		}
		return;
	}

	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		if (!session->replied) {
			evhttp_send_reply(session->req, 200, "OK",
					  bufferevent_get_input(bev));
			session->replied = true;
		}
		if (session->backend_path)
			free(session->backend_path);
		bufferevent_free(bev);
		free(session);
	}
}

static void http_provider_read_cb(struct bufferevent *bev, void *arg)
{
}

static void http_ingress_gencb(struct evhttp_request *req, void *arg)
{
	struct http_ingress_server *srv = arg;
	const char *uri = evhttp_request_get_uri(req);
	struct http_route *route, *tmp;
	struct http_route *matched = NULL;

	dl_list_for_each_safe(route, tmp, &srv->routes, struct http_route, list)
	{
		if (strncmp(uri, route->path, strlen(route->path)) == 0) {
			matched = route;
			break;
		}
	}

	if (!matched) {
		evhttp_send_error(req, 404, "Not Found");
		return;
	}

	struct pvx_link *link = matched->link;
	struct event_base *base = pvx_get_base();
	char provider_path[256];

	const char *subpath = uri + strlen(matched->path);
	if (subpath[0] != '/') {
		// ensure it starts with /
		char *new_path = malloc(strlen(subpath) + 2);
		sprintf(new_path, "/%s", subpath);
		subpath = new_path;
	} else {
		subpath = strdup(subpath);
	}

	printf("%s: Proxying %s -> %s (provider: %s)\n", MODULE_NAME, uri,
	       subpath, link->name);

	if (link->provider_pid > 0) {
		snprintf(provider_path, sizeof(provider_path),
			 "/proc/%d/root%s", link->provider_pid,
			 link->provider_socket);
	} else {
		strncpy(provider_path, link->provider_socket,
			sizeof(provider_path) - 1);
	}

	struct http_proxy_session *session = calloc(1, sizeof(*session));
	session->req = req;
	session->link = link;
	session->backend_path = (char *)subpath;
	session->be_provider =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

	bufferevent_setcb(session->be_provider, http_provider_read_cb, NULL,
			  http_provider_event_cb, session);
	bufferevent_enable(session->be_provider, EV_READ | EV_WRITE);

	if (bufferevent_socket_connect(session->be_provider,
				       (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		evhttp_send_error(req, 502, "Provider Gateway Error");
		bufferevent_free(session->be_provider);
		if (session->backend_path)
			free(session->backend_path);
		free(session);
		return;
	}
}

static struct http_ingress_server *find_server(const char *addr)
{
	struct http_ingress_server *srv;
	dl_list_for_each(srv, &g_http_servers, struct http_ingress_server, list)
	{
		if (!strcmp(srv->listen_addr, addr))
			return srv;
	}
	return NULL;
}

static int http_on_link_added(struct pvx_link *link)
{
	char *host = strdup(link->consumer_socket);
	char *path = strchr(host, '/');
	char full_path[256];

	if (path) {
		*path = '\0';
		snprintf(full_path, sizeof(full_path), "/%s", path + 1);
	} else {
		strcpy(full_path, "/");
	}

	struct http_ingress_server *srv = find_server(host);
	if (!srv) {
		if (link->consumer_pid > 0) {
			printf("%s: Injecting HTTP listener %s into pid %d\n",
			       MODULE_NAME, host, link->consumer_pid);
		} else {
			printf("%s: Binding HTTP listener %s on host network\n",
			       MODULE_NAME, host);
		}
		int fd = pvx_helper_inject_tcp_socket(host, link->consumer_pid);
		if (fd < 0) {
			free(host);
			return -1;
		}

		srv = calloc(1, sizeof(*srv));
		srv->listen_addr = strdup(host);
		srv->http = evhttp_new(pvx_get_base());
		dl_list_init(&srv->routes);
		evhttp_accept_socket(srv->http, fd);
		evhttp_set_gencb(srv->http, http_ingress_gencb, srv);
		dl_list_init(&srv->list);
		dl_list_add_tail(&g_http_servers, &srv->list);
	}

	struct http_route *route = calloc(1, sizeof(*route));
	route->path = strdup(full_path);
	route->link = link;
	dl_list_init(&route->list);
	dl_list_add_tail(&srv->routes, &route->list);

	printf("%s: Registered HTTP route %s on %s for %s\n", MODULE_NAME,
	       full_path, host, link->name);

	free(host);
	return 0;
}

static int http_init(void)
{
	dl_list_init(&g_http_servers);
	return 0;
}

struct pvx_plugin pvx_plugin_http = { .type = "http",
				      .init = http_init,
				      .on_link_added = http_on_link_added };