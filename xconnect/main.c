#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <picohttpparser.h>
#include <jsmn/jsmnutil.h>
#include "utils/json.h"

#include "include/xconnect.h"

#define PV_CTRL_SOCKET "/run/pantavisor/pv/pv-ctrl"

static struct event_base *g_base;
static struct dl_list g_links;

extern struct pvx_plugin pvx_plugin_unix;
extern struct pvx_plugin pvx_plugin_rest;
extern struct pvx_plugin pvx_plugin_dbus;
extern struct pvx_plugin pvx_plugin_drm;
extern struct pvx_plugin pvx_plugin_wayland;

static struct pvx_plugin *plugins[] = { &pvx_plugin_unix,    &pvx_plugin_rest,
					&pvx_plugin_dbus,    &pvx_plugin_drm,
					&pvx_plugin_wayland, NULL };

struct event_base *pvx_get_base(void)
{
	return g_base;
}

static struct pvx_plugin *find_plugin(const char *type)
{
	for (int i = 0; plugins[i]; i++) {
		if (!strcmp(plugins[i]->type, type))
			return plugins[i];
	}
	return NULL;
}

static void reconcile_graph(const char *json)
{
	jsmntok_t *tokv;
	int tokc;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		fprintf(stderr, "Failed to parse graph JSON\n");
		return;
	}

	if (tokv->type != JSMN_ARRAY) {
		fprintf(stderr, "Graph JSON is not an array\n");
		free(tokv);
		return;
	}

	int count = jsmnutil_array_count(json, tokv);
	printf("Reconciling graph with %d links\n", count);

	jsmntok_t **items = jsmnutil_get_array_toks(json, tokv);
	if (!items) {
		free(tokv);
		return;
	}

	for (int i = 0; items[i]; i++) {
		jsmntok_t *itok = items[i];
		int rem_tokc = (tokv + tokc) - itok;

		char *type = pv_json_get_value(json, "type", itok, rem_tokc);
		struct pvx_plugin *p = find_plugin(type);

		if (p) {
			struct pvx_link *link = calloc(1, sizeof(*link));
			link->type = type;
			link->name =
				pv_json_get_value(json, "name", itok, rem_tokc);
			link->consumer = pv_json_get_value(json, "consumer",
							   itok, rem_tokc);
			link->role =
				pv_json_get_value(json, "role", itok, rem_tokc);
			link->provider_socket = pv_json_get_value(
				json, "socket", itok, rem_tokc);
			link->interface = pv_json_get_value(json, "interface",
							    itok, rem_tokc);
			char *target = pv_json_get_value(json, "target", itok,
							 rem_tokc);

			// Parse consumer_pid for namespace injection
			char *pid_str = pv_json_get_value(json, "consumer_pid",
							  itok, rem_tokc);
			if (pid_str) {
				link->consumer_pid = atoi(pid_str);
				free(pid_str);
			}

			// Parse provider_pid for cross-namespace socket access
			pid_str = pv_json_get_value(json, "provider_pid", itok,
						    rem_tokc);
			if (pid_str) {
				link->provider_pid = atoi(pid_str);
				free(pid_str);
			}

			// Use target as consumer socket path if available
			if (target && target[0]) {
				link->consumer_socket = strdup(target);
			} else if (link->interface && link->interface[0]) {
				link->consumer_socket = strdup(link->interface);
			} else {
				// Fallback for host testing
				char path[1024];
				snprintf(path, sizeof(path),
					 "/tmp/pvx_%s_%s.sock", link->consumer,
					 link->name);
				link->consumer_socket = strdup(path);
			}
			if (target)
				free(target);

			link->plugin = p;
			dl_list_init(&link->list);
			dl_list_add_tail(&g_links, &link->list);

			printf("Adding link: %s (pid=%d, %s) -> %s (inject to: %s)\n",
			       link->consumer, link->consumer_pid, link->type,
			       link->provider_socket, link->consumer_socket);
			p->on_link_added(link);
		} else {
			fprintf(stderr, "No plugin found for type %s\n", type);
			if (type)
				free(type);
		}
	}
	jsmnutil_tokv_free(items);
	free(tokv);
}
static void ctrl_read_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(input);
	char *data = malloc(len + 1);
	evbuffer_remove(input, data, len);
	data[len] = '\0';

	const char *msg;
	int minor_version, status;
	struct phr_header headers[100];
	size_t msg_len, num_headers = 100;
	int pret = phr_parse_response(data, len, &minor_version, &status, &msg,
				      &msg_len, headers, &num_headers, 0);

	if (pret > 0 && status == 200) {
		reconcile_graph(data + pret);
	} else {
		fprintf(stderr, "Failed to fetch graph: pret=%d, status=%d\n",
			pret, status);
	}

	free(data);
	bufferevent_free(bev);
}

static void ctrl_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		printf("Connected to pv-ctrl\n");
		evbuffer_add_printf(
			bufferevent_get_output(bev),
			"GET /xconnect-graph HTTP/1.0\r\nHost: localhost\r\n\r\n");
	} else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		if (events & BEV_EVENT_ERROR) {
			fprintf(stderr, "Error connecting to pv-ctrl: %s\n",
				strerror(errno));
		}
		bufferevent_free(bev);
	}
}

static void fetch_graph(void)
{
	struct bufferevent *bev;
	struct sockaddr_un sun;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, PV_CTRL_SOCKET, sizeof(sun.sun_path) - 1);

	bev = bufferevent_socket_new(g_base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, ctrl_read_cb, NULL, ctrl_event_cb, NULL);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	if (bufferevent_socket_connect(bev, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		fprintf(stderr, "Failed to initiate connection to pv-ctrl\n");
		bufferevent_free(bev);
	}
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
	struct event_base *base = arg;
	printf("Caught an interrupt signal; terminating cleanly.\n");
	event_base_loopexit(base, NULL);
}

int main(int argc, char **argv)
{
	struct event *signal_event;
	struct event *term_event;

	g_base = event_base_new();
	if (!g_base) {
		fprintf(stderr, "Could not initialize libevent!\n");
		return 1;
	}

	dl_list_init(&g_links);

	signal_event = evsignal_new(g_base, SIGINT, signal_cb, (void *)g_base);
	if (!signal_event || event_add(signal_event, NULL) < 0) {
		fprintf(stderr, "Could not create/add a signal event!\n");
		return 1;
	}

	term_event = evsignal_new(g_base, SIGTERM, signal_cb, (void *)g_base);
	if (!term_event || event_add(term_event, NULL) < 0) {
		fprintf(stderr, "Could not create/add a term event!\n");
		return 1;
	}
	printf("pv-xconnect starting...\n");

	fetch_graph();

	event_base_dispatch(g_base);

	event_free(signal_event);

	event_free(term_event);

	event_base_free(g_base);

	return 0;
}
