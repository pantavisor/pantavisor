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
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <jsmn/jsmnutil.h>
#include "utils/json.h"

#include "include/xconnect.h"

static struct event_base *g_base;
static struct dl_list g_links;

extern struct pvx_plugin pvx_plugin_unix;
extern struct pvx_plugin pvx_plugin_rest;
extern struct pvx_plugin pvx_plugin_drm;
extern struct pvx_plugin pvx_plugin_wayland;

static struct pvx_plugin *plugins[] = { &pvx_plugin_unix, &pvx_plugin_rest,
					&pvx_plugin_drm, &pvx_plugin_wayland,
					NULL };

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

	int count = jsmnutil_array_count(json, tokv);
	printf("Reconciling graph with %d links\n", count);

	// Simplistic: just add new ones for now, don't delete
	jsmntok_t *t = tokv + 1;
	for (int i = 0; i < count; i++) {
		int obj_c;
		char *obj_s = pv_json_array_get_one_str(json, &count, &t);
		if (!obj_s)
			break;

		jsmntok_t *ov;
		if (jsmnutil_parse_json(obj_s, &ov, &obj_c) > 0) {
			char *type =
				pv_json_get_value(obj_s, "type", ov, obj_c);
			struct pvx_plugin *p = find_plugin(type);

			if (p) {
				struct pvx_link *link =
					calloc(1, sizeof(*link));
				link->type = type;
				link->name = pv_json_get_value(obj_s, "name",
							       ov, obj_c);
				link->consumer = pv_json_get_value(
					obj_s, "consumer", ov, obj_c);
				link->role = pv_json_get_value(obj_s, "role",
							       ov, obj_c);
				link->provider_socket = pv_json_get_value(
					obj_s, "socket", ov, obj_c);

				// For host testing, create a virtual path
				char path[1024];
				snprintf(path, sizeof(path),
					 "/tmp/pvx_%s_%s.sock", link->consumer,
					 link->name);
				link->consumer_socket = strdup(path);

				link->plugin = p;
				dl_list_init(&link->list);
				dl_list_add_tail(&g_links, &link->list);

				printf("Adding link: %s (%s) -> %s\n",
				       link->consumer, link->type,
				       link->provider_socket);
				p->on_link_added(link);
			} else {
				fprintf(stderr, "No plugin found for type %s\n",
					type);
				if (type)
					free(type);
			}
			free(ov);
		}
		free(obj_s);
	}
	free(tokv);
}

// In a real implementation, this would be a continuous bufferevent to pv-ctrl
static void fetch_graph_mock(void)
{
	// For now, let's just trigger a mock reconciliation if we were to test
	// reconcile_graph("[...]");
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

	printf("pv-xconnect starting...\n");

	// In real app, we'd start the pv-ctrl client here
	fetch_graph_mock();

	event_base_dispatch(g_base);

	event_free(signal_event);
	event_base_free(g_base);

	return 0;
}