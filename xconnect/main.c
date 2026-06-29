#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
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
#define RECONCILE_INTERVAL_SEC 5

static struct event_base *g_base;
static struct dl_list g_links;
static struct event *g_reconcile_timer;

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

// Links are keyed on (consumer, name, target). The target (resolved consumer
// socket) is part of the key so a multi-identity consumer can hold several
// links to the same service name on different sockets (e.g. distinct dbus roles
// on the hosted system bus) without them tearing each other down on reconcile.
static struct pvx_link *find_link(const char *consumer, const char *name,
				  const char *target)
{
	struct pvx_link *link;
	dl_list_for_each(link, &g_links, struct pvx_link, list)
	{
		if (link->consumer && link->name &&
		    !strcmp(link->consumer, consumer) &&
		    !strcmp(link->name, name) &&
		    ((!target && !link->consumer_socket) ||
		     (target && link->consumer_socket &&
		      !strcmp(target, link->consumer_socket))))
			return link;
	}
	return NULL;
}

static void pvx_link_free(struct pvx_link *link)
{
	if (!link)
		return;

	// Let the plugin release any per-link resources before we drop the
	// listener that owns the (possibly injected) listening socket.
	if (link->plugin && link->plugin->on_link_removed)
		link->plugin->on_link_removed(link);

	// The link owns its listener; freeing it here closes the listening
	// socket and prevents a listener/fd leak when a link is replaced (e.g.
	// on container restart) or retried.
	if (link->listener) {
		evconnlistener_free(link->listener);
		link->listener = NULL;
	}

	free(link->name);
	free(link->consumer);
	free(link->role);
	free(link->provider_socket);
	free(link->interface);
	free(link->consumer_socket);
	free(link->type);
	free(link);
}

static int parse_pid_field(const char *json, const char *key, jsmntok_t *tokv,
			   int tokc)
{
	char *pid_str = pv_json_get_value(json, key, tokv, tokc);
	if (!pid_str)
		return 0;

	char *endptr;
	long val = strtol(pid_str, &endptr, 10);
	int pid = (*endptr == '\0' && val > 0 && val <= INT_MAX) ? (int)val : 0;
	free(pid_str);
	return pid;
}

static struct pvx_link *parse_link(const char *json, jsmntok_t *itok,
				   int obj_tokc, struct pvx_plugin *plugin)
{
	struct pvx_link *link = calloc(1, sizeof(*link));
	if (!link)
		return NULL;

	link->consumer = pv_json_get_value(json, "consumer", itok, obj_tokc);
	link->name = pv_json_get_value(json, "name", itok, obj_tokc);
	link->type = pv_json_get_value(json, "type", itok, obj_tokc);
	link->role = pv_json_get_value(json, "role", itok, obj_tokc);
	link->provider_socket =
		pv_json_get_value(json, "socket", itok, obj_tokc);
	link->interface = pv_json_get_value(json, "interface", itok, obj_tokc);

	// Hosted system-bus links carry the role's resolved uid; the dbus plugin
	// masquerades to it directly instead of an /etc/passwd lookup. Absent for
	// legacy per-provider links, which keep the passwd path (uid stays -1).
	char *uid_str = pv_json_get_value(json, "uid", itok, obj_tokc);
	if (uid_str) {
		char *uend;
		long uval = strtol(uid_str, &uend, 10);
		link->uid = (*uend == '\0' && uval >= 0 && uval <= INT_MAX) ?
				    (int)uval :
				    -1;
		free(uid_str);
	} else {
		link->uid = -1;
	}

	if (!link->name || !link->consumer || !link->provider_socket) {
		fprintf(stderr, "Link missing required fields\n");
		pvx_link_free(link);
		return NULL;
	}

	link->consumer_pid =
		parse_pid_field(json, "consumer_pid", itok, obj_tokc);
	link->provider_pid =
		parse_pid_field(json, "provider_pid", itok, obj_tokc);

	char *target = pv_json_get_value(json, "target", itok, obj_tokc);
	if (target && target[0]) {
		link->consumer_socket = strdup(target);
	} else if (link->interface && link->interface[0]) {
		link->consumer_socket = strdup(link->interface);
	} else {
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "/tmp/pvx_%s_%s.sock",
			 link->consumer, link->name);
		link->consumer_socket = strdup(path);
	}
	free(target);

	link->plugin = plugin;
	return link;
}

static void reconcile_link(const char *json, jsmntok_t *itok, int obj_tokc)
{
	char *type = pv_json_get_value(json, "type", itok, obj_tokc);
	if (!type)
		return;

	struct pvx_plugin *plugin = find_plugin(type);
	if (!plugin) {
		fprintf(stderr, "No plugin found for type %s\n", type);
		free(type);
		return;
	}
	free(type);

	// Parse first so the key (consumer, name, resolved target) and the new
	// pids are available before we decide whether an existing link stands.
	struct pvx_link *link = parse_link(json, itok, obj_tokc, plugin);
	if (!link)
		return;

	struct pvx_link *existing =
		find_link(link->consumer, link->name, link->consumer_socket);

	if (existing && existing->established) {
		// The key survives a container restart, but a restarted peer's pid
		// changes: the old proxy would keep connecting to the dead provider
		// pid and the consumer socket would never be re-injected into the
		// new namespace. Detect the pid change and re-establish; otherwise
		// leave the working link untouched.
		// A reported pid of 0 means "unknown/down" (or a host-side peer);
		// don't tear down a working link until a real, different pid shows.
		bool cpid_changed =
			link->consumer_pid &&
			link->consumer_pid != existing->consumer_pid;
		bool ppid_changed =
			link->provider_pid &&
			link->provider_pid != existing->provider_pid;
		if (!cpid_changed && !ppid_changed) {
			pvx_link_free(link);
			return;
		}
		printf("Re-establishing link %s/%s (target %s) after restart (consumer pid %d->%d, provider pid %d->%d)\n",
		       link->consumer, link->name, link->consumer_socket,
		       existing->consumer_pid, link->consumer_pid,
		       existing->provider_pid, link->provider_pid);
		dl_list_del(&existing->list);
		pvx_link_free(existing);
	} else if (existing) {
		printf("Retrying link: %s/%s\n", link->consumer, link->name);
		dl_list_del(&existing->list);
		pvx_link_free(existing);
	}

	dl_list_init(&link->list);
	dl_list_add_tail(&g_links, &link->list);

	printf("Adding link: %s (pid=%d, %s) -> %s (inject to: %s)\n",
	       link->consumer ? link->consumer : "unknown", link->consumer_pid,
	       link->type, link->provider_socket, link->consumer_socket);

	if (plugin->on_link_added(link) < 0) {
		fprintf(stderr, "Failed to add link for %s\n", link->name);
		dl_list_del(&link->list);
		pvx_link_free(link);
	} else {
		link->established = true;
		printf("Link established: %s/%s\n", link->consumer, link->name);
	}
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
		int obj_tokc = items[i + 1] ? items[i + 1] - items[i] :
					      (tokv + tokc) - itok;
		reconcile_link(json, itok, obj_tokc);
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

static void reconcile_timer_cb(evutil_socket_t fd, short event, void *arg)
{
	printf("Periodic reconciliation check...\n");
	fetch_graph();

	// Re-arm the timer
	struct timeval tv = { RECONCILE_INTERVAL_SEC, 0 };
	evtimer_add(g_reconcile_timer, &tv);
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

	// Set up periodic reconciliation timer
	g_reconcile_timer = evtimer_new(g_base, reconcile_timer_cb, NULL);
	if (!g_reconcile_timer) {
		fprintf(stderr, "Could not create reconcile timer!\n");
		return 1;
	}
	struct timeval tv = { RECONCILE_INTERVAL_SEC, 0 };
	evtimer_add(g_reconcile_timer, &tv);

	// Initial graph fetch
	fetch_graph();

	event_base_dispatch(g_base);

	event_free(g_reconcile_timer);
	event_free(signal_event);
	event_free(term_event);
	event_base_free(g_base);

	return 0;
}
