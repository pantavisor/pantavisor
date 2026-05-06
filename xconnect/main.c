#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <picohttpparser.h>
#include <jsmn/jsmnutil.h>
#include "utils/json.h"

#include "include/xconnect.h"
#include "services_bridge.h"
#include "services_nft.h"

#define PV_CTRL_SOCKET "/run/pantavisor/pv/pv-ctrl"
#define RECONCILE_INTERVAL_SEC 5

static struct event_base *g_base;
static struct dl_list g_links;
static struct event *g_reconcile_timer;

extern struct pvx_plugin pvx_plugin_unix;
extern struct pvx_plugin pvx_plugin_rest;
extern struct pvx_plugin pvx_plugin_tcp;
extern struct pvx_plugin pvx_plugin_dbus;
extern struct pvx_plugin pvx_plugin_drm;
extern struct pvx_plugin pvx_plugin_wayland;

static struct pvx_plugin *plugins[] = {
	&pvx_plugin_unix, &pvx_plugin_rest,    &pvx_plugin_tcp,
	&pvx_plugin_dbus, &pvx_plugin_drm,     &pvx_plugin_wayland,
	NULL
};

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

static struct pvx_link *find_link(const char *consumer, const char *name)
{
	struct pvx_link *link;
	dl_list_for_each(link, &g_links, struct pvx_link, list)
	{
		if (link->consumer && link->name &&
		    !strcmp(link->consumer, consumer) &&
		    !strcmp(link->name, name))
			return link;
	}
	return NULL;
}

static void pvx_link_free(struct pvx_link *link)
{
	if (!link)
		return;

	free(link->name);
	free(link->consumer);
	free(link->role);
	free(link->provider_socket);
	free(link->interface);
	free(link->consumer_socket);
	free(link->type);
	free(link->last_error);
	free(link);
}

static int parse_pid_field(const char *json, const char *key, jsmntok_t *tokv,
			   int tokc)
{
	// pv-ctrl emits transitional values like consumer_pid:-1 while a
	// container is starting; we treat those as "not ready" (return 0)
	// so the link stays unestablished and reconcile retries on the next
	// pass. Real pids parse via the existing string path; the int helper
	// is a fallback for primitives the string getter doesn't surface.
	char *pid_str = pv_json_get_value(json, key, tokv, tokc);
	int pid = 0;
	if (pid_str) {
		char *endptr;
		long val = strtol(pid_str, &endptr, 10);
		if (*endptr == '\0' && val > 0 && val <= INT_MAX)
			pid = (int)val;
		free(pid_str);
	} else {
		pid = pv_json_get_value_int(json, key, tokv, tokc);
		if (pid <= 0)
			pid = 0;
	}
	return pid;
}

// Returns network-byte-order IPv4, or 0 if missing/invalid.
static uint32_t parse_ipv4_field(const char *json, const char *key,
				 jsmntok_t *tokv, int tokc)
{
	char *s = pv_json_get_value(json, key, tokv, tokc);
	if (!s)
		return 0;
	struct in_addr a;
	uint32_t out = (inet_aton(s, &a) != 0) ? a.s_addr : 0;
	free(s);
	return out;
}

static uint16_t parse_u16_field(const char *json, const char *key,
				jsmntok_t *tokv, int tokc)
{
	char *s = pv_json_get_value(json, key, tokv, tokc);
	if (!s)
		return 0;
	long v = strtol(s, NULL, 10);
	free(s);
	if (v < 0 || v > 65535)
		return 0;
	return (uint16_t)v;
}

// Defaults to UNIX (legacy) when the field is absent so existing graphs
// keep working unchanged. Only the new IP services need to set it.
static pvx_transport_t parse_transport_field(const char *json, const char *key,
					     jsmntok_t *tokv, int tokc)
{
	char *s = pv_json_get_value(json, key, tokv, tokc);
	if (!s)
		return PVX_TRANSPORT_UNIX;
	pvx_transport_t t = (!strcmp(s, "tcp")) ? PVX_TRANSPORT_TCP :
						  PVX_TRANSPORT_UNIX;
	free(s);
	return t;
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

	// Service-IP links use cluster_ip/provider_ip/port and may omit the
	// legacy `socket` field entirely. Validate whichever shape applies.
	bool has_service_ip =
		(parse_ipv4_field(json, "cluster_ip", itok, obj_tokc) != 0);

	if (!link->name || !link->consumer ||
	    (!link->provider_socket && !has_service_ip)) {
		fprintf(stderr, "Link missing required fields\n");
		pvx_link_free(link);
		return NULL;
	}

	link->consumer_pid =
		parse_pid_field(json, "consumer_pid", itok, obj_tokc);
	link->provider_pid =
		parse_pid_field(json, "provider_pid", itok, obj_tokc);

	// Service / IP layer fields. All optional — pv-ctrl only fills these
	// for declared services. Legacy unix-socket bind-mount links leave
	// them zero and the link parses unchanged.
	link->cluster_ip =
		parse_ipv4_field(json, "cluster_ip", itok, obj_tokc);
	link->cluster_port = parse_u16_field(json, "cluster_port", itok,
					     obj_tokc);
	link->provider_ip =
		parse_ipv4_field(json, "provider_ip", itok, obj_tokc);
	link->provider_port = parse_u16_field(json, "provider_port", itok,
					      obj_tokc);
	link->provider_transport = parse_transport_field(
		json, "provider_transport", itok, obj_tokc);
	link->consumer_transport = parse_transport_field(
		json, "consumer_transport", itok, obj_tokc);

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

// Record a failure reason on `link` so the status endpoint can surface it
// to pantavisor's container health subsystem. Failure is sticky: the link
// stays in g_links with established=false so retry happens on the next
// reconcile pass; no silent removal.
static void link_set_error(struct pvx_link *link, const char *fmt, ...)
{
	free(link->last_error);
	link->last_error = NULL;
	char buf[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	link->last_error = strdup(buf);
	fprintf(stderr, "link %s/%s unhealthy: %s\n",
		link->consumer ? link->consumer : "?",
		link->name ? link->name : "?", buf);
}

// Inject `<service>.pv.local` into the consumer's /etc/hosts pointing at the
// ClusterIP. Hard-fail (caller marks link unhealthy) on any error: a wired
// consumer that can't see its services in DNS is not a working consumer.
//
// If this is a service-IP link (cluster_ip set) but consumer_pid is not yet
// valid (pv-ctrl emits -1 early during container start), we MUST return
// failure so the link stays unestablished and the next reconcile retries.
// Returning 0 (success) would mark the link "established" with no actual
// /etc/hosts entry — the link would then never be re-evaluated.
static int link_inject_hosts(struct pvx_link *link)
{
	if (!link->cluster_ip)
		return 0; // legacy (unix-socket) link, nothing to do
	if (link->consumer_pid <= 0)
		return -1; // service-IP link but pid not ready yet; retry
	char *host = pvx_service_hostname(link->name);
	if (!host)
		return -1;
	int rc = pvx_helper_inject_hosts_entry(link->consumer_pid, host,
					       link->cluster_ip);
	free(host);
	return rc;
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

	char *consumer = pv_json_get_value(json, "consumer", itok, obj_tokc);
	char *name = pv_json_get_value(json, "name", itok, obj_tokc);
	struct pvx_link *existing = find_link(consumer, name);

	if (existing && existing->established) {
		free(consumer);
		free(name);
		return;
	}

	free(consumer);
	free(name);

	struct pvx_link *link;
	if (existing) {
		// Retry path: REFRESH dynamic fields from the latest JSON
		// (consumer_pid, provider_pid, etc. transition from -1 to
		// real values as containers come up) but PRESERVE the
		// data-plane state (listener bound to ClusterIP:port, bridge
		// /32, nft DNAT rule) IF it came up successfully — tearing
		// down a live listener and re-binding the same socket races
		// with kernel close, producing EADDRINUSE on the rebind.
		struct pvx_link *fresh =
			parse_link(json, itok, obj_tokc, plugin);
		if (!fresh)
			return;
		existing->consumer_pid = fresh->consumer_pid;
		existing->provider_pid = fresh->provider_pid;
		existing->provider_ip = fresh->provider_ip;
		existing->provider_port = fresh->provider_port;
		pvx_link_free(fresh);
		free(existing->last_error);
		existing->last_error = NULL;
		link = existing;
	} else {
		link = parse_link(json, itok, obj_tokc, plugin);
		if (!link)
			return;
		dl_list_init(&link->list);
		dl_list_add_tail(&g_links, &link->list);

		printf("Adding link: %s (pid=%d, %s)\n",
		       link->consumer ? link->consumer : "unknown",
		       link->consumer_pid, link->type);
	}

	// Plugin runs until it succeeds. data_plane_up gates re-runs so we
	// don't tear down a working listener and rebind. A failed plugin call
	// (e.g. nft DNAT install fails because provider_ip wasn't allocated
	// yet) leaves data_plane_up=false and retries next reconcile pass.
	if (!link->data_plane_up) {
		if (plugin->on_link_added(link) < 0) {
			link_set_error(link, "plugin %s on_link_added failed",
				       link->type ? link->type : "?");
			return;
		}
		link->data_plane_up = true;
	}

	// Hosts injection runs every reconcile while not yet successful.
	// Idempotent: re-injection just rewrites the same line.
	if (link_inject_hosts(link) < 0) {
		link_set_error(link,
			       "/etc/hosts injection failed in pid %d (errno=%d %s)",
			       link->consumer_pid, errno, strerror(errno));
		return;
	}

	link->established = true;
	printf("Link established: %s/%s\n", link->consumer, link->name);
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

// Build a JSON array describing every link's establishment state, suitable for
// POSTing to pv-ctrl's /xconnect-status endpoint. Caller frees.
//
// Each element: {"consumer", "name", "established", "last_error"}. Strings
// are escaped minimally — service names + container names are alnum/dash by
// convention, last_error is generated by us and never contains quotes.
static char *build_status_json(void)
{
	// Rough cap: 256 bytes per link is plenty.
	size_t cap = 1024;
	char *buf = malloc(cap);
	if (!buf)
		return NULL;
	size_t len = 0;
	buf[len++] = '[';

	struct pvx_link *link;
	int first = 1;
	dl_list_for_each(link, &g_links, struct pvx_link, list)
	{
		char obj[512];
		int n = snprintf(obj, sizeof(obj),
				 "%s{\"consumer\":\"%s\",\"name\":\"%s\","
				 "\"established\":%s,\"last_error\":%s%s%s}",
				 first ? "" : ",",
				 link->consumer ? link->consumer : "",
				 link->name ? link->name : "",
				 link->established ? "true" : "false",
				 link->last_error ? "\"" : "null",
				 link->last_error ? link->last_error : "",
				 link->last_error ? "\"" : "");
		if (n < 0 || (size_t)n >= sizeof(obj))
			continue;
		if (len + n + 2 >= cap) {
			size_t new_cap = cap * 2 + n;
			char *grown = realloc(buf, new_cap);
			if (!grown) {
				free(buf);
				return NULL;
			}
			buf = grown;
			cap = new_cap;
		}
		memcpy(buf + len, obj, n);
		len += n;
		first = 0;
	}
	if (len + 2 >= cap) {
		char *grown = realloc(buf, cap + 4);
		if (!grown) {
			free(buf);
			return NULL;
		}
		buf = grown;
	}
	buf[len++] = ']';
	buf[len] = '\0';
	return buf;
}

struct status_post_ctx {
	char *body;
};

static void status_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct status_post_ctx *ctx = arg;
	if (events & BEV_EVENT_CONNECTED) {
		struct evbuffer *out = bufferevent_get_output(bev);
		evbuffer_add_printf(out,
				    "POST /xconnect-status HTTP/1.0\r\n"
				    "Host: localhost\r\n"
				    "Content-Type: application/json\r\n"
				    "Content-Length: %zu\r\n\r\n",
				    strlen(ctx->body));
		evbuffer_add(out, ctx->body, strlen(ctx->body));
		free(ctx->body);
		ctx->body = NULL;
		bufferevent_disable(bev, EV_READ);
	} else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		free(ctx->body); // safe if NULL
		free(ctx);
		bufferevent_free(bev);
	}
}

// Fire-and-forget POST of the link status to pv-ctrl. Called after each
// reconcile pass. Failures are logged but don't block the daemon.
static void post_status(void)
{
	char *body = build_status_json();
	if (!body)
		return;

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, PV_CTRL_SOCKET, sizeof(sun.sun_path) - 1);

	struct bufferevent *bev = bufferevent_socket_new(g_base, -1,
							 BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		free(body);
		return;
	}
	struct status_post_ctx *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		bufferevent_free(bev);
		free(body);
		return;
	}
	ctx->body = body;
	bufferevent_setcb(bev, NULL, NULL, status_event_cb, ctx);
	bufferevent_enable(bev, EV_WRITE);
	if (bufferevent_socket_connect(bev, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		bufferevent_free(bev);
		free(ctx->body);
		free(ctx);
	}
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

	// After kicking the graph fetch, also push current link health back
	// to pv-ctrl. This is decoupled from the fetch (no ordering needed):
	// status reflects the previous reconcile pass, the new fetch starts
	// the next one, both async via libevent.
	post_status();

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

	// Service-IP layer: bring up the pv-services bridge and our nft
	// table before any link reconciles. Both are idempotent so a crash-
	// restart picks up cleanly. Failure here is logged but non-fatal:
	// legacy unix-socket links still work, only service-IP links would
	// fail to establish (and thus surface unhealthy via last_error).
	if (pvx_services_bridge_up() != 0)
		fprintf(stderr,
			"pv-xconnect: pv-services bridge bring-up failed; service-IP links will fail\n");
	if (pvx_services_nft_init() != 0)
		fprintf(stderr,
			"pv-xconnect: nft init failed; TCP fast-path DNAT unavailable\n");

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

	// Tear down service-IP infrastructure before exiting so the bridge,
	// nft rules, and ClusterIP /32 addresses don't outlive the daemon.
	pvx_services_nft_teardown();
	pvx_services_bridge_down();

	event_free(g_reconcile_timer);
	event_free(signal_event);
	event_free(term_event);
	event_base_free(g_base);

	return 0;
}
