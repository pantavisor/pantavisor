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

/*
 * pv-devicepass: Device-side management container for DevicePass.ai
 *
 * Provides:
 *  - HTTP API on Unix socket for container management (wraps pv-ctrl)
 *  - WebSocket tunnel client for cloud connectivity
 *  - Reverse proxy to container REST services (discovered via xconnect-graph)
 *  - Skill/service manifest collection
 *  - Identity header injection (X-DevicePass-Verified-*)
 *
 * Both HTTP and tunnel transports dispatch through agent-ops for
 * transport-agnostic operation handling.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <getopt.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/http.h>
#include <jsmn/jsmnutil.h>

#include "agent-ops.h"
#include "ctrl-client.h"
#include "proxy.h"
#include "tunnel.h"
#include "../utils/json.h"

#define API_SOCKET_PATH "/run/pv-devicepass/api.sock"
#define GRAPH_POLL_INTERVAL_SEC 5
#define DEFAULT_IDENTITY_DIR "/var/lib/devicepass"

/* Globals */
struct event_base *g_base;
struct service_route *g_routes;
char *g_device_address;
char *g_guardian_address;
static struct event *g_graph_timer;
static struct evhttp *g_http;

/* --- Signal handling --- */

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
	printf("pv-devicepass: caught signal, shutting down\n");
	event_base_loopexit(g_base, NULL);
}

/* --- HTTP transport: thin wrappers around agent_op_dispatch --- */

struct http_op_ctx {
	struct evhttp_request *req;
};

static void http_op_result(int status, const char *body, size_t body_len,
			   void *ctx)
{
	struct http_op_ctx *hctx = ctx;
	struct evbuffer *reply = evbuffer_new();

	if (!reply) {
		evhttp_send_error(hctx->req, 500, "Internal Server Error");
		free(hctx);
		return;
	}

	if (body && body_len > 0)
		evbuffer_add(reply, body, body_len);

	evhttp_add_header(evhttp_request_get_output_headers(hctx->req),
			  "Content-Type", "application/json");

	if (status >= 400)
		evhttp_send_error(hctx->req, status, "Error");
	else
		evhttp_send_reply(hctx->req, status, "OK", reply);

	evbuffer_free(reply);
	free(hctx);
}

static const char *http_method_str(enum evhttp_cmd_type cmd)
{
	switch (cmd) {
	case EVHTTP_REQ_GET:
		return "GET";
	case EVHTTP_REQ_POST:
		return "POST";
	case EVHTTP_REQ_PUT:
		return "PUT";
	case EVHTTP_REQ_DELETE:
		return "DELETE";
	default:
		return "GET";
	}
}

/*
 * Generic HTTP request handler — dispatches all requests through agent-ops.
 */
static void http_dispatch_handler(struct evhttp_request *req, void *arg)
{
	const char *uri = evhttp_request_get_uri(req);
	const char *method = http_method_str(evhttp_request_get_command(req));

	/* Extract request body if present */
	struct evbuffer *input = evhttp_request_get_input_buffer(req);
	size_t body_len = input ? evbuffer_get_length(input) : 0;
	char *body_str = NULL;

	if (body_len > 0) {
		body_str = malloc(body_len + 1);
		if (!body_str) {
			evhttp_send_error(req, 500, "Internal Server Error");
			return;
		}
		evbuffer_copyout(input, body_str, body_len);
		body_str[body_len] = '\0';
	}

	struct http_op_ctx *hctx = calloc(1, sizeof(*hctx));
	if (!hctx) {
		free(body_str);
		evhttp_send_error(req, 500, "Internal Server Error");
		return;
	}
	hctx->req = req;

	agent_op_dispatch(g_base, method, uri, body_str, body_len,
			  http_op_result, hctx);

	free(body_str);
}

/* --- xconnect-graph polling and routing table --- */

static void graph_response_cb(int status, const char *body, size_t body_len,
			       void *ctx)
{
	if (status != 200 || !body || body_len == 0) {
		fprintf(stderr,
			"pv-devicepass: graph fetch failed (status=%d)\n", status);
		return;
	}

	jsmntok_t *tokv;
	int tokc;

	if (jsmnutil_parse_json(body, &tokv, &tokc) < 0) {
		fprintf(stderr, "pv-devicepass: failed to parse graph JSON\n");
		return;
	}

	if (tokv->type != JSMN_ARRAY) {
		fprintf(stderr, "pv-devicepass: graph JSON is not an array\n");
		free(tokv);
		return;
	}

	/* Rebuild routing table */
	struct service_route *new_routes = NULL;
	int count = jsmnutil_array_count(body, tokv);
	jsmntok_t **items = jsmnutil_get_array_toks(body, tokv);

	(void)count;

	if (!items) {
		free(tokv);
		return;
	}

	for (int i = 0; items[i]; i++) {
		jsmntok_t *itok = items[i];
		int obj_tokc;

		if (items[i + 1])
			obj_tokc = items[i + 1] - items[i];
		else
			obj_tokc = (tokv + tokc) - itok;

		char *type = pv_json_get_value(body, "type", itok, obj_tokc);
		if (!type)
			continue;

		/* Only track REST services for proxying */
		if (strcmp(type, "rest") != 0) {
			free(type);
			continue;
		}

		char *name =
			pv_json_get_value(body, "name", itok, obj_tokc);
		char *socket =
			pv_json_get_value(body, "socket", itok, obj_tokc);
		int provider_pid =
			pv_json_get_value_int(body, "provider_pid", itok,
					   obj_tokc);

		if (name && socket) {
			routes_add(&new_routes, name, type, provider_pid,
				   socket);
		}

		free(type);
		free(name);
		free(socket);
	}

	jsmnutil_tokv_free(items);
	free(tokv);

	/* Swap routing table */
	routes_free(&g_routes);
	g_routes = new_routes;
}

static void graph_poll(void)
{
	ctrl_request(g_base, "GET", "/xconnect-graph", NULL, 0,
		     graph_response_cb, NULL);
}

static void graph_timer_cb(evutil_socket_t fd, short event, void *arg)
{
	graph_poll();

	/* Update guardian address from tunnel auth */
	const char *guardian = tunnel_get_guardian();
	if (guardian && !g_guardian_address) {
		g_guardian_address = strdup(guardian);
		printf("pv-devicepass: guardian address set: %s\n",
		       g_guardian_address);
	}

	struct timeval tv = { GRAPH_POLL_INTERVAL_SEC, 0 };
	evtimer_add(g_graph_timer, &tv);
}

/* --- HTTP server on Unix socket --- */

static int setup_http_server(const char *socket_path)
{
	/* Create directory for socket */
	char *dir = strdup(socket_path);
	if (dir) {
		char *last_slash = strrchr(dir, '/');
		if (last_slash) {
			*last_slash = '\0';
			mkdir(dir, 0755);
		}
		free(dir);
	}

	/* Remove stale socket */
	unlink(socket_path);

	/* Create Unix socket */
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "pv-devicepass: socket() failed: %s\n",
			strerror(errno));
		return -1;
	}

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, socket_path, sizeof(sun.sun_path) - 1);

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		fprintf(stderr, "pv-devicepass: bind(%s) failed: %s\n",
			socket_path, strerror(errno));
		close(fd);
		return -1;
	}

	if (listen(fd, 16) < 0) {
		fprintf(stderr, "pv-devicepass: listen() failed: %s\n",
			strerror(errno));
		close(fd);
		return -1;
	}

	evutil_make_socket_nonblocking(fd);

	/* Create evhttp and bind to our fd */
	g_http = evhttp_new(g_base);
	if (!g_http) {
		fprintf(stderr, "pv-devicepass: evhttp_new() failed\n");
		close(fd);
		return -1;
	}

	/* Allow all HTTP methods for proxying */
	evhttp_set_allowed_methods(g_http,
				   EVHTTP_REQ_GET | EVHTTP_REQ_POST |
					   EVHTTP_REQ_PUT |
					   EVHTTP_REQ_DELETE);

	/* All requests go through the unified dispatch handler */
	evhttp_set_gencb(g_http, http_dispatch_handler, NULL);

	if (evhttp_accept_socket(g_http, fd) < 0) {
		fprintf(stderr, "pv-devicepass: evhttp_accept_socket() failed\n");
		evhttp_free(g_http);
		close(fd);
		return -1;
	}

	printf("pv-devicepass: listening on %s\n", socket_path);
	return 0;
}

/* --- Main --- */

/*
 * Load device identity from identity directory.
 * Reads device.address and stores path to device.key.
 * Returns key_path on success (caller must free), NULL on failure.
 */
static char *load_identity(const char *identity_dir, char **out_address)
{
	char addr_path[512];
	char key_path[512];
	char addr_buf[128];

	snprintf(addr_path, sizeof(addr_path), "%s/device.address",
		 identity_dir);
	snprintf(key_path, sizeof(key_path), "%s/device.key", identity_dir);

	/* Check key file exists */
	if (access(key_path, R_OK) != 0) {
		fprintf(stderr,
			"pv-devicepass: identity key not found: %s\n",
			key_path);
		return NULL;
	}

	/* Read address */
	FILE *fp = fopen(addr_path, "r");
	if (!fp) {
		fprintf(stderr,
			"pv-devicepass: identity address not found: %s\n",
			addr_path);
		return NULL;
	}
	if (!fgets(addr_buf, sizeof(addr_buf), fp)) {
		fprintf(stderr,
			"pv-devicepass: empty address file: %s\n", addr_path);
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	/* Trim whitespace */
	size_t len = strlen(addr_buf);
	while (len > 0 && (addr_buf[len - 1] == '\n' ||
			   addr_buf[len - 1] == '\r' ||
			   addr_buf[len - 1] == ' '))
		addr_buf[--len] = '\0';

	*out_address = strdup(addr_buf);
	printf("pv-devicepass: loaded identity: %s\n", addr_buf);
	return strdup(key_path);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"  -s, --socket PATH          API socket path (default: %s)\n"
		"  -T, --tunnel-socket PATH   Tunnel server Unix socket path\n"
		"  -U, --tunnel-url HOST:PORT Tunnel server TCP address\n"
		"  -I, --identity-dir PATH    Device identity dir (default: %s)\n"
		"  -h, --help                 Show this help\n",
		prog, API_SOCKET_PATH, DEFAULT_IDENTITY_DIR);
}

int main(int argc, char **argv)
{
	const char *socket_path = API_SOCKET_PATH;
	const char *tunnel_socket = NULL;
	const char *tunnel_url = NULL;
	const char *identity_dir = DEFAULT_IDENTITY_DIR;

	static struct option long_options[] = {
		{ "socket", required_argument, 0, 's' },
		{ "tunnel-socket", required_argument, 0, 'T' },
		{ "tunnel-url", required_argument, 0, 'U' },
		{ "identity-dir", required_argument, 0, 'I' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "s:T:U:I:h", long_options,
				  NULL)) != -1) {
		switch (opt) {
		case 's':
			socket_path = optarg;
			break;
		case 'T':
			tunnel_socket = optarg;
			break;
		case 'U':
			tunnel_url = optarg;
			break;
		case 'I':
			identity_dir = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	printf("pv-devicepass v1.0 starting...\n");

	g_base = event_base_new();
	if (!g_base) {
		fprintf(stderr, "pv-devicepass: event_base_new() failed\n");
		return 1;
	}

	/* Signal handlers */
	struct event *sig_int =
		evsignal_new(g_base, SIGINT, signal_cb, NULL);
	struct event *sig_term =
		evsignal_new(g_base, SIGTERM, signal_cb, NULL);

	if (!sig_int || event_add(sig_int, NULL) < 0 || !sig_term ||
	    event_add(sig_term, NULL) < 0) {
		fprintf(stderr, "pv-devicepass: signal setup failed\n");
		return 1;
	}

	/* Set up HTTP server */
	if (setup_http_server(socket_path) < 0) {
		return 1;
	}

	/* Load device identity */
	char *key_path = NULL;
	char *device_addr = NULL;
	key_path = load_identity(identity_dir, &device_addr);
	if (key_path && device_addr) {
		g_device_address = device_addr;
	} else {
		fprintf(stderr,
			"pv-devicepass: no identity found in %s, "
			"tunnel auth will be unavailable\n",
			identity_dir);
	}

	/* Set up tunnel client if configured (--tunnel-url takes priority) */
	const char *tunnel_target = tunnel_url ? tunnel_url : tunnel_socket;
	if (tunnel_target) {
		if (tunnel_init(g_base, tunnel_target, key_path,
				device_addr) < 0) {
			fprintf(stderr,
				"pv-devicepass: tunnel init failed, continuing without tunnel\n");
		}
	}
	free(key_path);

	/* Set up xconnect-graph polling timer */
	g_graph_timer = evtimer_new(g_base, graph_timer_cb, NULL);
	if (g_graph_timer) {
		struct timeval tv = { GRAPH_POLL_INTERVAL_SEC, 0 };
		evtimer_add(g_graph_timer, &tv);
	}

	/* Initial graph fetch */
	graph_poll();

	printf("pv-devicepass: entering event loop\n");
	event_base_dispatch(g_base);

	/* Cleanup */
	printf("pv-devicepass: shutting down\n");
	tunnel_shutdown();
	routes_free(&g_routes);
	if (g_graph_timer)
		event_free(g_graph_timer);
	if (g_http)
		evhttp_free(g_http);
	event_free(sig_int);
	event_free(sig_term);
	event_base_free(g_base);
	unlink(socket_path);
	free(g_device_address);
	free(g_guardian_address);

	return 0;
}
