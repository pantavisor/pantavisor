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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/limits.h>
#include "../include/xconnect.h"
#include "../dbus_codec.h"
#include "../dbus_activation.h"
#include "proxy_common.h"

#define MODULE_NAME "pvx-dbus"

struct dbus_proxy_session {
	struct pvx_proxy proxy; // must stay first: shared callbacks cast to it
	struct pvx_link *link;
	int authenticated;
	// On-demand activation gating (post-auth, client->bus direction):
	int passthrough; // parsing gave up -> splice the rest untouched
	int holding; // a cold method_call is held awaiting activation
	uint32_t held_serial; // its serial, for a synthesized error reply
	struct evbuffer *held; // the held message bytes
};

static void hex_encode(const char *src, char *dst, size_t dst_size, size_t len)
{
	for (size_t i = 0; i < len && (i * 2 + 2) < dst_size; i++) {
		snprintf(dst + (i * 2), 3, "%02x", (unsigned char)src[i]);
	}
	dst[len * 2] = '\0';
}

static int lookup_uid_in_provider(const char *username, int provider_pid)
{
	char path[PATH_MAX];
	char line[1024];
	int uid = -1;

	if (!username)
		return -1;

	// If numeric, return directly
	if (username[0] >= '0' && username[0] <= '9') {
		char *endptr;
		long val = strtol(username, &endptr, 10);
		if (*endptr == '\0' && val >= 0 && val <= INT_MAX)
			return (int)val;
		return -1;
	}

	snprintf(path, sizeof(path), "/proc/%d/root/etc/passwd", provider_pid);
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		char *name = strtok(line, ":");
		strtok(NULL, ":"); // password
		char *uid_s = strtok(NULL, ":");
		if (name && uid_s &&
		    strncmp(name, username, strlen(username)) == 0 &&
		    name[strlen(username)] == '\0') {
			char *endptr;
			long val = strtol(uid_s, &endptr, 10);
			if (val >= 0 && val <= INT_MAX)
				uid = (int)val;
			break;
		}
	}
	fclose(f);
	return uid;
}

static void dbus_on_ready(void *ctx);
static void dbus_on_fail(void *ctx, const char *err, const char *msg);

// Forward `n` bytes from the client input to the provider (bus) output.
static void dbus_forward(struct dbus_proxy_session *sess, size_t n)
{
	evbuffer_remove_buffer(bufferevent_get_input(sess->proxy.be_client),
			       bufferevent_get_output(sess->proxy.be_provider),
			       n);
}

// Post-auth client->bus pump: frame each D-Bus message and, for a method_call to
// an on-demand activatable name with no current owner, hold it and trigger
// activation instead of splicing. Everything else forwards untouched.
static void dbus_process_client(struct dbus_proxy_session *sess)
{
	if (sess->holding)
		return;

	struct evbuffer *src = bufferevent_get_input(sess->proxy.be_client);
	for (;;) {
		if (sess->passthrough) {
			dbus_forward(sess, evbuffer_get_length(src));
			return;
		}
		size_t avail = evbuffer_get_length(src);
		if (avail < 16)
			return;

		unsigned char *data = evbuffer_pullup(src, -1);
		struct pv_dbus_msg m;
		int r = pv_dbus_msg_parse(data, avail, &m);
		if (r == 0)
			return; // need more bytes to frame this message
		if (r < 0) {
			// Not a message shape we model; stop gating this
			// connection and splice the rest verbatim so a working
			// client is never broken by our parser.
			fprintf(stderr,
				"%s: unparseable client frame, passthrough\n",
				MODULE_NAME);
			sess->passthrough = 1;
			continue;
		}

		if (m.type == PV_DBUS_TYPE_METHOD_CALL && m.destination[0] &&
		    !(m.flags & PV_DBUS_FLAG_NO_AUTO_START) &&
		    pvx_act_is_activatable(m.destination) &&
		    !pvx_act_name_has_owner(m.destination)) {
			printf("%s: holding cold call to %s (serial %u) — activating\n",
			       MODULE_NAME, m.destination, m.serial);
			if (!sess->held)
				sess->held = evbuffer_new();
			sess->held_serial = m.serial;
			evbuffer_remove_buffer(src, sess->held, m.total_len);
			sess->holding = 1;
			bufferevent_disable(sess->proxy.be_client, EV_READ);
			if (pvx_act_hold(m.destination, dbus_on_ready,
					 dbus_on_fail, sess) < 0) {
				// Could not register: forward best-effort and let
				// the bus answer (likely NameHasNoOwner).
				sess->holding = 0;
				bufferevent_enable(sess->proxy.be_client,
						   EV_READ);
				evbuffer_add_buffer(
					bufferevent_get_output(
						sess->proxy.be_provider),
					sess->held);
				continue;
			}
			return; // wait for ready/fail
		}

		dbus_forward(sess, m.total_len);
	}
}

// Activation succeeded (name now owned): flush the held call to the bus and
// resume pumping.
static void dbus_on_ready(void *ctx)
{
	struct dbus_proxy_session *sess = ctx;
	sess->holding = 0;
	if (sess->held)
		evbuffer_add_buffer(
			bufferevent_get_output(sess->proxy.be_provider),
			sess->held);
	bufferevent_enable(sess->proxy.be_client, EV_READ);
	dbus_process_client(sess);
}

// Activation failed/timed out: answer the held call with a typed D-Bus error so
// the client fails cleanly instead of hanging, then resume pumping.
static void dbus_on_fail(void *ctx, const char *err, const char *msg)
{
	struct dbus_proxy_session *sess = ctx;
	sess->holding = 0;
	uint8_t out[512];
	size_t n = pv_dbus_build_error(out, sizeof(out), 1, sess->held_serial,
				       err, msg);
	if (n)
		evbuffer_add(bufferevent_get_output(sess->proxy.be_client), out,
			     n);
	if (sess->held)
		evbuffer_drain(sess->held, evbuffer_get_length(sess->held));
	bufferevent_enable(sess->proxy.be_client, EV_READ);
	dbus_process_client(sess);
}

// Session teardown hook (invoked by pvx_proxy_free): drop any pending activation
// waiter pointing at this session and free the held buffer.
static void dbus_session_on_free(struct pvx_proxy *p)
{
	struct dbus_proxy_session *sess = (struct dbus_proxy_session *)p;
	pvx_act_cancel(sess);
	if (sess->held) {
		evbuffer_free(sess->held);
		sess->held = NULL;
	}
}

static void dbus_client_read_cb(struct bufferevent *bev, void *arg)
{
	struct dbus_proxy_session *sess = arg;

	if (sess->authenticated) {
		// Past the auth handshake: gate cold calls to activatable names,
		// otherwise splice through.
		dbus_process_client(sess);
		return;
	}

	struct evbuffer *src = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(src);
	if (len == 0)
		return;

	// D-Bus authentication starts with a single NULL byte
	unsigned char *data = evbuffer_pullup(src, 1);
	if (data[0] == '\0') {
		evbuffer_add(bufferevent_get_output(sess->proxy.be_provider),
			     "\0", 1);
		evbuffer_drain(src, 1);
		if (evbuffer_get_length(src) == 0)
			return;
	}

	char *line = evbuffer_readln(src, NULL, EVBUFFER_EOL_CRLF);
	if (!line)
		return;

	if (strncmp(line, "AUTH EXTERNAL", 13) == 0) {
		// The daemon authenticates our provider connection by its kernel
		// credential (SO_PEERCRED == the role uid we set in
		// dbus_on_accept), so the identity the client puts on the wire
		// only needs to not contradict it. Two client styles exist:
		const char *ext_arg = line + 13;
		while (*ext_arg == ' ')
			ext_arg++;

		if (*ext_arg != '\0') {
			// One-step (e.g. libdbus/dbus-send): the client asserts
			// its own uid inline and expects an immediate OK. That
			// uid differs from our SO_PEERCRED and would be rejected,
			// so rewrite it to the role uid.
			char uid_str[32];
			char hex_identity[64];
			const char *role =
				sess->link->role ? sess->link->role : "nobody";
			// Hosted system bus put the resolved uid on the link;
			// the legacy per-provider path keeps the passwd lookup.
			int uid =
				sess->link->uid >= 0 ?
					sess->link->uid :
					lookup_uid_in_provider(
						role, sess->link->provider_pid);

			if (uid < 0) {
				printf("%s: Role '%s' not found in provider, using UID 65534 (nobody)\n",
				       MODULE_NAME, role);
				uid = 65534;
			}

			snprintf(uid_str, sizeof(uid_str), "%d", uid);
			hex_encode(uid_str, hex_identity, sizeof(hex_identity),
				   strlen(uid_str));

			printf("%s: Masquerading D-Bus identity as role '%s' (UID %d) for service %s\n",
			       MODULE_NAME, role, uid, sess->link->name);

			evbuffer_add_printf(
				bufferevent_get_output(sess->proxy.be_provider),
				"AUTH EXTERNAL %s\r\n", hex_identity);
		} else {
			// Multi-step (e.g. GDBus/pydbus): the client sends a bare
			// AUTH EXTERNAL and an empty identity in the following
			// DATA line, asking the daemon to use SO_PEERCRED — which
			// is already the role uid. Forward verbatim and let the
			// rest of the handshake splice through untouched.
			evbuffer_add(
				bufferevent_get_output(sess->proxy.be_provider),
				"AUTH EXTERNAL\r\n", 15);
		}
		sess->authenticated = 1;
	} else if (strncmp(line, "BEGIN", 5) == 0) {
		evbuffer_add(bufferevent_get_output(sess->proxy.be_provider),
			     "BEGIN\r\n", 7);
		sess->authenticated = 1;
	} else {
		// Pass-through anything else during auth
		evbuffer_add(bufferevent_get_output(sess->proxy.be_provider),
			     line, strlen(line));
		evbuffer_add(bufferevent_get_output(sess->proxy.be_provider),
			     "\r\n", 2);
	}

	free(line);

	if (evbuffer_get_length(src) > 0)
		dbus_client_read_cb(bev, arg);
}

static void dbus_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
			   struct sockaddr *address, int socklen, void *arg)
{
	struct pvx_link *link = arg;
	struct event_base *base = pvx_get_base();
	char provider_path[PATH_MAX];
	(void)listener;
	(void)address;
	(void)socklen;

	if (!link->name || !link->provider_socket) {
		close(fd);
		return;
	}

	printf("%s: Accepted connection for service %s from pid %d\n",
	       MODULE_NAME, link->name, link->consumer_pid);

	if (link->provider_pid > 0) {
		snprintf(provider_path, sizeof(provider_path),
			 "/proc/%d/root%s", link->provider_pid,
			 link->provider_socket);
	} else {
		strncpy(provider_path, link->provider_socket,
			sizeof(provider_path) - 1);
		provider_path[sizeof(provider_path) - 1] = '\0';
	}
	struct dbus_proxy_session *sess = calloc(1, sizeof(*sess));
	if (!sess) {
		fprintf(stderr, "Could not allocate proxy session\n");
		close(fd);
		return;
	}
	sess->link = link;
	sess->proxy.on_free = dbus_session_on_free;

	// DEFER_CALLBACKS keeps bufferevent_socket_connect() from invoking our
	// event callback re-entrantly on an immediate connect failure (which
	// would free the session while we still use it below), and makes
	// freeing a bufferevent from within its own callback safe.
	sess->proxy.be_client = bufferevent_socket_new(
		base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	sess->proxy.be_provider = bufferevent_socket_new(
		base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	// Client side runs the dbus auth filter first, then plain splicing;
	// provider side and both event callbacks are the shared proxy core.
	bufferevent_setcb(sess->proxy.be_client, dbus_client_read_cb, NULL,
			  pvx_proxy_event_cb, sess);
	bufferevent_setcb(sess->proxy.be_provider, pvx_proxy_read_cb, NULL,
			  pvx_proxy_event_cb, sess);

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, provider_path, sizeof(sun.sun_path) - 1);

	// Hosted system bus: the daemon authenticates connections by their kernel
	// credential (SO_PEERCRED, which is the *real* uid), so asserting a role
	// uid over SASL EXTERNAL while staying root is rejected. Become the role
	// uid across the connect() so the provider-side socket carries it; the
	// credential is frozen at connect time, so we can restore root right after
	// and keep splicing as root. Keep the saved uid at 0 so the restore is
	// permitted. Single-threaded event loop => nothing runs in the window.
	// Legacy per-provider links (uid < 0) keep the old behaviour untouched.
	int role_uid = sess->link->uid;
	if (role_uid >= 0 && setresuid(role_uid, role_uid, 0) < 0) {
		fprintf(stderr, "%s: setresuid(%d) failed: %s\n", MODULE_NAME,
			role_uid, strerror(errno));
		pvx_proxy_free(&sess->proxy);
		return;
	}

	int connect_rc = bufferevent_socket_connect(
		sess->proxy.be_provider, (struct sockaddr *)&sun, sizeof(sun));

	if (role_uid >= 0 && setresuid(0, 0, 0) < 0) {
		// Lost the ability to regain root: the proxy can no longer
		// service other roles correctly, so fail hard rather than run
		// with the wrong identity.
		fprintf(stderr, "%s: setresuid restore to root failed: %s\n",
			MODULE_NAME, strerror(errno));
		abort();
	}

	if (connect_rc < 0) {
		fprintf(stderr, "Could not connect to provider %s\n",
			provider_path);
		pvx_proxy_free(&sess->proxy);
		return;
	}

	bufferevent_enable(sess->proxy.be_client, EV_READ | EV_WRITE);
	bufferevent_enable(sess->proxy.be_provider, EV_READ | EV_WRITE);
}

static int dbus_on_link_added(struct pvx_link *link)
{
	struct event_base *base = pvx_get_base();
	int fd;

	if (!base) {
		fprintf(stderr, "%s: event base is NULL\n", MODULE_NAME);
		return -1;
	}

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
		// World-connectable like a real system bus socket; the role
		// masquerade + bus policy enforce access, not the socket mode.
		if (chmod(link->consumer_socket, 0666) < 0)
			perror("chmod socket");
		evutil_make_socket_nonblocking(fd);
	}

	if (fd < 0)
		return -1;

	link->listener = evconnlistener_new(base, dbus_on_accept, link,
					    LEV_OPT_CLOSE_ON_FREE, -1, fd);

	if (!link->listener) {
		fprintf(stderr, "Could not create listener for %s\n",
			link->consumer_socket);
		close(fd);
		return -1;
	}

	// Survive fd exhaustion instead of busy-looping on accept().
	pvx_listener_set_emfile_backoff(link->listener);

	return 0;
}
struct pvx_plugin pvx_plugin_dbus = { .type = "dbus",
				      .on_link_added = dbus_on_link_added,
				      .on_accept = dbus_on_accept };
