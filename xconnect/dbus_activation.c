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
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <picohttpparser.h>

#include "include/xconnect.h"
#include "dbus_codec.h"
#include "dbus_activation.h"

#define PV_CTRL_SOCKET "/run/pantavisor/pv/pv-ctrl"

// Bound a held activation below libdbus' default reply timeout (~25s) so the
// client gets our typed error rather than an opaque libdbus timeout.
#define ACT_TIMEOUT_SEC 20
#define MON_RETRY_SEC 3

// Fixed serials for the monitor's own requests, so replies are identifiable.
#define MON_SERIAL_HELLO 1
#define MON_SERIAL_LISTNAMES 2
#define MON_SERIAL_ADDMATCH 3

enum mon_state { MON_DOWN = 0, MON_AUTH, MON_RUNNING };

struct name_entry {
	char *name;
	struct dl_list list;
};

struct waiter {
	char *name;
	pvx_act_ready_cb ready;
	pvx_act_fail_cb fail;
	void *ctx;
	struct event *timer;
	struct dl_list list;
};

static bool g_inited;
static struct dl_list g_activatable; // active set (names)
static struct dl_list g_pending; // built during a reconcile pass
static struct dl_list g_owned; // names with a current owner (per monitor)
static struct dl_list g_waiters;
static char g_bus_socket[PATH_MAX];
static struct bufferevent *g_mon;
static enum mon_state g_mon_state;
static struct event *g_mon_retry;

static void ensure_init(void)
{
	if (g_inited)
		return;
	dl_list_init(&g_activatable);
	dl_list_init(&g_pending);
	dl_list_init(&g_owned);
	dl_list_init(&g_waiters);
	g_inited = true;
}

// --- small name-set helpers ------------------------------------------------

static bool set_contains(struct dl_list *set, const char *name)
{
	struct name_entry *e, *t;
	dl_list_for_each_safe(e, t, set, struct name_entry, list)
	{
		if (!strcmp(e->name, name))
			return true;
	}
	return false;
}

static void set_add(struct dl_list *set, const char *name)
{
	if (set_contains(set, name))
		return;
	struct name_entry *e = calloc(1, sizeof(*e));
	if (!e)
		return;
	e->name = strdup(name);
	dl_list_init(&e->list);
	dl_list_add(set, &e->list);
}

static void set_remove(struct dl_list *set, const char *name)
{
	struct name_entry *e, *t;
	dl_list_for_each_safe(e, t, set, struct name_entry, list)
	{
		if (!strcmp(e->name, name)) {
			dl_list_del(&e->list);
			free(e->name);
			free(e);
			return;
		}
	}
}

static void set_clear(struct dl_list *set)
{
	struct name_entry *e, *t;
	dl_list_for_each_safe(e, t, set, struct name_entry, list)
	{
		dl_list_del(&e->list);
		free(e->name);
		free(e);
	}
}

// --- monitor connection ----------------------------------------------------

static void mon_connect(void);

static void mon_retry_cb(evutil_socket_t fd, short ev, void *arg)
{
	(void)fd;
	(void)ev;
	(void)arg;
	if (g_mon_state == MON_DOWN)
		mon_connect();
}

static void mon_schedule_retry(void)
{
	struct event_base *base = pvx_get_base();
	if (!base)
		return;
	if (!g_mon_retry)
		g_mon_retry = evtimer_new(base, mon_retry_cb, NULL);
	if (g_mon_retry) {
		struct timeval tv = { MON_RETRY_SEC, 0 };
		evtimer_add(g_mon_retry, &tv);
	}
}

static void mon_down(void)
{
	if (g_mon) {
		bufferevent_free(g_mon);
		g_mon = NULL;
	}
	g_mon_state = MON_DOWN;
	// Ownership is unknown while disconnected; a cold call then re-triggers
	// activation (idempotent) rather than trusting a stale owned-set.
	set_clear(&g_owned);
	mon_schedule_retry();
}

static void mon_send(const uint8_t *buf, size_t len)
{
	if (g_mon && len)
		evbuffer_add(bufferevent_get_output(g_mon), buf, len);
}

static void fire_ready(const char *name);

// Seed the owned-set from a ListNames method_return body ("as").
static void mon_seed_listnames(const uint8_t *buf, struct pv_dbus_msg *m)
{
	size_t p = m->body_off;
	if (p + 4 > m->total_len)
		return;
	uint32_t arrlen;
	memcpy(&arrlen, buf + p, 4); // little-endian host assumed on-device
	if (!m->little) {
		// normalize if wire is big-endian (rare)
		arrlen = ((arrlen & 0xff) << 24) | ((arrlen & 0xff00) << 8) |
			 ((arrlen & 0xff0000) >> 8) | ((arrlen >> 24) & 0xff);
	}
	p += 4;
	size_t end = p + arrlen;
	if (end > m->total_len)
		end = m->total_len;
	while (p < end) {
		char nm[PV_DBUS_STR_MAX];
		if (!pv_dbus_read_string(buf, end, &p, m->little, nm,
					 sizeof(nm)))
			break;
		if (nm[0] && nm[0] != ':') // skip unique connection names
			set_add(&g_owned, nm);
	}
}

static void mon_dispatch(const uint8_t *buf, struct pv_dbus_msg *m)
{
	if (m->type == PV_DBUS_TYPE_METHOD_RETURN &&
	    m->reply_serial == MON_SERIAL_LISTNAMES) {
		mon_seed_listnames(buf, m);
		return;
	}
	if (m->type == PV_DBUS_TYPE_SIGNAL &&
	    !strcmp(m->member, "NameOwnerChanged")) {
		char name[PV_DBUS_STR_MAX], new_owner[PV_DBUS_STR_MAX];
		if (!pv_dbus_parse_name_owner_changed(buf, m->total_len, name,
						      new_owner))
			return;
		if (name[0] == ':') // unique names aren't well-known services
			return;
		if (new_owner[0]) {
			set_add(&g_owned, name);
			fire_ready(name);
		} else {
			set_remove(&g_owned, name);
		}
	}
}

static void mon_read_cb(struct bufferevent *bev, void *arg)
{
	(void)arg;
	struct evbuffer *in = bufferevent_get_input(bev);

	// SASL phase is line-based (CRLF) until we send BEGIN.
	while (g_mon_state == MON_AUTH) {
		char *line = evbuffer_readln(in, NULL, EVBUFFER_EOL_CRLF);
		if (!line)
			return;
		if (!strncmp(line, "OK", 2)) {
			uint8_t out[512];
			size_t n;
			mon_send((const uint8_t *)"BEGIN\r\n", 7);
			n = pv_dbus_build_call(out, sizeof(out),
					       MON_SERIAL_HELLO, "Hello", NULL);
			mon_send(out, n);
			n = pv_dbus_build_call(out, sizeof(out),
					       MON_SERIAL_LISTNAMES,
					       "ListNames", NULL);
			mon_send(out, n);
			n = pv_dbus_build_call(
				out, sizeof(out), MON_SERIAL_ADDMATCH,
				"AddMatch",
				"type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'");
			mon_send(out, n);
			g_mon_state = MON_RUNNING;
			printf("pvx-act: ownership monitor running\n");
		} else if (!strncmp(line, "REJECTED", 8) ||
			   !strncmp(line, "ERROR", 5)) {
			free(line);
			mon_down();
			return;
		}
		// ignore other SASL lines (e.g. AGREE_UNIX_FD)
		free(line);
	}

	// Binary D-Bus phase: frame and dispatch complete messages.
	while (g_mon_state == MON_RUNNING) {
		size_t avail = evbuffer_get_length(in);
		if (avail < 16)
			return;
		unsigned char *data = evbuffer_pullup(in, -1);
		struct pv_dbus_msg m;
		int r = pv_dbus_msg_parse(data, avail, &m);
		if (r == 0)
			return; // need more bytes
		if (r < 0) {
			mon_down();
			return;
		}
		mon_dispatch(data, &m);
		evbuffer_drain(in, m.total_len);
	}
}

static void mon_event_cb(struct bufferevent *bev, short events, void *arg)
{
	(void)arg;
	if (events & BEV_EVENT_CONNECTED) {
		// EXTERNAL auth as our real uid (root on host => "0"); the bus
		// authenticates by SO_PEERCRED. Leading NUL then the AUTH line.
		const char *hello = "\0AUTH EXTERNAL 30\r\n"; // 30 = hex("0")
		evbuffer_add(bufferevent_get_output(bev), hello, 18);
		g_mon_state = MON_AUTH;
	} else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		mon_down();
	}
}

static void mon_connect(void)
{
	struct event_base *base = pvx_get_base();
	if (!base || g_bus_socket[0] == '\0' || g_mon)
		return;

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, g_bus_socket, sizeof(sun.sun_path) - 1);

	g_mon = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!g_mon)
		return;
	bufferevent_setcb(g_mon, mon_read_cb, NULL, mon_event_cb, NULL);
	bufferevent_enable(g_mon, EV_READ | EV_WRITE);
	g_mon_state = MON_AUTH;
	if (bufferevent_socket_connect(g_mon, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		mon_down();
	}
}

// --- reconcile API ---------------------------------------------------------

void pvx_act_reconcile_begin(void)
{
	ensure_init();
	set_clear(&g_pending);
}

void pvx_act_reconcile_add(const char *name, const char *bus_socket)
{
	ensure_init();
	if (!name || !name[0])
		return;
	set_add(&g_pending, name);
	if (bus_socket && bus_socket[0] && g_bus_socket[0] == '\0')
		strncpy(g_bus_socket, bus_socket, sizeof(g_bus_socket) - 1);
}

void pvx_act_reconcile_end(void)
{
	ensure_init();
	// Swap pending -> active.
	set_clear(&g_activatable);
	struct name_entry *e, *t;
	dl_list_for_each_safe(e, t, &g_pending, struct name_entry, list)
	{
		dl_list_del(&e->list);
		dl_list_add(&g_activatable, &e->list);
	}
	// Bring the monitor up once we know the bus socket and have work.
	if (!dl_list_empty(&g_activatable) && g_bus_socket[0] &&
	    g_mon_state == MON_DOWN)
		mon_connect();
}

bool pvx_act_is_activatable(const char *name)
{
	if (!g_inited || !name)
		return false;
	return set_contains(&g_activatable, name);
}

bool pvx_act_name_has_owner(const char *name)
{
	if (!g_inited || !name)
		return false;
	return set_contains(&g_owned, name);
}

// --- waiters + activation trigger ------------------------------------------

static bool set_contains_waiter_name(const char *name)
{
	struct waiter *w, *t;
	dl_list_for_each_safe(w, t, &g_waiters, struct waiter, list)
	{
		if (!strcmp(w->name, name))
			return true;
	}
	return false;
}

static void waiter_free(struct waiter *w)
{
	dl_list_del(&w->list);
	if (w->timer) {
		evtimer_del(w->timer);
		event_free(w->timer);
	}
	free(w->name);
	free(w);
}

static void fire_ready(const char *name)
{
	struct waiter *w, *t;
	dl_list_for_each_safe(w, t, &g_waiters, struct waiter, list)
	{
		if (strcmp(w->name, name))
			continue;
		pvx_act_ready_cb cb = w->ready;
		void *ctx = w->ctx;
		waiter_free(w);
		if (cb)
			cb(ctx);
	}
}

static void fail_name(const char *name, const char *err, const char *msg)
{
	struct waiter *w, *t;
	dl_list_for_each_safe(w, t, &g_waiters, struct waiter, list)
	{
		if (strcmp(w->name, name))
			continue;
		pvx_act_fail_cb cb = w->fail;
		void *ctx = w->ctx;
		waiter_free(w);
		if (cb)
			cb(ctx, err, msg);
	}
}

static void waiter_timeout_cb(evutil_socket_t fd, short ev, void *arg)
{
	(void)fd;
	(void)ev;
	struct waiter *w = arg;
	pvx_act_fail_cb cb = w->fail;
	void *ctx = w->ctx;
	char name[PV_DBUS_STR_MAX];
	strncpy(name, w->name, sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	waiter_free(w);
	if (cb)
		cb(ctx, "org.freedesktop.DBus.Error.TimedOut",
		   "activation timed out waiting for the service to start");
	(void)name;
}

// One in-flight activation POST per name; on a non-2xx reply we fail that name's
// waiters. Success just leaves them waiting for NameOwnerChanged / timeout.
struct act_post {
	char *name;
};

static void act_post_read_cb(struct bufferevent *bev, void *ctx)
{
	struct act_post *ap = ctx;
	struct evbuffer *in = bufferevent_get_input(bev);
	size_t len = evbuffer_get_length(in);
	char *data = malloc(len + 1);
	if (data) {
		evbuffer_remove(in, data, len);
		data[len] = '\0';
		const char *msg;
		int minor, status;
		struct phr_header h[32];
		size_t msg_len, nh = 32;
		int pret = phr_parse_response(data, len, &minor, &status, &msg,
					      &msg_len, h, &nh, 0);
		if (pret > 0 && (status < 200 || status >= 300))
			fail_name(ap->name, "org.freedesktop.DBus.Error.Failed",
				  "activation request rejected by pantavisor");
		free(data);
	}
	free(ap->name);
	free(ap);
	bufferevent_free(bev);
}

static void act_post_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	struct act_post *ap = ctx;
	if (events & BEV_EVENT_CONNECTED) {
		char body[PV_DBUS_STR_MAX + 32];
		int blen = snprintf(body, sizeof(body), "{\"name\":\"%s\"}",
				    ap->name);
		evbuffer_add_printf(
			bufferevent_get_output(bev),
			"POST /xconnect/dbus/activate HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			blen, body);
	} else if (events & BEV_EVENT_ERROR) {
		// Could not even reach pv-ctrl: fail now rather than wait out
		// the timeout.
		fail_name(ap->name, "org.freedesktop.DBus.Error.Failed",
			  "could not reach pantavisor to activate service");
		free(ap->name);
		free(ap);
		bufferevent_free(bev);
	}
}

static void trigger_activation(const char *name)
{
	struct event_base *base = pvx_get_base();
	if (!base)
		return;
	struct act_post *ap = calloc(1, sizeof(*ap));
	if (!ap)
		return;
	ap->name = strdup(name);

	struct sockaddr_un sun;
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, PV_CTRL_SOCKET, sizeof(sun.sun_path) - 1);

	struct bufferevent *bev =
		bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		free(ap->name);
		free(ap);
		return;
	}
	bufferevent_setcb(bev, act_post_read_cb, NULL, act_post_event_cb, ap);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
	if (bufferevent_socket_connect(bev, (struct sockaddr *)&sun,
				       sizeof(sun)) < 0) {
		free(ap->name);
		free(ap);
		bufferevent_free(bev);
	}
}

int pvx_act_hold(const char *name, pvx_act_ready_cb ready, pvx_act_fail_cb fail,
		 void *ctx)
{
	struct event_base *base = pvx_get_base();
	if (!g_inited || !name || !base)
		return -1;

	// Coalesce: only POST activation when this is the first waiter for the
	// name; later waiters ride the same in-flight activation + signal.
	bool first = !set_contains_waiter_name(name);

	struct waiter *w = calloc(1, sizeof(*w));
	if (!w)
		return -1;
	w->name = strdup(name);
	w->ready = ready;
	w->fail = fail;
	w->ctx = ctx;
	w->timer = evtimer_new(base, waiter_timeout_cb, w);
	dl_list_init(&w->list);
	dl_list_add(&g_waiters, &w->list);
	if (w->timer) {
		struct timeval tv = { ACT_TIMEOUT_SEC, 0 };
		evtimer_add(w->timer, &tv);
	}

	if (first)
		trigger_activation(name);
	return 0;
}

void pvx_act_cancel(void *ctx)
{
	if (!g_inited)
		return;
	struct waiter *w, *t;
	dl_list_for_each_safe(w, t, &g_waiters, struct waiter, list)
	{
		if (w->ctx == ctx)
			waiter_free(w);
	}
}
