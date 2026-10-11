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
#ifndef PVX_PROXY_COMMON_H
#define PVX_PROXY_COMMON_H

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

/*
 * Shared bidirectional proxy session used by the stream plugins (unix, rest,
 * dbus, wayland). It splices bytes between a consumer ("client") and the
 * provider it was wired to.
 *
 * Plugins that need extra per-session state (e.g. dbus auth) embed this struct
 * as their FIRST member, so a pointer to the outer session is also a valid
 * `struct pvx_proxy *`. That lets every plugin share the read/event callbacks
 * and teardown below while keeping its own bufferevent callback arg.
 *
 * Lifecycle (see proxy_common.c): the pair is freed when BOTH sides have EOF'd,
 * or on error, or once a half-open session (one side gone) has been idle past a
 * linger window. Waiting for both EOFs preserves the response on a normal
 * request/response; the idle linger bounds fds when a provider never closes
 * (e.g. an idle stream whose consumer has already left).
 */
struct pvx_proxy {
	struct bufferevent *be_client;
	struct bufferevent *be_provider;
	int client_eof;
	int provider_eof;
	struct event *linger;
	// Optional per-session cleanup hook, invoked by pvx_proxy_free() before
	// the bufferevents and the session are freed. A plugin that embeds this
	// struct uses it to release its own state (e.g. dbus activation waiter /
	// held buffer) so nothing dangles onto the freed session.
	void (*on_free)(struct pvx_proxy *p);
};

/* The opposite bufferevent of `bev` within the session (for forwarding). */
struct bufferevent *pvx_proxy_peer(const struct pvx_proxy *p,
				   struct bufferevent *bev);

/* Default read callback: splice all input from `bev` to its peer's output. */
void pvx_proxy_read_cb(struct bufferevent *bev, void *ctx);

/* Shared event callback: drives the lifecycle described above. */
void pvx_proxy_event_cb(struct bufferevent *bev, short events, void *ctx);

/* Tear down both bufferevents, cancel the linger timer, and free the session.
 * Use this in the accept path when wiring fails before callbacks are live. */
void pvx_proxy_free(struct pvx_proxy *p);

/*
 * Install an error callback on a proxy listener that survives fd exhaustion.
 * libevent's default on an accept() EMFILE/ENFILE is to log and retry
 * immediately, spinning the loop and flooding the log. Instead we disable the
 * listener and re-enable it after a short back-off. The listener's user arg
 * (a struct pvx_link *) is reused to label log lines with the service name.
 */
void pvx_listener_set_emfile_backoff(struct evconnlistener *lev);

#endif /* PVX_PROXY_COMMON_H */
