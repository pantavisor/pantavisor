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
#include <errno.h>
#include <string.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include "../include/xconnect.h"
#include "proxy_common.h"

/*
 * How long a half-open proxy session (one side EOF'd, the other never closing)
 * may sit idle before we reclaim it. The timer is reset on every byte spliced,
 * so an actively streaming response never trips it; it only fires when nothing
 * has flowed for this long, which is what bounds fds against a provider that
 * holds a connection open after its consumer has gone.
 */
#define PVX_PROXY_LINGER_SECS 60

/* How long to pause a listener after running out of file descriptors. */
#define PVX_EMFILE_BACKOFF_SECS 2

struct bufferevent *pvx_proxy_peer(const struct pvx_proxy *p,
				   struct bufferevent *bev)
{
	return bev == p->be_client ? p->be_provider : p->be_client;
}

void pvx_proxy_free(struct pvx_proxy *p)
{
	if (!p)
		return;
	if (p->on_free)
		p->on_free(p);
	if (p->linger)
		event_free(p->linger);
	if (p->be_client)
		bufferevent_free(p->be_client);
	if (p->be_provider)
		bufferevent_free(p->be_provider);
	free(p);
}

static void proxy_linger_cb(evutil_socket_t fd, short what, void *ctx)
{
	(void)fd;
	(void)what;
	// Half-open session went idle past the window: reclaim it.
	pvx_proxy_free(ctx);
}

// Arm (or, if already armed, push back) the idle-linger timer. Called when a
// session becomes half-open and again on every splice so active transfers are
// never cut short.
static void proxy_bump_linger(struct pvx_proxy *p)
{
	struct timeval tv = { PVX_PROXY_LINGER_SECS, 0 };

	if (!p->linger) {
		struct event_base *base = pvx_get_base();
		if (!base)
			return;
		p->linger = evtimer_new(base, proxy_linger_cb, p);
		if (!p->linger)
			return;
	}
	evtimer_add(p->linger, &tv);
}

void pvx_proxy_read_cb(struct bufferevent *bev, void *ctx)
{
	struct pvx_proxy *p = ctx;
	struct bufferevent *other = pvx_proxy_peer(p, bev);

	evbuffer_add_buffer(bufferevent_get_output(other),
			    bufferevent_get_input(bev));

	// Keep a half-open session alive as long as data keeps moving.
	if (p->linger)
		proxy_bump_linger(p);
}

void pvx_proxy_event_cb(struct bufferevent *bev, short events, void *ctx)
{
	struct pvx_proxy *p = ctx;

	if (events & BEV_EVENT_ERROR) {
		// A peer errored (e.g. write to a closed consumer): drop the pair.
		pvx_proxy_free(p);
		return;
	}

	if (events & BEV_EVENT_EOF) {
		if (bev == p->be_client)
			p->client_eof = 1;
		else
			p->provider_eof = 1;
		bufferevent_disable(bev, EV_READ);

		// Both ends done: the response (if any) has already been spliced
		// to the still-draining side's output, so freeing now is safe.
		if (p->client_eof && p->provider_eof) {
			pvx_proxy_free(p);
			return;
		}

		// One end closed but the other has not. Keep the session so an
		// in-flight response can still flow, but bound the wait so a
		// provider that never EOFs cannot leak fds forever.
		proxy_bump_linger(p);
	}
}

static void listener_reenable_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	evconnlistener_enable((struct evconnlistener *)arg);
}

static void listener_error_cb(struct evconnlistener *lev, void *ctx)
{
	struct pvx_link *link = ctx;
	const char *who = (link && link->type) ? link->type : "pvx";
	const char *name = (link && link->name) ? link->name : "?";
	int err = EVUTIL_SOCKET_ERROR();

	if (err == EMFILE || err == ENFILE) {
		struct event_base *base = pvx_get_base();
		struct timeval tv = { PVX_EMFILE_BACKOFF_SECS, 0 };

		fprintf(stderr,
			"pvx-%s: accept() for %s failed: %s; pausing listener for %ds\n",
			who, name, strerror(err), PVX_EMFILE_BACKOFF_SECS);

		evconnlistener_disable(lev);
		if (!base ||
		    event_base_once(base, -1, EV_TIMEOUT, listener_reenable_cb,
				    lev, &tv) < 0)
			evconnlistener_enable(lev);
		return;
	}

	fprintf(stderr, "pvx-%s: accept() for %s failed: %s\n", who, name,
		strerror(err));
}

void pvx_listener_set_emfile_backoff(struct evconnlistener *lev)
{
	if (!lev)
		return;
	evconnlistener_set_error_cb(lev, listener_error_cb);
}
