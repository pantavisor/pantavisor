/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#include "event_http_server.h"
#include "event.h"

#include <sys/un.h>
#include <unistd.h>
#include <string.h>

#include <event2/listener.h>

#define MODULE_NAME "event_http_server"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static struct evhttp *server_new()
{
	pv_event_base_init();
	struct event_base *base = pv_event_get_base();
	if (!base) {
		pv_log(DEBUG, "couldn't initialize server, NULL base event");
		return NULL;
	}

	struct evhttp *http = evhttp_new(base);

	if (!http)
		pv_log(DEBUG, "couldn't initialize server, NULL http object");

	return http;
}

struct evhttp *pv_http_server_new(const char *sock_path)
{
	struct evhttp *http = server_new();
	if (!http)
		return NULL;

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	memccpy(addr.sun_path, sock_path, '\0', strlen(sock_path));
	unlink(addr.sun_path);

	struct event_base *base = pv_event_get_base();

	int flags = LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC;
	struct evconnlistener *lev =
		evconnlistener_new_bind(base, NULL, NULL, flags, -1,
					(struct sockaddr *)&addr, sizeof(addr));

	if (!lev) {
		pv_log(DEBUG, "couldn't initialize connection listener");
		evhttp_free(http);
		return NULL;
	}

	evhttp_bind_listener(http, lev);
	return http;
}