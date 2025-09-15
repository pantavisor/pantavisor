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

#include "event/event_http_server.h"
#include "paths.h"

#include <event2/buffer.h>

#include <linux/limits.h>

#define MODULE_NAME "ctrl"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_CTRL_UNKNOWN_ENDPOINT "{\"Error\":\"Unknown endpoint\"}"
#define PV_CTRL_RESPONSE_ERROR "{\"err\":\"%s\",\"code\":%d}"

static struct evhttp *httpsrv = NULL;

static void drivers_endp(struct evhttp_request *req, void *ctx)
{
}

// catch any call to an unknown endpoint
static void unknown_endpoint(struct evhttp_request *req, void *data)
{
	(void)data;
	struct evbuffer *reply = evbuffer_new();
	evbuffer_add_printf(reply, PV_CTRL_UNKNOWN_ENDPOINT);
	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "application/json");

	evhttp_send_reply(req, HTTP_BADREQUEST, "unknown endpoint", reply);
	evbuffer_free(reply);
}

// catch any error in the communication, for example use any other protocol
// than http against the socket
static int error_cb(struct evhttp_request *req, struct evbuffer *buf, int err,
		    const char *reason, void *data)
{
	(void)req;
	(void)data;
	evbuffer_add_printf(buf, PV_CTRL_RESPONSE_ERROR,
			    reason ? reason : "null", err);
	return 0;
}

void set_callbacks()
{
	// error callbacks
	evhttp_set_gencb(httpsrv, unknown_endpoint, NULL);
	evhttp_set_errorcb(httpsrv, error_cb, NULL);

	// api callbacks
}

int pv_ctrl_start()
{
	pv_log(DEBUG, "starting server");
	if (httpsrv) {
		pv_log(DEBUG, "server is already created");
		return 0;
	}

	char sock_path[PATH_MAX] = { 0 };
	pv_paths_pv_file(sock_path, PATH_MAX - 1, PVCTRL_FNAME);

	httpsrv = pv_http_server_new(sock_path);

	if (!httpsrv) {
		pv_log(DEBUG, "couldn't create server");
		return -1;
	}

	set_callbacks();

	return 0;
}

void pv_ctrl_stop()
{
	evhttp_free(httpsrv);
	httpsrv = NULL;
	pv_log(DEBUG, "server stopped");
}