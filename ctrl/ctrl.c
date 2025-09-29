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

#include "ctrl/ctrl_sender.h"
#include "ctrl/ctrl_handler.h"
#include "ctrl/ctrl_utils.h"
#include "event/event_http_server.h"
#include "paths.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "ctrl"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pv_ctrl {
	struct evhttp *srv;
};

extern const struct pv_ctrl_handler driver_hnd;
extern const struct pv_ctrl_handler buildinfo_hnd;
extern const struct pv_ctrl_handler devicemeta_hnd;
extern const struct pv_ctrl_handler usermeta_hnd;
extern const struct pv_ctrl_handler steps_hnd;
extern const struct pv_ctrl_handler object_hnd;
extern const struct pv_ctrl_handler containers_hnd;
extern const struct pv_ctrl_handler groups_hnd;
extern const struct pv_ctrl_handler signal_hnd;

struct pv_ctrl pvctrl = {
	.srv = NULL,
};

static void router_endpoint(struct evhttp_request *req, void *data)
{
	(void)data;

	const char *uri = evhttp_request_get_uri(req);
	pv_ctrl_handler_fn fn = NULL;

	if (!strncmp(uri, driver_hnd.path, strlen(driver_hnd.path)))
		fn = driver_hnd.fn;
	else if (!strncmp(uri, buildinfo_hnd.path, strlen(buildinfo_hnd.path)))
		fn = buildinfo_hnd.fn;
	else if (!strncmp(uri, devicemeta_hnd.path,
			  strlen(devicemeta_hnd.path)))
		fn = devicemeta_hnd.fn;
	else if (!strncmp(uri, usermeta_hnd.path, strlen(usermeta_hnd.path)))
		fn = usermeta_hnd.fn;
	else if (!strncmp(uri, steps_hnd.path, strlen(steps_hnd.path)))
		fn = steps_hnd.fn;
	else if (!strncmp(uri, object_hnd.path, strlen(object_hnd.path)))
		fn = object_hnd.fn;
	else if (!strncmp(uri, containers_hnd.path,
			  strlen(containers_hnd.path)))
		fn = containers_hnd.fn;
	else if (!strncmp(uri, groups_hnd.path, strlen(groups_hnd.path)))
		fn = groups_hnd.fn;
	else if (!strncmp(uri, signal_hnd.path, strlen(signal_hnd.path)))
		fn = signal_hnd.fn;

	if (fn) {
		fn(req);
		return;
	}

	pv_log(WARN, "HTTP request received has unknown endpoint");
	pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, "unknown endpoint");
}

// catch any error in the communication, for example use any other protocol
// than http against the socket
static int error_cb(struct evhttp_request *req, struct evbuffer *buf, int err,
		    const char *reason, void *data)
{
	(void)req;
	(void)data;
	evbuffer_add_printf(buf, PV_CTRL_UTILS_ERR_RSP, "Unsupported protocol");
	return 0;
}

int pv_ctrl_start()
{
	pv_log(DEBUG, "starting server");
	if (pvctrl.srv) {
		pv_log(DEBUG, "server is already created");
		return 0;
	}

	char sock_path[PATH_MAX] = { 0 };
	pv_paths_pv_file(sock_path, PATH_MAX - 1, PVCTRL_FNAME);

	pvctrl.srv = pv_http_server_new(sock_path);

	if (!pvctrl.srv) {
		pv_log(DEBUG, "couldn't create server");
		return -1;
	}

	evhttp_set_gencb(pvctrl.srv, router_endpoint, NULL);
	evhttp_set_errorcb(pvctrl.srv, error_cb, NULL);

	return 0;
}

void pv_ctrl_stop()
{
	evhttp_free(pvctrl.srv);
	pvctrl.srv = NULL;
	pv_log(DEBUG, "server stopped");
}