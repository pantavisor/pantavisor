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
//
// /xconnect-status endpoint pair
// ------------------------------
// pv-xconnect POSTs an array of {consumer, name, established, last_error}
// objects on every reconcile pass. We stash the most recent body verbatim and
// serve it back via GET. A future container-health subsystem inside pantavisor
// will consume this to gate `pv_platform_start` outcomes on link establishment;
// for v1.1 the endpoint primarily exists for external observability (test
// drivers, dashboards, CI assertions).
//
// pv-ctrl is single-threaded (libevent), so a plain static buffer with no mutex
// is safe — POST replaces it, GET dups it, no concurrency.
//
#include "ctrl_endpoints.h"
#include "ctrl.h"
#include "ctrl_util.h"
#include "pantavisor.h"

#include <event2/http.h>

#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "xconnect-status-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#ifdef PANTAVISOR_XCONNECT

#define XCONNECT_STATUS_MAX_SIZE (64 * 1024)

// Latest status body posted by pv-xconnect. Owned here, replaced on each POST.
static char *g_status_json = NULL;

static void ctrl_xconnect_status_post(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	char *data = pv_ctrl_utils_get_data(req, XCONNECT_STATUS_MAX_SIZE, NULL);
	if (!data) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "empty status body");
		return;
	}

	free(g_status_json);
	g_status_json = data; // owned now
	pv_ctrl_utils_send_ok(req);
}

static void ctrl_xconnect_status_get(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	const char *body = g_status_json ? g_status_json : "[]";
	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, (char *)body);
}

#else
static void ctrl_xconnect_status_post(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;
	pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
				 "xconnect not enabled at build time");
}
static void ctrl_xconnect_status_get(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;
	pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
				 "xconnect not enabled at build time");
}
#endif

// libevent's evhttp_set_cb only allows one callback per path, so we
// dispatch GET vs POST inside this single handler.
static void ctrl_xconnect_status_dispatch(struct evhttp_request *req, void *ctx)
{
	enum evhttp_cmd_type m = evhttp_request_get_command(req);
	if (m == EVHTTP_REQ_POST)
		ctrl_xconnect_status_post(req, ctx);
	else
		ctrl_xconnect_status_get(req, ctx);
}

int pv_ctrl_endpoints_xconnect_status_init()
{
	pv_ctrl_add_endpoint("/xconnect-status",
			     EVHTTP_REQ_POST | EVHTTP_REQ_GET, true,
			     ctrl_xconnect_status_dispatch);
	return 0;
}
