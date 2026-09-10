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

#include "ctrl_endpoints.h"
#include "ctrl.h"
#include "ctrl_util.h"
#include "state.h"
#include "pantavisor.h"
#include "utils/json.h"
#include <jsmn/jsmnutil.h>

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>
#include <stdlib.h>

#define MODULE_NAME "xconnect-activate-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#if defined(PANTAVISOR_XCONNECT) && defined(PANTAVISOR_XCONNECT_DBUS_SYSTEMBUS)

#include "dbus_daemon.h"

#define ACTIVATE_MAX_DATA 512

// Read the {"name":"<well-known>"} body and activate its owner. Called either
// inline (body already buffered) or from the arrival callback below.
static void ctrl_xconnect_activate_process(struct evhttp_request *req)
{
	ssize_t len = 0;
	char *data = pv_ctrl_utils_get_data(req, ACTIVATE_MAX_DATA, &len);
	if (!data || len <= 0) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, "Empty body");
		goto out;
	}

	jsmntok_t *tokv = NULL;
	int tokc;
	char *name = NULL;
	if (jsmnutil_parse_json(data, &tokv, &tokc) > 0)
		name = pv_json_get_value(data, "name", tokv, tokc);
	if (tokv)
		free(tokv);
	if (!name || !name[0]) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Missing 'name' in body");
		goto out_name;
	}

	struct pantavisor *pv = pv_get_instance();
	if (!pv || !pv->state) {
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "State not loaded yet");
		goto out_name;
	}

	if (pv_dbus_daemon_activate(pv->state, name) < 0) {
		pv_log(WARN, "no activatable owner for D-Bus name '%s'", name);
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "No activatable owner for name");
		goto out_name;
	}

	pv_ctrl_utils_send_ok(req);

out_name:
	free(name);
out:
	if (data)
		free(data);
}

// Arrival callback: fires when the body is still streaming in when the request
// handler ran (evbuffer grows after we registered).
static void ctrl_xconnect_activate_body(struct evbuffer *buf,
					const struct evbuffer_cb_info *info,
					void *ctx)
{
	if (!info->n_added)
		return;
	if (!pv_ctrl_utils_has_all_data(ctx))
		return;
	evbuffer_remove_cb(buf, ctrl_xconnect_activate_body, ctx);
	ctrl_xconnect_activate_process(ctx);
}

static void ctrl_xconnect_activate_post(struct evhttp_request *req, void *ctx)
{
	char err[PV_CTRL_MAX_ERR] = { 0 };
	int code = pv_ctrl_utils_is_req_ok(req, ctx, err);
	if (code != 0) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, err);
		return;
	}

	if (pv_ctrl_utils_get_content_length(req) < 1) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, "Empty body");
		return;
	}

	// Over a unix socket the small body usually arrives with the headers, so
	// it is already fully buffered here — process inline. Only fall back to
	// the arrival callback if it is still streaming (add_cb would otherwise
	// never fire for an already-complete body).
	if (pv_ctrl_utils_has_all_data(req)) {
		ctrl_xconnect_activate_process(req);
		return;
	}

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_xconnect_activate_body, req);
}

#else

static void ctrl_xconnect_activate_post(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;
	pv_ctrl_utils_send_error(
		req, HTTP_NOTFOUND,
		"hosted dbus system bus not enabled at build time");
}

#endif

int pv_ctrl_endpoints_xconnect_activate_init()
{
	pv_ctrl_add_endpoint("/xconnect/dbus/activate", EVHTTP_REQ_POST, true,
			     ctrl_xconnect_activate_post);
	return 0;
}
