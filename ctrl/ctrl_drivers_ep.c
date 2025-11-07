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

#include "ctrl_endpoints.h"
#include "ctrl.h"
#include "ctrl_caller.h"
#include "ctrl_util.h"

#include "drivers.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>
#include <linux/limits.h>

#define MODULE_NAME "drivers-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static char *ctrl_drivers_get_name(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char split[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };

	int size = pv_ctrl_utils_split_path(uri, split);

	if (size < 3)
		return NULL;

	if (!strcmp(split[1], "load") || !strcmp(split[1], "unload"))
		return NULL;

	return strdup(split[1]);
}

static void ctrl_drivers_list(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	struct pv_ctrl_caller caller = { 0 };
	if (pv_ctrl_caller_init(&caller, req) != 0) {
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error identifying caller");
		return;
	}

	char *drivers = pv_drivers_state_all(caller.plat);

	if (!drivers) {
		pv_log(DEBUG, "couldn't get drivers");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot get drivers");
		return;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, drivers);
	free(drivers);
}

static void ctrl_drivers_load(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	struct pv_ctrl_caller caller = { 0 };
	if (pv_ctrl_caller_init(&caller, req) != 0) {
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error identifying caller");
		return;
	}

	char *name = ctrl_drivers_get_name(req);
	if (!name) {
		pv_log(WARN, "no driver name provided");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "No driver name");
		return;
	}

	int ret = pv_platform_load_drivers(caller.plat, name, DRIVER_MANUAL);
	if (ret != 0) {
		pv_log(WARN, "Error loading driver %s", name);
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Error loading driver");
		goto out;
	}

	pv_ctrl_utils_send_ok(req);
out:
	if (name)
		free(name);
}

static void ctrl_drivers_unload(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	struct pv_ctrl_caller caller = { 0 };
	if (pv_ctrl_caller_init(&caller, req) != 0) {
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error identifying caller");
		return;
	}

	char *name = ctrl_drivers_get_name(req);
	if (!name) {
		pv_log(WARN, "no driver name provided");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "No driver name");
		return;
	}

	pv_platform_unload_drivers(caller.plat, name, DRIVER_MANUAL);
	pv_ctrl_utils_send_ok(req);

	if (name)
		free(name);
}

static void ctrl_drivers_load_bulk(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	struct pv_ctrl_caller caller = { 0 };
	if (pv_ctrl_caller_init(&caller, req) != 0) {
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error identifying caller");
		return;
	}

	int ret = pv_platform_load_drivers(caller.plat, NULL, DRIVER_MANUAL);
	if (ret != 0) {
		pv_log(WARN, "Error loading drivers");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Error loading drivers");
		return;
	}

	pv_ctrl_utils_send_ok(req);
}

static void ctrl_drivers_unload_bulk(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	struct pv_ctrl_caller caller = { 0 };
	if (pv_ctrl_caller_init(&caller, req) != 0) {
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error identifying caller");
		return;
	}

	pv_platform_unload_drivers(caller.plat, NULL, DRIVER_MANUAL);
	pv_ctrl_utils_send_ok(req);
}

int pv_ctrl_endpoints_drivers_init()
{
	pv_ctrl_add_endpoint("/drivers", EVHTTP_REQ_GET, true,
			     ctrl_drivers_list);

	pv_ctrl_add_endpoint("/drivers/load", EVHTTP_REQ_PUT, true,
			     ctrl_drivers_load_bulk);

	pv_ctrl_add_endpoint("/drivers/{}/load", EVHTTP_REQ_PUT, true,
			     ctrl_drivers_load);

	pv_ctrl_add_endpoint("/drivers/unload", EVHTTP_REQ_PUT, true,
			     ctrl_drivers_unload_bulk);

	pv_ctrl_add_endpoint("/drivers/{}/unload", EVHTTP_REQ_PUT, true,
			     ctrl_drivers_unload);

	return 0;
}