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
#include "ctrl_callback.h"
#include "ctrl_util.h"
#include "state.h"
#include "pantavisor.h"

#include <event2/http.h>

#define MODULE_NAME "groups-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void ctrl_groups_list(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	struct pantavisor *pv = pv_get_instance();
	char *groups = pv_state_get_groups_json(pv->state);

	if (!groups) {
		pv_log(WARN, "couldn't get group list");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot get group list");
		return;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, groups);
}

int pv_ctrl_endpoints_groups_init()
{
	pv_ctrl_add_endpoint("/groups", EVHTTP_REQ_GET, true, ctrl_groups_list);

	return 0;
}
