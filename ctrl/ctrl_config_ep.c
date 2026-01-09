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
#include "config.h"

#include <event2/http.h>

#define MODULE_NAME "config-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void ctrl_config_send(struct evhttp_request *req, struct pv_ctrl_cb *cb,
			     char *(get_conf)())
{
	if (pv_ctrl_utils_is_req_ok(req, cb, NULL) != 0)
		return;

	char *conf = get_conf();
	if (!conf) {
		pv_log(WARN, "couldn't get conf");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Cannot get conf");
		return;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, conf);
}

static void ctrl_config_list(struct evhttp_request *req, void *ctx)
{
	ctrl_config_send(req, ctx, pv_config_get_legacy_json);
}

static void ctrl_config_list2(struct evhttp_request *req, void *ctx)
{
	ctrl_config_send(req, ctx, pv_config_get_complete_json);
}

int pv_ctrl_endpoints_config_init()
{
	pv_ctrl_add_endpoint("/config", EVHTTP_REQ_GET, true, ctrl_config_list);
	pv_ctrl_add_endpoint("/config2", EVHTTP_REQ_GET, true,
			     ctrl_config_list2);

	return 0;
}
