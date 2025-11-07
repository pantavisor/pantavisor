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
#include "ctrl_util.h"
#include "version.h"

#include <event2/http.h>
#include <event2/buffer.h>

#define MODULE_NAME "buildinfo-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void ctrl_buildinfo_send(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	struct evbuffer *buf = evhttp_request_get_output_buffer(req);
	if (!buf) {
		pv_log(WARN, "couldn't get output buffer");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error quering build info");
		return;
	}

	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "content-type", "text/plain");
	evbuffer_add_printf(buf, "%s", pv_build_manifest);
	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
}

int pv_ctrl_endpoints_buildinfo_init()
{
	pv_ctrl_add_endpoint("/buildinfo", EVHTTP_REQ_GET, true,
			     ctrl_buildinfo_send);

	return 0;
}