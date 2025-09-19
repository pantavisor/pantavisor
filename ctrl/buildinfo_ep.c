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

#include "ctrl/sender.h"
#include "ctrl/handler.h"
#include "ctrl/utils.h"
#include "version.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>

#define MODULE_NAME "buildinfo-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void buildinfo_send(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };

	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	struct evbuffer *buf = evbuffer_new();
	if (!buf) {
		pv_log(WARN, "couldn't allocate response buffer");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error quering build info");
		goto out;
	}

	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "text/plain");
	evbuffer_add_printf(buf, "%s", pv_build_manifest);
	evhttp_send_reply(req, HTTP_OK, NULL, buf);
out:
	pv_ctrl_sender_free(snd);
}

static int buildinfo_handler(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char *parts[PV_CTRL_UTILS_MAX_PARTS] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, parts);

	if (size < 1 || size > 1 || strcmp(parts[0], "buildinfo") != 0)
		return -1;

	buildinfo_send(req);
	return 0;
}

struct pv_ctrl_handler buildinfo_hnd = {
	.path = "/buildinfo",
	.fn = buildinfo_handler,
};