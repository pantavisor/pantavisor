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
#include "ctrl/utils.h"
#include "ctrl/sender.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#define MODULE_NAME "ctrl-utils"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pv_ctrl_http_code_value {
	int code;
	const char *reason;
};

struct pv_ctrl_http_code_value http_codes[] = {
	{ 507, "Insufficient Storage" },
	{ 422, "Unprocessable Content" },
};

static struct pv_ctrl_http_code_value get_http_value(int code)
{
	if (code > -1) {
		pv_log(WARN, "pv_ctrl_codes should be < 0");
		// this will cause a problem in the clint, a good clue
		// to debug this
		return (struct pv_ctrl_http_code_value){ -1, "" };
	}
	return http_codes[(-code) - 1];
}

struct pv_ctrl_sender *pv_ctrl_utils_checks(const char *logname,
					    struct evhttp_request *req,
					    int *methods, bool check_mgmt)
{
	struct pv_ctrl_sender *snd = pv_ctrl_sender_new(req);

	if (!snd) {
		pv_log(WARN, "%s: couldn't create sender object", logname);
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Internal error");
		goto err;
	}

	bool method_ok = false;
	int i = 0;
	while (methods[i] != -1) {
		if (methods[i] != snd->method)
			continue;

		method_ok = true;
		break;
		i++;
	}

	if (!method_ok) {
		pv_log(WARN, "%s: HTTP method not supported for this endpoint",
		       logname);
		pv_ctrl_utils_send_error(
			req, HTTP_BADREQUEST,
			"Method not supported for this endpoint");
		goto err;
	}

	if (check_mgmt && !snd->is_privileged) {
		pv_log(WARN, "%s: Request not sent from mgmt platform",
		       logname);
		pv_ctrl_utils_send_error(req, HTTP_FORBIDDEN,
					 "Request not sent from mgmt platform");
		goto err;
	}

	return snd;
err:
	pv_ctrl_sender_free(snd);
	return NULL;
}

void pv_ctrl_utils_send_ok(struct evhttp_request *req)
{
	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
}

void pv_ctrl_utils_send_json(struct evhttp_request *req, int code,
			     const char *reason, const char *json, ...)
{
	struct evbuffer *reply = evbuffer_new();
	if (!reply) {
		pv_log(DEBUG, "couldn't allocate reply buffer");
		return;
	}

	va_list lst;
	va_start(lst, json);

	evbuffer_add_vprintf(reply, json, lst);
	va_end(lst);

	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "application/json");
	evhttp_send_reply(req, code, reason, reply);
	evbuffer_free(reply);
}

void pv_ctrl_utils_send_error(struct evhttp_request *req, int code,
			      const char *err_str)
{
	if (code > 0) {
		pv_ctrl_utils_send_json(req, code, NULL, PV_CTRL_UTILS_ERR_RSP,
					err_str);
		return;
	}

	struct pv_ctrl_http_code_value v = get_http_value(code);
	pv_ctrl_utils_send_json(req, v.code, v.reason, PV_CTRL_UTILS_ERR_RSP,
				err_str);
}

int pv_ctrl_utils_split_path(const char *path,
			     char parts[PV_CTRL_UTILS_MAX_PARTS][NAME_MAX])
{
	if (!path)
		return 0;

	const char *start = path;
	const char *end = path;
	int parts_count = 0;

	while (*start) {
		while (*start == '/')
			start++;

		if (!*start)
			break;

		end = start;
		while (*end && *end != '/')
			end++;

		if (end > start) {
			memccpy(parts[parts_count], start, '\0', (end - start));
			parts_count++;

			if (parts_count == PV_CTRL_UTILS_MAX_PARTS)
				return parts_count;
		}

		start = end;
	}

	return parts_count;
}

void pv_ctrl_utils_drain_req(struct evhttp_request *req)
{
	struct evbuffer *buf = evhttp_request_get_input_buffer(req);
	evbuffer_drain(buf, evbuffer_get_length(buf));
}