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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ctrl_util.h"
#include "ctrl_caller.h"
#include "ctrl.h"

#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>

#define MODULE_NAME "ctrl-utils"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

// to improve the evbuffer_add_file() performance
#define EVBUFFER_FLAG_DRAINS_TO_FD 1

struct pv_ctrl_http_code_value {
	int code;
	const char *reason;
};

struct ctrl_utils_drain_data {
	struct evhttp_request *req;
	int code;
	const char *msg;
};

struct pv_ctrl_http_code_value http_codes[] = {
	{ 507, "Insufficient Storage" },
	{ 422, "Unprocessable Content" },
	{ 409, "Conflict" },
};

#define PV_CTRL_UTILS_ERR_RSP "{\"Error\":\"%s\"}"

static struct pv_ctrl_http_code_value ctrl_utils_get_http_value(int code)
{
	if (code > -1) {
		pv_log(WARN, "pv_ctrl_codes should be < 0");
		// this will cause a problem in the clint, a good clue
		// to debug this
		return (struct pv_ctrl_http_code_value){ -1, "" };
	}
	return http_codes[(-code) - 1];
}

void pv_ctrl_utils_send_ok(struct evhttp_request *req)
{
	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "application/json");

	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
}

static void ctrl_utils_clean_json_cb(const void *data, size_t datalen,
				     void *extra)
{
	char *json = (char *)data;
	if (!json)
		return;
	free(json);
}

void pv_ctrl_utils_send_json(struct evhttp_request *req, int code,
			     const char *reason, char *json)
{
	struct evbuffer *reply = evhttp_request_get_output_buffer(req);
	if (!reply) {
		pv_log(DEBUG, "couldn't allocate reply buffer");
		return;
	}

	if (!json)
		return;

	int ret;
	ret = evbuffer_add_reference(reply, json, strlen(json),
				     ctrl_utils_clean_json_cb, NULL);
	if (ret) {
		pv_log(WARN, "could not add reference to evbuffer to evbuffer");
		free(json);
	}

	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "application/json");

	evhttp_send_reply(req, code, reason, NULL);
}

void pv_ctrl_utils_send_json_file(struct evhttp_request *req, const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pv_log(ERROR, "%s could not be opened for read", path);
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "Resource does not exist");
		goto out;
	}

	struct evbuffer *buf = evhttp_request_get_output_buffer(req);
	if (evbuffer_add_file(buf, fd, 0, -1) != 0) {
		pv_log(ERROR, "%s could not send data", path);
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot send data");
		goto out;
	}

	pv_ctrl_utils_send_ok(req);
out:
	if (fd > -1)
		close(fd);
}

static void ctrl_utils_send_fmt_str(struct evhttp_request *req, int code,
				    const char *reason, const char *fmt, ...)
{
	struct evbuffer *reply = evhttp_request_get_output_buffer(req);
	if (!reply) {
		pv_log(DEBUG, "couldn't allocate reply buffer");
		return;
	}

	evbuffer_expand(reply, 4096);

	va_list lst;
	va_start(lst, fmt);
	evbuffer_add_vprintf(reply, fmt, lst);
	va_end(lst);

	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "application/json");

	evhttp_send_reply(req, code, reason, NULL);
}

void pv_ctrl_utils_send_error(struct evhttp_request *req, int code,
			      const char *err_str)
{
	if (code > 0) {
		ctrl_utils_send_fmt_str(req, code, NULL, PV_CTRL_UTILS_ERR_RSP,
					err_str);
		return;
	}

	struct pv_ctrl_http_code_value v = ctrl_utils_get_http_value(code);
	ctrl_utils_send_fmt_str(req, v.code, v.reason, PV_CTRL_UTILS_ERR_RSP,
				err_str);
}

int pv_ctrl_utils_split_path(const char *uri,
			     char parts[PV_CTRL_MAX_SPLIT][NAME_MAX])
{
	if (!uri)
		return 0;

	const char *start = uri;
	const char *end = uri;
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

			if (parts_count == PV_CTRL_MAX_SPLIT)
				return parts_count;
		}

		start = end;
	}

	return parts_count;
}

int pv_ctrl_utils_is_req_ok(struct evhttp_request *req, struct pv_ctrl_cb *cb,
			    char *err)
{
	struct pv_ctrl_caller caller = { 0 };
	if (pv_ctrl_caller_init(&caller, req) != 0) {
		pv_log(WARN, "couldn't get caller info");
		if (!err)
			pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
						 "Internal Error");
		else
			memccpy(err, "Internal Error", '\0', PV_CTRL_MAX_ERR);
		return HTTP_INTERNAL;
	}

	if (!(caller.method & cb->methods)) {
		pv_log(WARN, "HTTP method not supported for this endpoint");
		if (!err)
			pv_ctrl_utils_send_error(
				req, HTTP_BADREQUEST,
				"Method not supported for this endpoint");
		else
			memccpy(err, "Method not supported for this endpoint",
				'\0', PV_CTRL_MAX_ERR);
		return HTTP_BADREQUEST;
	}

	if (cb->need_mgmt && !caller.is_privileged) {
		pv_log(WARN, "Request not sent from mgmt platform");

		if (!err)
			pv_ctrl_utils_send_error(
				req, HTTP_FORBIDDEN,
				"Request not sent from a mgmt platform");
		else
			memccpy(err, "Request not sent from a mgmt platform",
				'\0', PV_CTRL_MAX_ERR);
		return HTTP_FORBIDDEN;
	}
	return 0;
}

ssize_t pv_ctrl_utils_get_content_length(struct evhttp_request *req)
{
	struct evkeyvalq *headers = evhttp_request_get_input_headers(req);
	const char *cl_str = evhttp_find_header(headers, "content-length");

	if (!cl_str)
		return -1;

	errno = 0;
	ssize_t cl = strtoimax(cl_str, NULL, 10);
	if (errno == ERANGE)
		return -1;

	return cl;
}

char *pv_ctrl_utils_get_data(struct evhttp_request *req, ssize_t max,
			     ssize_t *len)
{
	struct evbuffer *buf = evhttp_request_get_input_buffer(req);
	if (!buf) {
		pv_log(DEBUG, "couldn't get incoming data");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "No incoming data found");

		return NULL;
	}

	size_t cur_size = evbuffer_get_length(buf);

	if (cur_size > max) {
		pv_log(DEBUG,
		       "incoming data exceeds the limit; max: %zd, incoming: %zd",
		       max, cur_size);

		pv_ctrl_utils_send_error(req, PV_HTTP_INSF_STORAGE,
					 "Not enough disk space available");

		return NULL;
	}

	char *data = calloc(cur_size + 1, sizeof(char));
	if (!data) {
		pv_log(DEBUG, "couldn't alloc incoming data");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot allocate data");
		return NULL;
	}

	evbuffer_remove(buf, data, cur_size);

	if (len)
		*len = cur_size;

	return data;
}

static void ctrl_utils_drain_buf(struct evbuffer *buf)
{
	size_t len = evbuffer_get_length(buf);
	pv_log(DEBUG, "discarding %zd bytes");
	evbuffer_drain(buf, len);
}

void pv_ctrl_utils_drain_req(struct evhttp_request *req)
{
	ctrl_utils_drain_buf(evhttp_request_get_input_buffer(req));
}

static void ctrl_utils_drain_ok_callback(struct evbuffer *buf,
					 const struct evbuffer_cb_info *info,
					 void *ctx)
{
	(void)info;
	ctrl_utils_drain_buf(buf);

	pv_ctrl_utils_send_ok(ctx);
}

static void ctrl_utils_drain_error_callback(struct evbuffer *buf,
					    const struct evbuffer_cb_info *info,
					    void *ctx)
{
	(void)info;
	ctrl_utils_drain_buf(buf);

	if (!ctx)
		return;

	struct ctrl_utils_drain_data *data = ctx;
	pv_ctrl_utils_send_error(data->req, data->code, data->msg);
}

void pv_ctrl_utils_drain_on_arrive_with_ok(struct evhttp_request *req)
{
	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_utils_drain_ok_callback, req);
}

void pv_ctrl_utils_drain_on_arrive_with_err(struct evhttp_request *req,
					    int code, const char *err_str)
{
	struct ctrl_utils_drain_data *data =
		calloc(1, sizeof(struct ctrl_utils_drain_data));
	if (!data) {
		pv_log(DEBUG,
		       "couldn't allocate message data. Request will be "
		       "drain but a 'broken pipe' could happen on the client side");

		evbuffer_add_cb(evhttp_request_get_input_buffer(req),
				ctrl_utils_drain_error_callback, data);
		return;
	}

	data->code = code;
	data->msg = err_str;
	data->req = req;

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_utils_drain_error_callback, data);
}