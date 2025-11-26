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

#ifndef PV_CTRL_UTIL_H
#define PV_CTRL_UTIL_H

#include <linux/limits.h>
#include <stdbool.h>
#include <sys/types.h>

// complementary codes missing in libevent
// always use negatives numbers
enum pv_ctrl_http_code {
	PV_HTTP_INSF_STORAGE = -1,
	PV_HTTP_UNPROC_CONTENT = -2,
	PV_HTTP_CONFLICT = -3,
};

#define PV_CTRL_MAX_SPLIT (10)
#define PV_CTRL_MAX_ERR (128)

struct evhttp_request;
struct pv_ctrl_cb;

void pv_ctrl_utils_send_json(struct evhttp_request *req, int code,
			     const char *reason, char *json);

void pv_ctrl_utils_send_json_file(struct evhttp_request *req, const char *path);

void pv_ctrl_utils_send_error(struct evhttp_request *req, int code,
			      const char *err_str);

void pv_ctrl_utils_send_ok(struct evhttp_request *req);

int pv_ctrl_utils_split_path(const char *uri,
			     char parts[PV_CTRL_MAX_SPLIT][NAME_MAX]);

int pv_ctrl_utils_is_req_ok(struct evhttp_request *req, struct pv_ctrl_cb *cb,
			    char *err);

ssize_t pv_ctrl_utils_get_content_length(struct evhttp_request *req);

char *pv_ctrl_utils_get_data(struct evhttp_request *req, ssize_t max,
			     ssize_t *len);

void pv_ctrl_utils_drain_req(struct evhttp_request *req);
void pv_ctrl_utils_drain_on_arrive_with_ok(struct evhttp_request *req);
void pv_ctrl_utils_drain_on_arrive_with_err(struct evhttp_request *req,
					    int code, const char *err_str);

#endif
