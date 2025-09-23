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

#ifndef PV_CTRL_UTILS_H
#define PV_CTRL_UTILS_H

#include <stdbool.h>
#include <linux/limits.h>

#define PV_CTRL_UTILS_MAX_PARTS (10)
#define PV_CTRL_UTILS_ERR_RSP "{\"Error\":\"%s\"}"

// complementary codes missing in libevent
// always use negatives numbers
enum pv_ctrl_http_code {
	PV_HTTP_INSF_STORAGE = -1,
	PV_HTTP_UNPROC_CONTENT = -2,
};

struct pv_ctrl_sender;
struct evhttp_request;
struct evbuffer;

void pv_ctrl_utils_send_json(struct evhttp_request *req, int code,
			     const char *reason, const char *json, ...);

void pv_ctrl_utils_send_error(struct evhttp_request *req, int code,
			      const char *err_str);

int pv_ctrl_utils_split_path(const char *path,
			     char parts[PV_CTRL_UTILS_MAX_PARTS][NAME_MAX]);

struct pv_ctrl_sender *pv_ctrl_utils_checks(const char *logname,
					    struct evhttp_request *req,
					    int *methods, bool check_mgmt);
#endif
