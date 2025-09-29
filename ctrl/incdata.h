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

#ifndef PV_CTRL_INCDATA_H
#define PV_CTRL_INCDATA_H

#include <sys/types.h>
#include <linux/limits.h>

#define PV_CTRL_REQ_MAX (4096)

struct evhttp_request;
struct evbuffer;
struct evbuffer_cb_info;

struct pv_ctrl_incdata {
	int fd;
	char path[PATH_MAX];
	void *user_data;
};

typedef void (*pv_ctrl_incdata_read_cb)(struct evbuffer *,
					const struct evbuffer_cb_info *,
					void *ctx);

typedef void (*pv_ctrl_incdata_complete_cb)(struct evhttp_request *req,
					    void *ctx);

struct pv_ctrl_incdata *pv_ctrl_incdata_new(const char *path);
void pv_ctrl_incdata_free(struct pv_ctrl_incdata *data);

void pv_ctrl_incdata_set_watermark(struct evhttp_request *req, size_t low,
				   size_t high);
ssize_t pv_ctrl_incdata_get_size(struct evhttp_request *req);
char *pv_ctrl_incdata_get_data(struct evhttp_request *req, size_t max,
			       size_t *len);

ssize_t pv_ctrl_incdata_to_file(struct evhttp_request *req, const char *dst,
				pv_ctrl_incdata_read_cb read_cb,
				pv_ctrl_incdata_complete_cb complete_cb,
				void *user_data);

#endif
