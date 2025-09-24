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

#ifndef PV_CTRL_OUTDATA_H
#define PV_CTRL_OUTDATA_H

#include <event2/util.h>

#include <linux/limits.h>
#include <stddef.h>
#include <stdbool.h>

struct event;
struct evhttp_request;
struct evhttp_connection;

struct pv_ctrl_outdata {
	int fd;
	char path[PATH_MAX];
	size_t chunk_size;
	bool ok;
	struct evhttp_request *req;
	struct event *timer;
	void *data;
};

typedef void (*send_data_cb)(evutil_socket_t fd, short events, void *ctx);
typedef void (*clean_up_cb)(struct evhttp_connection *con, void *ctx);

struct pv_ctrl_outdata *pv_ctrl_outdata_new(struct evhttp_request *req,
					    const char *path, size_t chunk_size,
					    void *user_data);

void pv_ctrl_outdata_free(struct pv_ctrl_outdata *data);
void pv_ctrl_outdata_start(struct pv_ctrl_outdata *data, send_data_cb send_cb,
			   clean_up_cb clean_cb);

#endif
