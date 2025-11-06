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

#include "ctrl_upload.h"
#include "ctrl_file.h"
#include "ctrl_util.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <stdlib.h>

#define MODULE_NAME "ctrl_upload"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct ctrl_upload {
	struct pv_ctrl_file *file;
	pv_ctrl_upload_complete_func complete_cb;
};

static void ctrl_upload_free(struct ctrl_upload *up)
{
	if (!up)
		return;

	if (up->file)
		pv_ctrl_file_free(up->file);
	free(up);
}

static void ctrl_upload_complete_cb_caller(struct evbuffer *buf,
					   const struct evbuffer_cb_info *info,
					   void *ctx)
{
	size_t len = evbuffer_get_length(buf);

	pv_log(DEBUG, "=== COMPLETE CALLED %zd", len);

	if (len <= 0)
		return;

	char *x = (char *)evbuffer_pullup(buf, len);

	pv_log(DEBUG, "=== PULL: %s", x);

	evbuffer_drain(buf, len);

	struct ctrl_upload *up = ctx;

	pv_log(DEBUG, "upload done, processing file");

	if (up->complete_cb)
		up->complete_cb(up->file);

	ctrl_upload_free(up);
}

static void ctrl_upload_read_cb(struct evbuffer *buf,
				const struct evbuffer_cb_info *info, void *ctx)
{
	(void)info;
	struct ctrl_upload *up = ctx;

	size_t len = evbuffer_get_length(buf);

	pv_log(DEBUG, "=== READ!!!!! %zd", len);

	if (len > 0)
		evbuffer_write(buf, up->file->fd);
}

int pv_ctrl_upload_start(struct evhttp_request *req, const char *path,
			 pv_ctrl_upload_complete_func complete_cb)
{
	struct ctrl_upload *up = calloc(1, sizeof(struct ctrl_upload));
	if (!up)
		goto err;

	up->file = pv_ctrl_file_new(req, path, PV_CTRL_FILE_WRITE);

	if (!up->file)
		goto err;

	if (complete_cb)
		up->complete_cb = complete_cb;

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_upload_read_cb, up);

	evbuffer_add_cb(evhttp_request_get_output_buffer(req),
			ctrl_upload_complete_cb_caller, up);

	return 0;

err:
	ctrl_upload_free(up);
	pv_log(WARN, "couldn't allocate file");
	pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Upload error");

	return -1;
}