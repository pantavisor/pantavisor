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

#include "ctrl/incdata.h"
#include "ctrl/utils.h"
#include "storage.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define MODULE_NAME "ctrl-utils"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_CTRL_STORAGE_ERR_BUF 256

void pv_ctrl_incdata_free(struct pv_ctrl_incdata *data)
{
	if (!data)
		return;
	close(data->fd);
}

struct pv_ctrl_incdata *pv_ctrl_incdata_new(const char *path)
{
	if (!path)
		return NULL;

	struct pv_ctrl_incdata *data =
		calloc(1, sizeof(struct pv_ctrl_incdata));

	if (!data)
		goto err;

	data->fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
	if (data->fd < 0)
		goto err;

	memccpy(data->path, path, '\0', PATH_MAX);

err:
	pv_ctrl_incdata_free(data);
	return NULL;
}

static void incdata_generic_read_cb(struct evbuffer *buf,
				    const struct evbuffer_cb_info *info,
				    void *ctx)
{
	struct pv_ctrl_incdata *data = ctx;
	size_t len = evbuffer_get_length(buf);

	pv_log(DEBUG, "upload, %zd received; file: %s", len, data->path);

	if (!data || data->fd < 0) {
		evbuffer_drain(buf, len);
		pv_log(WARN, "data loss, file descriptor error");
		return;
	}

	evbuffer_write(buf, data->fd);
}

static void incdata_generic_complete_cb(struct evhttp_request *req, void *ctx)
{
	struct pv_ctrl_incdata *data = ctx;

	char err_str[PV_CTRL_STORAGE_ERR_BUF] = { 0 };

	if (!pv_storage_verify_state_json(data->path, err_str,
					  PV_CTRL_STORAGE_ERR_BUF)) {
		pv_log(ERROR, "state verification went wrong");
		pv_ctrl_utils_send_error(req, PV_HTTP_UNPROC_CONTENT, err_str);
		pv_storage_rm_rev(data->path);
		goto out;
	}

	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
out:
	pv_ctrl_incdata_free(data);
}

void pv_ctrl_incdata_set_watermark(struct evhttp_request *req, size_t low,
				   size_t high)
{
	struct evhttp_connection *con = evhttp_request_get_connection(req);
	struct bufferevent *bev = evhttp_connection_get_bufferevent(con);
	bufferevent_setwatermark(bev, EV_READ, low, high);
	bufferevent_setwatermark(bev, EV_WRITE, low, high);
}

ssize_t pv_ctrl_incdata_get_size(struct evhttp_request *req)
{
	struct evbuffer *buf = evhttp_request_get_input_buffer(req);
	if (!buf) {
		pv_log(DEBUG, "couldn't get incoming data length");
		return -1;
	}

	return evbuffer_get_length(buf);
}

char *pv_ctrl_incdata_get_data(struct evhttp_request *req, size_t max,
			       size_t *len)
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
					 "Data size exceeds the limit");

		return NULL;
	}

	char *data = calloc(cur_size + 1, sizeof(char));
	if (data) {
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

ssize_t pv_ctrl_incdata_to_file(struct evhttp_request *req, const char *dst,
				pv_ctrl_incdata_read_cb read_cb,
				pv_ctrl_incdata_complete_cb complete_cb,
				void *user_data)
{
	size_t cur_free = pv_storage_get_free();
	size_t cur_size = pv_ctrl_incdata_get_size(req);

	if (cur_size > cur_free) {
		pv_log(WARN,
		       "%zu B needed but only %zu B available. Cannot create file",
		       cur_size, cur_free);
		pv_ctrl_utils_send_error(req, PV_HTTP_INSF_STORAGE,
					 "Not enough disk space available");
		return -1;
	}

	pv_log(DEBUG,
	       "reading file with size %zu from endpoint and putting it in %s",
	       cur_size, dst);

	pv_ctrl_incdata_read_cb rcb = incdata_generic_read_cb;
	if (read_cb)
		rcb = read_cb;

	pv_ctrl_incdata_complete_cb ccb = incdata_generic_complete_cb;
	if (complete_cb)
		ccb = complete_cb;

	struct pv_ctrl_incdata *data = pv_ctrl_incdata_new(dst);
	if (user_data)
		data->user_data = user_data;

	evhttp_request_set_on_complete_cb(req, ccb, data);
	evbuffer_add_cb(evhttp_request_get_input_buffer(req), rcb, data);

	return cur_size;
}