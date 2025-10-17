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

#include "ctrl/ctrl_outdata.h"
#include "ctrl/ctrl_utils.h"
#include "utils/fs.h"

#include <event.h>
#include <event2/http.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define MODULE_NAME "ctrl"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_CTRL_OUTDATA_DEFAULT_CHUNK_SIZE 8192
#define PV_CTRL_OUTDATA_DEFAULT_CONTENT_TYPE "application/octet-stream"

struct pv_ctrl_outdata *pv_ctrl_outdata_new(struct evhttp_request *req,
					    const char *path, size_t chunk_size,
					    void *user_data, bool create)
{
	if (!req || !path)
		return NULL;

	struct pv_ctrl_outdata *data =
		calloc(1, sizeof(struct pv_ctrl_outdata));

	if (!data) {
		pv_log(WARN, "couldn't send file, outdata allocation failed");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error sending file");
		return NULL;
	}

	errno = 0;

	if (create)
		data->fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	else
		data->fd = open(path, O_RDONLY);

	if (data->fd < 0) {
		pv_log(WARN, "couldn't send file, open file failed %s",
		       strerror(errno));
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Resource does not exist");
		goto err;
	}

	data->chunk_size = chunk_size > 0 ? chunk_size :
					    PV_CTRL_OUTDATA_DEFAULT_CHUNK_SIZE;

	memccpy(data->path, path, '\0', PATH_MAX);
	data->data = user_data;
	data->ok = true;

	evhttp_request_own(req);
	data->req = req;

	return data;
err:
	pv_ctrl_outdata_free(data);
	return NULL;
}

void pv_ctrl_outdata_free(struct pv_ctrl_outdata *data)
{
	if (!data)
		return;

	if (data->timer)
		event_free(data->timer);

	if (data->req)
		evhttp_request_free(data->req);

	close(data->fd);
	free(data);
}

static void outdata_generic_cleanup_cb(struct evhttp_connection *con, void *ctx)
{
	(void)con;

	struct pv_ctrl_outdata *data = ctx;
	if (!data->ok) {
		pv_log(WARN, "couldn't sent file %s", data->path);
	} else {
		pv_log(DEBUG, "file %s sent successfully", data->path);
	}

	pv_ctrl_outdata_free(data);
}

static void outdata_generic_send_cb(evutil_socket_t fd, short events, void *ctx)
{
	(void)fd;
	(void)events;

	struct pv_ctrl_outdata *data = ctx;

	char *buf = calloc(data->chunk_size, sizeof(char));
	if (!buf) {
		pv_log(DEBUG, "couldn't alloc data");
		goto out;
	}

	size_t size = pv_fs_file_read_nointr(data->fd, buf, data->chunk_size);

	if (size < 0) {
		pv_log(DEBUG, "couldn't read data");
		evhttp_send_reply_end(data->req);
		data->req = NULL;
		data->ok = false;
		goto out;
	} else if (size == 0) {
		evhttp_send_reply_end(data->req);
		data->ok = true;
		data->req = NULL;
		goto out;
	} else {
		struct evbuffer *evbuf = evbuffer_new();
		evbuffer_add(evbuf, buf, size);
		evhttp_send_reply_chunk(data->req, evbuf);
		evbuffer_free(evbuf);

		struct timeval tv = { .tv_sec = 0, .tv_usec = 1 };
		event_add(data->timer, &tv);
	}

out:
	if (buf)
		free(buf);
}

void pv_ctrl_outdata_start(struct pv_ctrl_outdata *data,
			   event_callback_fn send_cb, clean_up_cb clean_cb)
{
	struct evhttp_connection *con =
		evhttp_request_get_connection(data->req);

	// struct bufferevent *bev = evhttp_connection_get_bufferevent(con);
	// if (!bev) {
	// 	pv_log(DEBUG, "=== NO BEV POSSIBLE");
	// }

	clean_up_cb ccb = outdata_generic_cleanup_cb;
	if (clean_cb)
		ccb = clean_cb;

	evhttp_connection_set_closecb(con, ccb, data);

	struct evkeyvalq *headers =
		evhttp_request_get_output_headers(data->req);

	// TODO: set better content type!!!!
	if (!evhttp_find_header(headers, "Content-Type")) {
		evhttp_add_header(headers, "Content-Type",
				  PV_CTRL_OUTDATA_DEFAULT_CONTENT_TYPE);
	}

	struct evkeyvalq *h = evhttp_request_get_input_headers(data->req);
	data->size = atoi(evhttp_find_header(headers, "Content-Length"));

	event_callback_fn scb = outdata_generic_send_cb;
	if (send_cb)
		scb = send_cb;

	struct timeval tv = { .tv_sec = 0, .tv_usec = 1 };

	data->timer = evtimer_new(evhttp_connection_get_base(con), scb, data);
	event_add(data->timer, &tv);
	evhttp_send_reply_start(data->req, 200, NULL);
}