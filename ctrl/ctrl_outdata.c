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

#include "ctrl_outdata.h"
#include "utils/fs.h"

#include <event.h>
#include <event2/http.h>

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
					    void *user_data)
{
	if (!req || !path)
		return NULL;

	struct pv_ctrl_outdata *data =
		calloc(1, sizeof(struct pv_ctrl_outdata));

	if (!data)
		return NULL;

	data->fd = open(path, O_RDONLY | O_CLOEXEC);
	if (data->fd < 0)
		goto err;

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
	if (!buf)
		goto out;

	size_t size = pv_fs_file_read_nointr(data->fd, buf, data->chunk_size);

	if (size < 1) {
		evhttp_send_reply_end(data->req);
		goto out;
	}

	struct evbuffer *evbuf = evbuffer_new();
	evbuffer_add(evbuf, buf, size);
	evhttp_send_reply_chunk(data->req, evbuf);
	evbuffer_free(evbuf);

	event_add(data->timer, NULL);

out:
	if (buf)
		free(buf);
}

void pv_ctrl_outdata_start(struct pv_ctrl_outdata *data, send_data_cb send_cb,
			   clean_up_cb clean_cb)
{
	struct evhttp_connection *con =
		evhttp_request_get_connection(data->req);

	clean_up_cb ccb = outdata_generic_cleanup_cb;
	if (clean_cb)
		ccb = clean_cb;

	evhttp_connection_set_closecb(con, ccb, data);

	struct evkeyvalq *headers =
		evhttp_request_get_output_headers(data->req);

	if (!evhttp_find_header(headers, "Content-Type")) {
		evhttp_add_header(headers, "Content-Type",
				  PV_CTRL_OUTDATA_DEFAULT_CONTENT_TYPE);
	}

	send_data_cb scb = outdata_generic_send_cb;
	if (send_cb)
		scb = send_cb;

	data->timer = evtimer_new(evhttp_connection_get_base(con), scb, data);

	event_add(data->timer, NULL);
}
