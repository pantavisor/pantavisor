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

#include "ctrl_download.h"
#include "ctrl_util.h"
#include "ctrl_file.h"

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>

#include <stdlib.h>
#include <sys/stat.h>

#define MODULE_NAME "ctrl-download"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pv_ctrl_download {
	struct pv_ctrl_file *file;
	ssize_t chunk_size;
	ssize_t cur;
	ssize_t total;
	struct event *timer;
};

static void pv_ctrl_download_free(struct pv_ctrl_download *dl)
{
	if (!dl)
		return;

	if (dl->file)
		pv_ctrl_file_free(dl->file);

	if (dl->timer)
		event_free(dl->timer);

	free(dl);
}

static void ctrl_download_complete_cb(struct evhttp_connection *con, void *ctx)
{
	struct pv_ctrl_download *dl = ctx;
	if (!dl->file->ok) {
		pv_log(WARN, "couldn't sent file %s", dl->file->path);
	} else {
		pv_log(DEBUG, "file %s sent successfully", dl->file->path);
	}

	pv_ctrl_download_free(dl);
}

static void ctrl_download_send_cb(evutil_socket_t fd, short events, void *ctx)
{
	(void)fd;
	(void)events;

	struct pv_ctrl_download *dl = ctx;

	struct evbuffer_file_segment *seg = evbuffer_file_segment_new(
		dl->file->fd, dl->cur, dl->chunk_size, 0);

	if (!seg) {
		pv_log(DEBUG, "couldn't alloc file chunk");
		return;
	}

	struct evbuffer *buf = evbuffer_new();
	if (!buf) {
		pv_log(DEBUG, "couldn't alloc buffer data");
		goto out;
	}

	if (evbuffer_add_file_segment(buf, seg, 0, -1) != 0) {
		pv_log(DEBUG, "couldn't add data chunk");
		goto out;
	}

	evhttp_send_reply_chunk(dl->file->req, buf);
	dl->cur += dl->chunk_size;

	// file completely read
	if (dl->cur >= dl->total) {
		evhttp_send_reply_end(dl->file->req);
		dl->file->ok = true;
		goto out;
	}

	pv_log(DEBUG, "%zd of %zd bytes send", dl->cur, dl->total);
	// new timer for next chunk
	struct timeval tv = { .tv_sec = 0, .tv_usec = 1 };
	event_add(dl->timer, &tv);

out:
	if (seg)
		evbuffer_file_segment_free(seg);
	if (buf)
		evbuffer_free(buf);
}

static void crtl_download_set_events(struct pv_ctrl_download *dl)
{
	if (dl->timer)
		event_free(dl->timer);

	struct evhttp_connection *con =
		evhttp_request_get_connection(dl->file->req);

	evhttp_connection_set_closecb(con, ctrl_download_complete_cb, dl);

	dl->timer = evtimer_new(evhttp_connection_get_base(con),
				ctrl_download_send_cb, dl);

	struct timeval tv = { .tv_sec = 0, .tv_usec = 1 };
	event_add(dl->timer, &tv);
	evhttp_send_reply_start(dl->file->req, 200, NULL);
}

int pv_ctrl_download_start(struct evhttp_request *req, const char *path,
			   ssize_t chunk_size, const char *content_type)
{
	struct pv_ctrl_download *dl =
		calloc(1, sizeof(struct pv_ctrl_download));

	if (!dl)
		goto err;

	dl->file = pv_ctrl_file_new(req, path, PV_CTRL_FILE_READ);
	if (!dl->file)
		goto err;

	struct evkeyvalq *headers =
		evhttp_request_get_output_headers(dl->file->req);

	if (!evhttp_find_header(headers, "content-type"))
		evhttp_add_header(headers, "content-type", content_type);

	struct stat st = { 0 };
	if (fstat(dl->file->fd, &st) != 0) {
		pv_log(WARN, "stat failed");
		goto err;
	}

	dl->total = st.st_size;
	dl->chunk_size = chunk_size;

	crtl_download_set_events(dl);

	return 0;

err:
	pv_log(WARN, "couldn't create download");
	pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Object allocation error");
	pv_ctrl_download_free(dl);
	return -1;
}