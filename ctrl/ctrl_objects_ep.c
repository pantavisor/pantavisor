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

#include "ctrl_endpoints.h"
#include "ctrl.h"
#include "ctrl_callback.h"
#include "ctrl_util.h"
#include "utils/fs.h"
#include "objects.h"
#include "paths.h"
#include "storage.h"

#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/event.h>

#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>

#define MODULE_NAME "objects-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

enum file_type { FILE_IN, FILE_OUT };

struct ctrl_object_file {
	int fd;
	char fname[PATH_MAX];
	char tmp[PATH_MAX];
	struct evhttp_request *req;
};

struct ctrl_object_file_out {
	struct ctrl_object_file *file;
	size_t chunk_sz;
	bool ok;
	struct event *timer;
};

static void ctrl_object_list(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	char *objs = pv_objects_get_list_string();
	if (!objs) {
		pv_log(WARN, "couldn't get device objects");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "couldn't get device objects");
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, objs);
	free(objs);
}

static void ctrl_object_file_free(struct ctrl_object_file *file)
{
	if (!file)
		return;

	if (file->fd >= 0)
		close(file->fd);
	free(file);
}

static struct ctrl_object_file *ctrl_object_file_new(struct evhttp_request *req,
						     const char *fname,
						     enum file_type type)
{
	struct ctrl_object_file *file =
		calloc(1, sizeof(struct ctrl_object_file));

	if (!file) {
		pv_log(WARN, "couldn't allocate file object");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Object allocation error");
		return NULL;
	}

	memccpy(file->fname, fname, '\0', PATH_MAX);

	if (type == FILE_OUT) {
		pv_log(DEBUG, "=== OPEN %s", file->fname);
		file->fd = open(file->fname, O_CLOEXEC | O_RDONLY, 0644);

	} else if (type == FILE_IN) {
		pv_paths_tmp(file->tmp, PATH_MAX, file->fname);
		file->fd = open(file->tmp,
				O_CREAT | O_TRUNC | O_CLOEXEC | O_WRONLY, 0644);
	} else {
		pv_log(DEBUG, "couldn't create file of unknown type");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Internal error");
		goto err;
	}

	if (file->fd < 0) {
		pv_log(WARN, "couldn't open file");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Open file error");
		goto err;
	}

	file->req = req;

	return file;
err:
	ctrl_object_file_free(file);
	return NULL;
}

static void ctrl_object_file_out_free(struct ctrl_object_file_out *fout)
{
	if (!fout)
		return;

	ctrl_object_file_free(fout->file);

	free(fout);
}

static struct ctrl_object_file_out *
ctrl_object_file_out_new(struct evhttp_request *req, const char *fname,
			 size_t chunk_sz)
{
	struct ctrl_object_file *file =
		ctrl_object_file_new(req, fname, FILE_OUT);

	struct ctrl_object_file_out *fout =
		calloc(1, sizeof(struct ctrl_object_file_out));

	if (!fout) {
		pv_log(WARN, "couldn't allocate file out structure");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Internal error");
		goto err;
	}

	fout->file = file;
	fout->ok = true;
	fout->chunk_sz = chunk_sz;

	return fout;
err:
	ctrl_object_file_free(file);
	if (fout)
		free(fout);
	return NULL;
}

static void ctrl_object_upload_complete_cb(struct evbuffer *buf,
					   const struct evbuffer_cb_info *info,
					   void *ctx)
{
	(void)info;

	size_t len = evbuffer_get_length(buf);

	pv_log(DEBUG, "=== COMPLETED!!!!! %zd", len);
	if (len <= 0)
		return;

	// evbuffer_remove_cb(buf, ctrl_object_upload_complete_cb, ctx);
	evbuffer_drain(buf, len);

	struct ctrl_object_file *file = ctx;

	if (rename(file->tmp, file->fname) != 0) {
		pv_log(WARN,
		       "couldn't move temp file %s to final destination %s",
		       file->tmp, file->fname);

		pv_ctrl_utils_send_error(file->req, HTTP_INTERNAL,
					 "File couldn't be saved");
		goto out;
	}

	char bname[NAME_MAX] = { 0 };
	pv_fs_basename(file->fname, bname);

	if (pv_storage_validate_file_checksum(file->fname, bname) != 0) {
		pv_log(WARN, "file upload with errors, checksum error");
		pv_ctrl_utils_send_error(file->req, HTTP_INTERNAL,
					 "Checksum error");

		pv_fs_path_remove(file->fname, false);
		goto out;
	}

	pv_ctrl_utils_send_ok(file->req);
out:
	ctrl_object_file_free(file);
}

static void ctrl_object_upload_read_cb(struct evbuffer *buf,
				       const struct evbuffer_cb_info *info,
				       void *ctx)
{
	(void)info;
	struct ctrl_object_file *file = ctx;

	size_t len = evbuffer_get_length(buf);

	// pv_log(DEBUG, "=== READ!!!!! %zd", len);

	if (len <= 0)
		return;

	evbuffer_write(buf, file->fd);
}

static void ctrl_object_recv(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	// TODO space
	// TODO checksum verification at chunks

	const char *uri = evhttp_request_get_uri(req);

	char parts[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	ssize_t size = pv_ctrl_utils_split_path(uri, parts);

	if (size < 1) {
		pv_log(DEBUG, "couldn't find the objects name");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "No object name provided");
		return;
	}

	char fname[PATH_MAX] = { 0 };
	pv_paths_storage_object(fname, PATH_MAX, parts[1]);

	if (pv_fs_path_exist(fname) &&
	    pv_storage_validate_file_checksum(fname, (char *)parts[1]) == 0) {
		pv_log(WARN,
		       "object %s already exists and is valid; discarding new object upload",
		       fname);

		pv_ctrl_utils_send_ok(req);

		return;
	}

	pv_log(DEBUG, "new object received, uploading");

	struct ctrl_object_file *file =
		ctrl_object_file_new(req, fname, FILE_IN);
	if (!file)
		return;

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_object_upload_read_cb, file);

	evbuffer_add_cb(evhttp_request_get_output_buffer(req),
			ctrl_object_upload_complete_cb, file);
}

static void ctrl_object_send_complete_cb(struct evhttp_connection *con,
					 void *ctx)
{
	struct ctrl_object_file_out *fout = ctx;
	if (!fout->ok) {
		pv_log(WARN, "couldn't sent file %s", fout->file->fname);
	} else {
		pv_log(DEBUG, "file %s sent successfully", fout->file->fname);
	}

	ctrl_object_file_out_free(fout);
}

static void ctrl_object_send_cb(evutil_socket_t fd, short events, void *ctx)
{
	(void)fd;
	(void)events;

	struct ctrl_object_file_out *fout = ctx;

	char *buf = calloc(fout->chunk_sz, sizeof(char));
	if (!buf) {
		pv_log(DEBUG, "couldn't alloc data");
		goto out;
	}

	size_t size =
		pv_fs_file_read_nointr(fout->file->fd, buf, fout->chunk_sz);

	if (size < 0) {
		pv_log(DEBUG, "couldn't read data");
		evhttp_send_reply_end(fout->file->req);
		fout->ok = false;
		goto out;
	} else if (size == 0) {
		evhttp_send_reply_end(fout->file->req);
		fout->ok = true;
		goto out;
	} else {
		struct evbuffer *evbuf = evbuffer_new();
		evbuffer_add(evbuf, buf, size);
		evhttp_send_reply_chunk(fout->file->req, evbuf);
		evbuffer_free(evbuf);

		struct timeval tv = { .tv_sec = 0, .tv_usec = 1 };
		event_add(fout->timer, &tv);
	}
out:
	if (buf)
		free(buf);
}

static void ctrl_objects_send(struct evhttp_request *req, void *ctx)
{
	const char *uri = evhttp_request_get_uri(req);

	char parts[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	ssize_t size = pv_ctrl_utils_split_path(uri, parts);

	if (size < 1) {
		pv_log(DEBUG, "couldn't find the objects name");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "No object name provided");
		return;
	}

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_object(path, PATH_MAX, parts[1]);

	// TODO chunk_sz from config
	struct ctrl_object_file_out *fout =
		ctrl_object_file_out_new(req, path, 4096);

	struct evhttp_connection *con = evhttp_request_get_connection(req);
	evhttp_connection_set_closecb(con, ctrl_object_send_complete_cb, fout);

	struct evkeyvalq *headers =
		evhttp_request_get_output_headers(fout->file->req);

	if (!evhttp_find_header(headers, "Content-Type")) {
		evhttp_add_header(headers, "Content-Type",
				  "application/octet-stream");
	}

	struct timeval tv = { .tv_sec = 0, .tv_usec = 1 };

	fout->timer = evtimer_new(evhttp_connection_get_base(con),
				  ctrl_object_send_cb, fout);
	event_add(fout->timer, &tv);
	evhttp_send_reply_start(fout->file->req, 200, NULL);
}

int pv_ctrl_endpoints_objects_init()
{
	pv_ctrl_add_endpoint("/objects", EVHTTP_REQ_GET, true,
			     ctrl_object_list);

	pv_ctrl_add_endpoint("/objects/{}", EVHTTP_REQ_PUT, true,
			     ctrl_object_recv);

	pv_ctrl_add_endpoint("/objects/{}", EVHTTP_REQ_GET, true,
			     ctrl_objects_send);

	return 0;
}