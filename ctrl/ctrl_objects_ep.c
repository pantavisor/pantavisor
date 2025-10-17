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

#include "ctrl/ctrl_handler.h"
#include "ctrl/ctrl_utils.h"
// #include "ctrl/ctrl_indata.h"
#include "ctrl/ctrl_sender.h"
#include "ctrl/ctrl_outdata.h"
#include "utils/fs.h"
#include "objects.h"
#include "paths.h"
#include "storage.h"

#include <event2/http.h>

#include <string.h>
#include <linux/limits.h>

#define MODULE_NAME "objects-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define OBJECTS_HIGH_WMK (1 * 1024 * 1024)
#define OBJECTS_LOW_WMK (512 * 1024)

static void objects_list(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	char *objs = pv_objects_get_list_string();
	if (!objs) {
		pv_log(WARN, "couldn't get device objects");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "couldn't get device objects");
		goto out;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, objs);
out:
	if (objs)
		free(objs);

	pv_ctrl_sender_free(snd);
}

static void objects_get(struct evhttp_request *req, const char *name)
{
	pv_log(DEBUG, "CALL GET");
	char path[PATH_MAX] = { 0 };
	pv_paths_storage_object(path, PATH_MAX, name);

	struct pv_ctrl_outdata *data =
		pv_ctrl_outdata_new(req, path, 0, NULL, false);
	if (!data) {
		pv_log(DEBUG, "CALL GET FAIL");

		return;
	}

	pv_ctrl_outdata_start(data, NULL, NULL);
}

static void objects_complete_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "ALL DONE!!!");
	struct pv_ctrl_outdata *data = ctx;

	char base[NAME_MAX] = { 0 };
	pv_fs_basename(data->path, base);

	char *tmp = data->data;

	if (pv_storage_validate_file_checksum(tmp, base) < 0) {
		pv_log(WARN, "object %s has bad checksum", tmp);
		// pv_ctrl_utils_send_error(req, PV_HTTP_UNPROC_CONTENT,
		// 			 "Object has bad checksum");
		goto out;
	}

	pv_log(DEBUG, "renaming %s to %s", tmp, data->path);
	if (pv_fs_path_rename(tmp, data->path) < 0) {
		pv_log(ERROR, "could not rename: %s", strerror(errno));
		// pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
		// 			 "Cannot rename object");
		goto out;
	}

	pv_storage_gc_defer_run_threshold();
	// pv_ctrl_utils_send_ok(req);
out:
	if (tmp)
		free(tmp);
	pv_ctrl_outdata_free(data);
}

static void complete_dummy_cb(struct evhttp_connection *con, void *ctx)
{
	pv_log(DEBUG, "=== complete!!!");

	struct pv_ctrl_outdata *d = ctx;
	free(d->data);

	pv_ctrl_outdata_free(d);
}

static void read_dummy_cb(evutil_socket_t fd, short events, void *ctx)
{
	pv_log(DEBUG, "=== SEND!!!");
	struct pv_ctrl_outdata *d = ctx;
	int *n = d->data;
	*n = *n + 1;

	// if (*n == 5) {
	// 	struct evbuffer *buf = evhttp_request_get_input_buffer(d->req);
	// 	evbuffer_drain(buf, evbuffer_get_length(buf));
	// 	evhttp_send_reply_end(d->req);

	// } else {
	// char buf[3] = { 0 };

	struct evbuffer *buf = evhttp_request_get_input_buffer(d->req);
	int x = evbuffer_write_atmost(buf, d->fd, 3);
	d->size -= x;
	// struct evhttp_connection *con =
	// 	evhttp_request_get_connection(d->req);
	// if (!con) {
	// 	pv_log(DEBUG, "=== NO CON POSSIBLE");
	// 	goto next;
	// }

	// struct bufferevent *bev =
	// 	evhttp_connection_get_bufferevent(con);
	// if (!bev) {
	// 	pv_log(DEBUG, "=== NO BEV POSSIBLE");
	// 	goto next;
	// }

	// evutil_socket_t sock = bufferevent_getfd(bev);
	// if (sock < 0) {
	// 	pv_log(DEBUG, "=== NO sock POSSIBLE");
	// 	goto next;
	// }
	if (d->size > 0) {
		struct timeval tv = { .tv_sec = 0, .tv_usec = 1 };
		event_add(d->timer, &tv);
	} else {
		evhttp_send_reply_end(d->req);
	}
	// }
}

static void objects_set(struct evhttp_request *req, const char *name)
{
	char path[PATH_MAX] = { 0 };
	pv_paths_storage_object(path, PATH_MAX, name);

	char tmp[PATH_MAX] = { 0 };
	pv_paths_tmp(tmp, PATH_MAX, path);

	if (pv_fs_path_exist(path) &&
	    pv_storage_validate_file_checksum(path, (char *)name) == 0) {
		pv_log(WARN,
		       "object %s already exists and is valid; discarding new object upload",
		       path);
		pv_fs_path_remove(tmp, false);
		pv_ctrl_utils_drain_req(req);

		pv_ctrl_utils_send_ok(req);
		return;
	}

	pv_log(DEBUG, "=== new file!!!!");

	int *n = calloc(1, sizeof(int));

	struct pv_ctrl_outdata *data =
		pv_ctrl_outdata_new(req, path, 0, n, true);
	if (!data) {
		pv_log(DEBUG, "CALL GET FAIL");

		return;
	}

	pv_ctrl_outdata_start(data, read_dummy_cb, complete_dummy_cb);

	// struct pv_ctrl_indata *data = pv_ctrl_indata_new(req, tmp, 4096, NULL);
	// if (!data) {
	// 	return;
	// }

	// pv_log(DEBUG, "=== data created!");

	// pv_ctrl_indata_to_file(data, NULL, NULL);

	// pv_ctrl_indata_set_watermark(req, OBJECTS_LOW_WMK, OBJECTS_HIGH_WMK);
	// ssize_t size = pv_ctrl_indata_to_file(req, tmp, NULL,
	// 				      objects_complete_cb, strdup(tmp));

	// pv_ctrl_utils_send_ok(req);
	// if (size < 0)
	// 	pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Unknown error");
	// else
	// 	pv_ctrl_utils_send_ok(req);
}

static void objects_ops(struct evhttp_request *req, const char *name)
{
	if (strlen(name) != 64) {
		pv_log(WARN, "HTTP request has bad object name %s", name);

		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Request has bad object name");
		return;
	}

	int methods[] = { EVHTTP_REQ_GET, EVHTTP_REQ_PUT, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	if (snd->method == EVHTTP_REQ_GET)
		objects_get(req, name);
	else if (snd->method == EVHTTP_REQ_PUT)
		objects_set(req, name);

	pv_ctrl_sender_free(snd);
}

static int objects_handler(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char parts[PV_CTRL_UTILS_MAX_PARTS][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, parts);

	pv_log(DEBUG, "=== size : %zd", size);
	pv_log(DEBUG, "=== part0: %s", parts[0]);

	if (size == 0 || size > 2 || strcmp(parts[0], "objects") != 0)
		return -1;

	if (size == 1)
		objects_list(req);
	else
		objects_ops(req, parts[1]);

	return 0;
}

struct pv_ctrl_handler object_hnd = {
	.path = "/objects",
	.fn = objects_handler,
};