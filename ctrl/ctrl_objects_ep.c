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
#include "ctrl_upload.h"
#include "ctrl_download.h"
#include "ctrl_file.h"
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

static void ctrl_object_list(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	char *objs = pv_objects_get_list_string();
	if (!objs) {
		pv_log(WARN, "couldn't get device objects");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "couldn't get device objects");
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, objs);
}

static int ctrl_object_upload_complete_cb(struct pv_ctrl_file *file)
{
	if (!file->ok)
		goto out;

	char bname[NAME_MAX] = { 0 };
	pv_fs_basename(file->path, bname);

	pv_log(DEBUG, "checking object integrity");
	if (pv_storage_validate_file_checksum(file->path, bname)) {
		pv_log(WARN, "file upload with errors, checksum error");
		pv_ctrl_utils_send_error(file->req, PV_HTTP_CONFLICT,
					 "Checksum error");

		pv_fs_path_remove(file->path, false);
		return -1;
	}
	pv_log(DEBUG, "object %s stored", file->path);

out:
	pv_ctrl_utils_send_ok(file->req);
	return 0;
}

static void ctrl_object_recv(struct evhttp_request *req, void *ctx)
{
	char err[PV_CTRL_MAX_ERR] = { 0 };
	int code = pv_ctrl_utils_is_req_ok(req, ctx, err);
	if (code != 0) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, err);
		return;
	}

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
		pv_ctrl_utils_drain_on_arrive_with_ok(req);
		return;
	}

	pv_log(DEBUG, "new object received, uploading");

	pv_ctrl_upload_start(req, fname, ctrl_object_upload_complete_cb);
}

static void ctrl_objects_send(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

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

	pv_ctrl_download_start(req, path, 4096, "application/octet-stream");
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
