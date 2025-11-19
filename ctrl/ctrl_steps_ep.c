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
#include "ctrl_upload.h"
#include "ctrl_file.h"
#include "ctrl_util.h"
#include "storage.h"
#include "paths.h"
#include "utils/fs.h"

#include <event2/http.h>

#include <string.h>

#define MODULE_NAME "steps-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define CTRL_STEPS_MAX_MSG_LEN (256)
#define CTRL_STEPS_COMMIT_MSG_MAX (256)

static void ctrl_steps_list(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	char *steps = pv_storage_get_revisions_string();
	if (!steps) {
		pv_log(WARN, "couldn't get device steps");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "couldn't get device steps");
		return;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, steps);
}

static char *ctrl_steps_rev_name(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char parts[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, parts);

	if (size < 2) {
		pv_log(DEBUG, "HTTP request has bad step name: %s", uri);
		return NULL;
	}

	// first element is the endpoint name and +2 for the initial two /
	// e.g: /steps/locals/nnnn
	//      |_____|
	//  this is removed
	const char *name = uri + strlen(parts[0]) + 2;
	const char *end = strstr(name, "/progress");
	if (!end)
		end = strstr(name, "/commitmsg");

	if (!end)
		return strdup(name);

	return strndup(name, end - name);
}

static void ctrl_steps_send(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	char *name = ctrl_steps_rev_name(req);
	if (!name)
		return;

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, name, JSON_FNAME);

	pv_ctrl_utils_send_json_file(req, path);

	free(name);
}

static int ctrl_steps_upload_complete(struct pv_ctrl_file *file)
{
	if (!file->ok)
		return -1;

	char *name = ctrl_steps_rev_name(file->req);
	char msg[CTRL_STEPS_MAX_MSG_LEN] = { 0 };
	if (!pv_storage_verify_state_json(name, msg, CTRL_STEPS_MAX_MSG_LEN)) {
		pv_log(ERROR, "state verification went wrong");
		pv_ctrl_utils_send_error(file->req, PV_HTTP_UNPROC_CONTENT,
					 msg);
		pv_storage_rm_rev(name);
		free(name);
		return -1;
	}

	free(name);
	pv_ctrl_utils_send_ok(file->req);
	return 0;
}

static void ctrl_steps_recv(struct evhttp_request *req, void *ctx)
{
	char err[PV_CTRL_MAX_ERR] = { 0 };
	int code = pv_ctrl_utils_is_req_ok(req, ctx, err);
	if (code != 0) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, err);
		return;
	}

	char *name = ctrl_steps_rev_name(req);
	if (!name) {
		pv_ctrl_utils_drain_on_arrive_with_err(
			req, HTTP_BADREQUEST, "Request has bad step name");
		return;
	}

	if (!pv_storage_is_revision_local(name)) {
		pv_log(ERROR, "wrong local step name %s", name);
		pv_ctrl_utils_drain_on_arrive_with_err(
			req, HTTP_BADREQUEST, "Request has bas step name");
		goto out;
	}

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, name, JSON_FNAME);
	pv_fs_mkbasedir_p(path, 0775);

	pv_ctrl_upload_start(req, path, ctrl_steps_upload_complete);
out:
	if (name)
		free(name);
}

static void ctrl_steps_progress(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	char *name = ctrl_steps_rev_name(req);

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pv_file(path, PATH_MAX, name, PROGRESS_FNAME);

	pv_ctrl_utils_send_json_file(req, path);

	free(name);
}

static void ctrl_step_commit_cb(struct evbuffer *buf,
				const struct evbuffer_cb_info *info, void *ctx)
{
	(void)buf;
	(void)info;

	struct evhttp_request *req = ctx;
	char *name = ctrl_steps_rev_name(req);

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pv_file(path, PATH_MAX, name, COMMITMSG_FNAME);

	char tmp[PATH_MAX] = { 0 };
	pv_paths_tmp(tmp, PATH_MAX, path);

	pv_fs_mkbasedir_p(path, 0755);

	ssize_t len = 0;
	char *msg =
		pv_ctrl_utils_get_data(req, CTRL_STEPS_COMMIT_MSG_MAX, &len);

	pv_log(DEBUG, "new commit message arrived (%zd): %s", len, msg);

	if (!msg) {
		pv_log(WARN, "no commit message provided");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "No commit message");
		goto out;
	}

	if (pv_fs_file_save(tmp, msg, 0644) < 0) {
		pv_log(WARN, "couldn't write message");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot write message");
		goto out;
	}

	pv_log(DEBUG, "renaming %s to %s", tmp, path);
	if (pv_fs_path_rename(tmp, path) < 0) {
		pv_log(ERROR, "couldn't rename: %s", strerror(errno));
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot rename commitmsg");
		goto out;
	}

	pv_ctrl_utils_send_ok(req);
out:
	if (msg)
		free(msg);
	if (name)
		free(name);
}

static void ctrl_steps_commit(struct evhttp_request *req, void *ctx)
{
	char err[PV_CTRL_MAX_ERR] = { 0 };
	int code = pv_ctrl_utils_is_req_ok(req, ctx, err) != 0;
	if (code != 0) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, err);
		return;
	}

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_step_commit_cb, req);
}

int pv_ctrl_endpoints_steps_init()
{
	pv_ctrl_add_endpoint("/steps", EVHTTP_REQ_GET, true, ctrl_steps_list);
	pv_ctrl_add_endpoint("/steps/{}", EVHTTP_REQ_GET, true,
			     ctrl_steps_send);
	pv_ctrl_add_endpoint("/steps/locals/{}", EVHTTP_REQ_GET, true,
			     ctrl_steps_send);
	pv_ctrl_add_endpoint("/steps/locals/{}", EVHTTP_REQ_PUT, true,
			     ctrl_steps_recv);
	pv_ctrl_add_endpoint("/steps/{}/progress", EVHTTP_REQ_GET, true,
			     ctrl_steps_progress);
	pv_ctrl_add_endpoint("/steps/locals/{}/progress", EVHTTP_REQ_GET, true,
			     ctrl_steps_progress);
	pv_ctrl_add_endpoint("/steps/{}/commitmsg", EVHTTP_REQ_PUT, true,
			     ctrl_steps_commit);
	pv_ctrl_add_endpoint("/steps/locals/{}/commitmsg", EVHTTP_REQ_PUT, true,
			     ctrl_steps_commit);
	return 0;
}