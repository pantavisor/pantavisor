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

#include "ctrl/sender.h"
#include "ctrl/handler.h"
#include "ctrl/incdata.h"

#include "storage.h"
#include "paths.h"
#include "ctrl/utils.h"
#include "utils/fs.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>
#include <errno.h>
#include <linux/limits.h>
#include <unistd.h>
#include <fcntl.h>

#define MODULE_NAME "steps-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define STEPS_HIGH_WATERMARK (1 * 1024 * 1024)
#define STEPS_LOW_WATERMARK (512 * 1024)

static void steps_list(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	char *steps = pv_storage_get_revisions_string();
	if (!steps) {
		pv_log(WARN, "couldn't get device steps");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "couldn't get device steps");
		goto out;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, steps);

out:
	if (steps)
		free(steps);

	pv_ctrl_sender_free(snd);
}

static void steps_get(struct evhttp_request *req, const char *name)
{
	errno = 0;
	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, name, JSON_FNAME);
	char *step = pv_fs_file_read(path, NULL);

	if (!step) {
		pv_log(DEBUG, "couldn't get json file from %s: %s(%d)", path,
		       strerror(errno), errno);
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "couldn't get requested json");
		goto out;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, step);

out:
	if (step)
		free(step);
}

static void upload_complete_cb(struct evhttp_request *req, void *ctx)
{
	struct pv_ctrl_incdata *data = ctx;

	char err_str[256] = { 0 };

	if (!pv_storage_verify_state_json(data->path, err_str, 256)) {
		pv_log(ERROR, "state verification went wrong");
		pv_ctrl_utils_send_error(req, PV_HTTP_UNPROC_CONTENT, err_str);
		pv_storage_rm_rev(data->path);
		goto out;
	}

	pv_ctrl_utils_send_ok(req);

out:
	pv_ctrl_incdata_free(data);
}

static void steps_add(struct evhttp_request *req, const char *name)
{
	if (!pv_storage_is_revision_local(name)) {
		pv_log(ERROR, "wrong local step name %s", name);
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Step name has bad name");
		return;
	}

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, name, JSON_FNAME);
	pv_fs_mkbasedir_p(path, 0755);

	pv_ctrl_incdata_set_watermark(req, STEPS_LOW_WATERMARK,
				      STEPS_HIGH_WATERMARK);

	pv_ctrl_incdata_to_file(req, name, NULL, upload_complete_cb, NULL);
}

static void steps_name(struct evhttp_request *req, const char *name)
{
	int methods[] = { EVHTTP_REQ_GET, EVHTTP_REQ_PUT, -1 };

	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	if (snd->method == EVHTTP_REQ_GET)
		steps_get(req, name);
	else if (snd->method == EVHTTP_REQ_PUT)
		steps_add(req, name);

	pv_ctrl_sender_free(snd);
}

static void steps_progress(struct evhttp_request *req, const char *name)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pv_file(path, PATH_MAX, name, PROGRESS_FNAME);

	char *prog_json = pv_fs_file_read(path, NULL);
	if (!prog_json) {
		pv_log(ERROR, "%s could not be opened for read", path);
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "Resource does not exist");
		goto out;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, prog_json);
out:
	if (prog_json)
		free(prog_json);

	pv_ctrl_sender_free(snd);
}

static void steps_commit(struct evhttp_request *req, const char *name)
{
	int methods[] = { EVHTTP_REQ_PUT, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pv_file(path, PATH_MAX, name, COMMITMSG_FNAME);

	char tmp[PATH_MAX] = { 0 };
	pv_paths_tmp(tmp, PATH_MAX, path);

	pv_fs_mkbasedir_p(path, 0755);

	size_t len = 0;
	char *data = pv_ctrl_incdata_get_data(req, 2048, &len);
	if (!data)
		return;

	pv_log(DEBUG, "renaming %s to %s", tmp, path);
	if (pv_fs_path_rename(tmp, path) < 0) {
		pv_log(ERROR, "could not rename: %s", strerror(errno));
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot rename commitmsg");
		goto out;
	}

	pv_ctrl_utils_send_ok(req);
out:
	if (data)
		free(data);
}

static int steps_handler(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char parts[PV_CTRL_UTILS_MAX_PARTS][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, parts);

	if (size == 0 || size > 4 || strcmp(parts[0], "steps") != 0)
		return -1;

	// we need to merge locals/name_rev again.
	if (!strcmp(parts[1], "locals")) {
		if (size < 3)
			return -1;

		char buf[PATH_MAX] = { 0 };
		pv_fs_path_concat(buf, 2, parts[1], parts[2]);
		memset(parts[1], 0, NAME_MAX);
		memccpy(parts[1], buf, '\0', NAME_MAX);

		// now move parts[3] to parts[2]
		memset(parts[2], 0, NAME_MAX);
		memccpy(parts[2], parts[3], '\0', NAME_MAX);

		size--;
	}

	if (size == 1) {
		steps_list(req);
	} else if (size == 2) {
		steps_name(req, parts[1]);
	} else if (size == 3) {
		if (!strcmp(parts[3], "progress"))
			steps_progress(req, parts[1]);
		else if (!strcmp(parts[3], "commitmsg"))
			steps_commit(req, parts[1]);
		else
			return -1;
	}

	return 0;
}

struct pv_ctrl_handler steps_hnd = {
	.path = "/steps",
	.fn = steps_handler,
};