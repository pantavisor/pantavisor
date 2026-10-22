/*
 * Copyright (c) 2026 Pantacor Ltd.
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
#include "ctrl_cmd.h"
#include "ctrl_util.h"
#include "bootloader.h"
#include "config.h"
#include "pantavisor.h"
#include "paths.h"
#include "platforms.h"
#include "state.h"
#include "storage.h"
#include "volumes.h"
#include "update/update.h"
#include "utils/fs.h"
#include "utils/json.h"

#include <dirent.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/http.h>

#define MODULE_NAME "devmode-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static bool ctrl_devmode_is_active(struct pantavisor *pv)
{
	return pv->state && pv_storage_is_revision_devmode(pv->state->rev);
}

// on failure the error is sent and false returned
static bool ctrl_devmode_check_active(struct evhttp_request *req,
				      struct pantavisor *pv)
{
	if (!pv_config_get_bool(PV_DEVMODE_ALLOWED)) {
		pv_ctrl_utils_send_error(
			req, HTTP_FORBIDDEN,
			"Devmode is disabled, enable PV_DEVMODE_ALLOWED in pantavisor.config or the OEM config");
		return false;
	}

	if (!ctrl_devmode_is_active(pv)) {
		pv_ctrl_utils_send_error(req, PV_HTTP_CONFLICT,
					 "Not running a devmode revision");
		return false;
	}

	return true;
}

static void ctrl_devmode_inlay_path(struct pv_state *s, struct pv_platform *p,
				    char *buf, size_t size)
{
	struct pv_volume *v, *tmp;

	dl_list_for_each_safe(v, tmp, &s->volumes, struct pv_volume, list)
	{
		if (v->plat == p && v->src &&
		    !strcmp(v->name, DEVMODE_INLAY_DNAME)) {
			snprintf(buf, size, "%s", v->src);
			return;
		}
	}

	pv_paths_storage_disks_rev_file(buf, size, s->rev, p->name,
					DEVMODE_INLAY_DNAME);
}

// the inlay relative to the storage root, which mgmt containers see at /storage
static const char *ctrl_devmode_storage_rel(const char *inlay)
{
	char root[PATH_MAX] = { 0 };
	size_t len;

	pv_paths_storage(root, PATH_MAX);
	len = strlen(root);
	while (len && root[len - 1] == '/')
		len--;

	if (!len || strncmp(inlay, root, len) || inlay[len] != '/')
		return "";

	inlay += len;
	while (*inlay == '/')
		inlay++;

	return inlay;
}

static void ctrl_devmode_get(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	struct pantavisor *pv = pv_get_instance();
	bool active = ctrl_devmode_is_active(pv);
	struct pv_json_ser js;

	pv_json_ser_init(&js, 512);
	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "enabled");
		pv_json_ser_bool(&js, pv_config_get_bool(PV_DEVMODE_ALLOWED));
		pv_json_ser_key(&js, "active");
		pv_json_ser_bool(&js, active);

		if (active) {
			char *base =
				pv_storage_get_devmode_base(pv->state->rev);
			struct pv_platform *p, *tmp;

			pv_json_ser_key(&js, "revision");
			pv_json_ser_string(&js, pv->state->rev);
			pv_json_ser_key(&js, "base");
			pv_json_ser_string(&js, base ? base : "");
			free(base);

			pv_json_ser_key(&js, "containers");
			pv_json_ser_array(&js);
			{
				dl_list_for_each_safe(p, tmp,
						      &pv->state->platforms,
						      struct pv_platform, list)
				{
					char path[PATH_MAX] = { 0 };

					if (!p->devmode_inlay)
						continue;

					ctrl_devmode_inlay_path(pv->state, p,
								path, PATH_MAX);
					pv_json_ser_object(&js);
					{
						pv_json_ser_key(&js, "name");
						pv_json_ser_string(&js,
								   p->name);
						pv_json_ser_key(&js, "inlay");
						pv_json_ser_string(&js, path);
						pv_json_ser_key(
							&js, "inlay_storage");
						pv_json_ser_string(
							&js,
							ctrl_devmode_storage_rel(
								path));
						pv_json_ser_object_pop(&js);
					}
				}
				pv_json_ser_array_pop(&js);
			}
		}

		pv_json_ser_object_pop(&js);
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, pv_json_ser_str(&js));
}

static void ctrl_devmode_empty_dir(const char *path)
{
	struct dirent **arr = NULL;
	int n = scandir(path, &arr, NULL, alphasort);

	for (int i = 0; i < n; i++) {
		char child[PATH_MAX] = { 0 };

		if (strcmp(arr[i]->d_name, ".") &&
		    strcmp(arr[i]->d_name, "..")) {
			pv_fs_path_concat(child, 2, path, arr[i]->d_name);
			pv_fs_path_remove(child, arr[i]->d_type == DT_DIR);
		}
		free(arr[i]);
	}
	free(arr);
}

static void ctrl_devmode_inlay_delete(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	struct pantavisor *pv = pv_get_instance();
	if (!ctrl_devmode_check_active(req, pv))
		return;

	char parts[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(evhttp_request_get_uri(req), parts);
	if (size < 3) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Missing container name");
		return;
	}

	struct pv_platform *p = pv_state_fetch_platform(pv->state, parts[2]);
	if (!p || !p->devmode_inlay) {
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "Container not found");
		return;
	}

	char path[PATH_MAX] = { 0 }, work[PATH_MAX] = { 0 };
	ctrl_devmode_inlay_path(pv->state, p, path, PATH_MAX);
	pv_log(INFO, "emptying devmode inlay of %s: %s", p->name, path);
	// the folder is an overlay of the inlay: take it away, clear the inlay
	// with its whiteouts and the overlay work directory, and mount it again
	pv_volumes_devmode_fs_umount(p);
	ctrl_devmode_empty_dir(path);
	snprintf(work, sizeof(work), "%s.work", path);
	pv_fs_path_remove(work, true);
	pv_volumes_devmode_fs_mount(pv->state, p);

	pv_ctrl_utils_send_ok(req);
}

#define CTRL_DEVMODE_MAX_BODY (4096)

static void ctrl_devmode_send_session(struct evhttp_request *req,
				      const char *name, const char *base,
				      bool resumed, bool running, bool reboot)
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, 512);
	pv_json_ser_object(&js);
	pv_json_ser_key(&js, "revision");
	pv_json_ser_string(&js, name);
	pv_json_ser_key(&js, "base");
	pv_json_ser_string(&js, base);
	pv_json_ser_key(&js, "resumed");
	pv_json_ser_bool(&js, resumed);
	if (running) {
		pv_json_ser_key(&js, "running");
		pv_json_ser_bool(&js, true);
	}
	if (reboot) {
		pv_json_ser_key(&js, "reboot");
		pv_json_ser_bool(&js, true);
	}
	pv_json_ser_object_pop(&js);

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, pv_json_ser_str(&js));
}

// the devmode revision for a base: devmode/r/<number> or devmode/l/<name>
static const char *ctrl_devmode_name(const char *base, char *name, size_t size)
{
	if (!strncmp(base, PREFIX_DEVMODE_LOCAL_REV,
		     strlen(PREFIX_DEVMODE_LOCAL_REV)) ||
	    !strncmp(base, PREFIX_DEVMODE_REMOTE_REV,
		     strlen(PREFIX_DEVMODE_REMOTE_REV)))
		return "a devmode revision cannot be the base of another one";

	if (!strncmp(base, PREFIX_LOCAL_REV, strlen(PREFIX_LOCAL_REV)))
		snprintf(name, size, "%s%s", PREFIX_DEVMODE_LOCAL_REV,
			 base + strlen(PREFIX_LOCAL_REV));
	else if (*base && strspn(base, "0123456789") == strlen(base))
		snprintf(name, size, "%s%s", PREFIX_DEVMODE_REMOTE_REV, base);
	else
		name[0] = '\0';

	if (!pv_storage_is_revision_devmode(name))
		return "base must be a revision number or locals/<name>";

	return NULL;
}

// copy the state of the base into the devmode revision, like a PUT of it does
static const char *ctrl_devmode_store_state(const char *base, const char *name,
					    int *code)
{
	char path[PATH_MAX] = { 0 };
	char msg[PV_CTRL_MAX_ERR] = { 0 };
	char *json = pv_storage_get_state_json(base);

	*code = HTTP_INTERNAL;
	if (!json)
		return "Cannot read the state of the base";

	pv_update_pre_install(name);
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, name, JSON_FNAME);
	if (pv_fs_file_save(path, json, 0644)) {
		free(json);
		return "Cannot write the devmode revision";
	}
	free(json);
	pv_update_post_install(name);

	if (!pv_storage_verify_state_json(name, msg, sizeof(msg))) {
		// keep the inlay, like a refused PUT does
		pv_paths_storage_trail(path, PATH_MAX, name);
		pv_fs_path_remove(path, true);
		*code = PV_HTTP_UNPROC_CONTENT;
		return "State of the base does not verify";
	}

	return NULL;
}

static void ctrl_devmode_start(struct evhttp_request *req, const char *data)
{
	struct pantavisor *pv = pv_get_instance();
	char name[NAME_MAX] = { 0 };
	char path[PATH_MAX] = { 0 };
	char *base = NULL, *resume_str = NULL;
	jsmntok_t *tokv = NULL;
	int tokc = 0;
	bool resume = false, exists, reboot;
	const char *err;
	int code;

	if (data && *data) {
		if (jsmnutil_parse_json(data, &tokv, &tokc) <= 0 || !tokv ||
		    tokv[0].type != JSMN_OBJECT) {
			pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
						 "Body must be a JSON object");
			goto out;
		}
		base = pv_json_get_value_toplevel(data, "base", tokv, tokc);
		resume_str =
			pv_json_get_value_toplevel(data, "resume", tokv, tokc);
		resume = resume_str && !strcmp(resume_str, "true");
	}

	if (!pv_config_get_bool(PV_DEVMODE_ALLOWED)) {
		pv_ctrl_utils_send_error(
			req, HTTP_FORBIDDEN,
			"Devmode is disabled, enable PV_DEVMODE_ALLOWED in pantavisor.config or the OEM config");
		goto out;
	}

	if (!pv || !pv->state) {
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Internal Error");
		goto out;
	}

	// no base: the committed revision, which a devmode revision falls back to
	if (!base || !*base) {
		const char *committed = pv->state->rev;

		free(base);
		if (ctrl_devmode_is_active(pv))
			committed = pv_bootloader_get_done();
		base = committed ? strdup(committed) : NULL;
		if (!base) {
			pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
						 "No committed revision");
			goto out;
		}
	}

	err = ctrl_devmode_name(base, name, sizeof(name));
	if (err) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, err);
		goto out;
	}

	pv_paths_storage_trail(path, PATH_MAX, base);
	if (!pv_fs_path_exist(path)) {
		char msg[PV_CTRL_MAX_ERR] = { 0 };

		snprintf(msg, sizeof(msg), "Revision %s not found", base);
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND, msg);
		goto out;
	}

	// the session goes on, nothing changes
	if (pv->state->rev && !strcmp(pv->state->rev, name)) {
		ctrl_devmode_send_session(req, name, base, true, true, false);
		goto out;
	}

	if (pv->update || pv->cmd) {
		pv_ctrl_utils_send_error(
			req, PV_HTTP_CONFLICT,
			"Cannot do this operation while update is ongoing");
		goto out;
	}

	pv_paths_storage_trail(path, PATH_MAX, name);
	exists = pv_fs_path_exist(path);
	if (exists && !resume) {
		pv_log(INFO, "removing devmode revision %s to start clean",
		       name);
		pv_storage_rm_rev(name);
	}

	err = ctrl_devmode_store_state(base, name, &code);
	if (err) {
		pv_ctrl_utils_send_error(req, code, err);
		goto out;
	}

	reboot = pv_storage_is_devmode_change(pv->state->rev, name);

	struct pv_ctrl_cmd *cmd = calloc(1, sizeof(struct pv_ctrl_cmd));
	if (cmd) {
		cmd->op = CMD_LOCAL_RUN;
		cmd->payload = strdup(name);
	}
	if (!cmd || !cmd->payload) {
		pv_ctrl_cmd_free(cmd);
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Out of memory");
		goto out;
	}

	struct pv_ctrl_cmd_add_result rs = pv_ctrl_cmd_add(cmd);
	if (!rs.ok) {
		pv_ctrl_cmd_free(cmd);
		pv_ctrl_utils_send_error(req, rs.code,
					 rs.err ? rs.err : "unknown error");
		goto out;
	}

	pv_log(INFO, "starting devmode revision %s based on %s", name, base);
	ctrl_devmode_send_session(req, name, base, exists && resume, false,
				  reboot);
out:
	free(base);
	free(resume_str);
	free(tokv);
}

static void ctrl_devmode_post_body(struct evbuffer *buf,
				   const struct evbuffer_cb_info *info,
				   void *ctx)
{
	struct evhttp_request *req = ctx;
	char *data;

	if (!info->n_added || !pv_ctrl_utils_has_all_data(req))
		return;

	evbuffer_remove_cb(buf, ctrl_devmode_post_body, ctx);

	data = pv_ctrl_utils_get_data(req, CTRL_DEVMODE_MAX_BODY, NULL);
	if (!data)
		return;

	ctrl_devmode_start(req, data);
	free(data);
}

static void ctrl_devmode_post(struct evhttp_request *req, void *ctx)
{
	char err[PV_CTRL_MAX_ERR] = { 0 };
	int code = pv_ctrl_utils_is_req_ok(req, ctx, err);
	ssize_t cl;

	if (code != 0) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, err);
		return;
	}

	cl = pv_ctrl_utils_get_content_length(req);
	if (cl > CTRL_DEVMODE_MAX_BODY) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, HTTP_BADREQUEST,
						       "The body is too large");
		return;
	}
	if (cl <= 0) {
		ctrl_devmode_start(req, NULL);
		return;
	}

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_devmode_post_body, req);
}

int pv_ctrl_endpoints_devmode_init()
{
	pv_ctrl_add_endpoint("/devmode", EVHTTP_REQ_GET, true,
			     ctrl_devmode_get);
	pv_ctrl_add_endpoint("/devmode", EVHTTP_REQ_POST, true,
			     ctrl_devmode_post);
	pv_ctrl_add_endpoint("/devmode/containers/{}", EVHTTP_REQ_DELETE, true,
			     ctrl_devmode_inlay_delete);

	return 0;
}
