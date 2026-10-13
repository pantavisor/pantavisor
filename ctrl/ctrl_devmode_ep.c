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
#include "ctrl_util.h"
#include "config.h"
#include "pantavisor.h"
#include "paths.h"
#include "platforms.h"
#include "state.h"
#include "storage.h"
#include "volumes.h"
#include "utils/fs.h"
#include "utils/json.h"

#include <dirent.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>

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

	char path[PATH_MAX] = { 0 };
	ctrl_devmode_inlay_path(pv->state, p, path, PATH_MAX);
	pv_log(INFO, "emptying devmode inlay of %s: %s", p->name, path);
	ctrl_devmode_empty_dir(path);

	pv_ctrl_utils_send_ok(req);
}

int pv_ctrl_endpoints_devmode_init()
{
	pv_ctrl_add_endpoint("/devmode", EVHTTP_REQ_GET, true,
			     ctrl_devmode_get);
	pv_ctrl_add_endpoint("/devmode/containers/{}", EVHTTP_REQ_DELETE, true,
			     ctrl_devmode_inlay_delete);

	return 0;
}
