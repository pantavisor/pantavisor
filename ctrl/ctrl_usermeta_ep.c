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

#include "ctrl/ctrl_sender.h"
#include "ctrl/ctrl_handler.h"
#include "ctrl/ctrl_utils.h"
#include "ctrl/ctrl_indata.h"
#include "metadata.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>
#include <linux/limits.h>

#define MODULE_NAME "usermeta-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_CTRL_MAX_META (4096)

static void usermeta_list(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	char *usermeta = pv_metadata_get_user_meta_string();
	if (!usermeta) {
		pv_log(WARN, "couldn't get user-maeta");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "couldn't get user-meta");
		goto out;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, usermeta);

out:
	if (usermeta)
		free(usermeta);

	pv_ctrl_sender_free(snd);
}

static void usermeta_add_or_update(struct evhttp_request *req, const char *key)
{
	char *value = pv_ctrl_indata_get_data(req, PV_CTRL_MAX_META, NULL);
	if (!value)
		return;
	int ret = pv_metadata_add_usermeta(key, value);

	if (ret != 0) {
		pv_log(DEBUG, "couldn't add new key: %s, val: %.*s", key, 20,
		       value);
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot add or update user meta");
		goto out;
	}

	pv_ctrl_utils_send_ok(req);
out:
	if (value)
		free(value);
}

static void usermeta_remove(struct evhttp_request *req, const char *key)
{
	if (pv_metadata_rm_usermeta(key) < 0) {
		pv_log(DEBUG, "couldn't remove user meta, key: %s", key);
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "User meta does not exist");
		return;
	}

	pv_ctrl_utils_send_ok(req);
}

static void usermeta_key(struct evhttp_request *req, const char *key)
{
	int methods[] = { EVHTTP_REQ_PUT, EVHTTP_REQ_DELETE, -1 };

	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	if (snd->method == EVHTTP_REQ_PUT)
		usermeta_add_or_update(req, key);
	else if (snd->method == EVHTTP_REQ_DELETE)
		usermeta_remove(req, key);

	pv_ctrl_sender_free(snd);
}

static int usermeta_handler(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char parts[PV_CTRL_UTILS_MAX_PARTS][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, parts);

	if (size == 0 || size > 2 || strcmp(parts[0], "user-meta") != 0)
		return -1;

	if (size == 1) {
		usermeta_list(req);
	} else if (size == 2) {
		usermeta_key(req, parts[1]);
	}

	return 0;
}

struct pv_ctrl_handler usermeta_hnd = {
	.path = "/user-meta",
	.fn = usermeta_handler,
};