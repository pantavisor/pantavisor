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
#include "ctrl_caller.h"
#include "ctrl_util.h"
#include "metadata.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>

#define MODULE_NAME "usrmeta-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define CTRL_USRMETA_MAX_DATA (4096)

static const char *ctrl_usrmeta_get_key(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	const char *key = strrchr(uri, '/');

	return key + 1;
}

static void ctrl_usrmeta_list(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	char *usrmeta = pv_metadata_get_user_meta_string();
	if (!usrmeta) {
		pv_log(WARN, "couldn't get user-meta");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "couldn't get user-meta");
		goto out;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, usrmeta);

out:
	if (usrmeta)
		free(usrmeta);
}

static void ctrl_usrmeta_set_key(struct evbuffer *buf,
				 const struct evbuffer_cb_info *info, void *ctx)
{
	struct evhttp_request *req = ctx;

	ssize_t len = 0;
	char *value = pv_ctrl_utils_get_data(req, CTRL_USRMETA_MAX_DATA, &len);
	const char *key = ctrl_usrmeta_get_key(req);

	pv_log(DEBUG, "=== Adding %s", value);

	int ret = pv_metadata_add_usermeta(key, value);

	if (ret < 0) {
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

static void ctrl_usrmeta_set(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx)) {
		pv_ctrl_utils_drain_req(req);
		return;
	}

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_usrmeta_set_key, req);
}

static void ctrl_usrmeta_delete(struct evhttp_request *req, void *ctx)
{
	if (!pv_ctrl_utils_is_req_ok(req, ctx))
		return;

	const char *key = ctrl_usrmeta_get_key(req);

	if (pv_metadata_rm_usermeta(key) < 0) {
		pv_log(DEBUG, "couldn't remove user meta, key: %s", key);
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "User meta does not exist");
		return;
	}

	pv_ctrl_utils_send_ok(req);
}

int pv_ctrl_endpoints_usrmeta_init()
{
	pv_ctrl_add_endpoint("/user-meta", EVHTTP_REQ_GET, true,
			     ctrl_usrmeta_list);
	pv_ctrl_add_endpoint("/user-meta/{}", EVHTTP_REQ_PUT, true,
			     ctrl_usrmeta_set);
	pv_ctrl_add_endpoint("/user-meta/{}", EVHTTP_REQ_DELETE, true,
			     ctrl_usrmeta_delete);

	return 0;
}