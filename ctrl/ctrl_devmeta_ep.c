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

#define MODULE_NAME "devmeta-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define CTRL_USRMETA_MAX_DATA (4096)

static const char *ctrl_devmeta_get_key(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	const char *key = strrchr(uri, '/');

	return key + 1;
}

static void ctrl_devmeta_list(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	char *devmeta = pv_metadata_get_device_meta_string();
	if (!devmeta) {
		pv_log(WARN, "couldn't get device-meta");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "couldn't get device-meta");
		goto out;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, devmeta);

out:
	if (devmeta)
		free(devmeta);
}

static void ctrl_devmeta_set_key(struct evbuffer *buf,
				 const struct evbuffer_cb_info *info, void *ctx)
{
	struct evhttp_request *req = ctx;

	ssize_t len = 0;
	char *value = pv_ctrl_utils_get_data(req, CTRL_USRMETA_MAX_DATA, &len);
	const char *key = ctrl_devmeta_get_key(req);

	int ret = pv_metadata_add_devmeta(key, value);

	if (ret < 0) {
		pv_log(DEBUG, "couldn't add new key: %s, val: %.*s", key, 20,
		       value);
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot add or update device meta");
		goto out;
	}

	pv_ctrl_utils_send_ok(req);
out:
	if (value)
		free(value);
}

static void ctrl_devmeta_set(struct evhttp_request *req, void *ctx)
{
	char err[PV_CTRL_MAX_ERR] = { 0  };
	int code = pv_ctrl_utils_is_req_ok(req, ctx, err);
	if (code != 0) {
		pv_ctrl_utils_drain_on_arrive_with_err(req, code, err);
		return;
	}

	evbuffer_add_cb(evhttp_request_get_input_buffer(req),
			ctrl_devmeta_set_key, req);
}

static void ctrl_devmeta_delete(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	const char *key = ctrl_devmeta_get_key(req);

	if (pv_metadata_rm_devmeta(key) < 0) {
		pv_log(DEBUG, "couldn't remove device meta, key: %s", key);
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "Device meta does not exist");
		return;
	}

	pv_ctrl_utils_send_ok(req);
}

int pv_ctrl_endpoints_devmeta_init()
{
	pv_ctrl_add_endpoint("/device-meta", EVHTTP_REQ_GET, true,
			     ctrl_devmeta_list);
	pv_ctrl_add_endpoint("/device-meta/{}", EVHTTP_REQ_PUT, true,
			     ctrl_devmeta_set);
	pv_ctrl_add_endpoint("/device-meta/{}", EVHTTP_REQ_DELETE, true,
			     ctrl_devmeta_delete);

	return 0;
}