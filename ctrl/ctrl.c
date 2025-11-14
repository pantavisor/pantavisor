
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

#include "ctrl.h"
#include "ctrl_util.h"
#include "ctrl_caller.h"
#include "ctrl_endpoints.h"
#include "utils/list.h"
#include "event/event_http_server.h"
#include "paths.h"
#include "init.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <linux/limits.h>
#include <string.h>
#include <stdio.h>

#define MODULE_NAME "ctrl"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_CTRL_ERROR_RSP "{\"Error\": \"Unsupported protocol\"}"

struct ctrl_run_req {
	struct evhttp_request *req;
	struct dl_list lst;
};

struct ctrl_srv {
	struct evhttp *srv;
	struct dl_list custom_cb;
	struct dl_list normal_cb;
	struct dl_list request;
};

static struct ctrl_srv pvctrl = { 0 };

// catch any error in the communication, for example use any other protocol
// than http against the socket
static int ctrl_error_cb(struct evhttp_request *req, struct evbuffer *buf,
			 int err, const char *reason, void *ctx)
{
	(void)req;
	(void)err;
	(void)ctx;
	(void)reason;

	evbuffer_add_printf(buf, PV_CTRL_ERROR_RSP);

	return 0;
}

static bool ctrl_uri_equals(const char *uri1, const char *uri2)
{
	char split1[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	int size1 = pv_ctrl_utils_split_path(uri1, split1);

	char split2[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	int size2 = pv_ctrl_utils_split_path(uri2, split2);

	if (size1 != size2)
		return false;

	for (int i = 0; i < size1; i++) {
		if (strcmp(split1[i], split2[i]) != 0 &&
		    strcmp(split1[i], "{}") != 0 &&
		    strcmp(split2[i], "{}") != 0)
			return false;
	}

	return true;
}

static bool ctrl_is_running_req(struct evhttp_request *req)
{
	struct ctrl_run_req *it, *tmp;
	dl_list_for_each_safe(it, tmp, &pvctrl.request, struct ctrl_run_req,
			      lst)
	{
		if (it->req == req)
			return true;
	}
	return false;
}

static void ctrl_remove_req(struct evhttp_request *req)
{
	struct ctrl_run_req *it, *tmp;
	dl_list_for_each_safe(it, tmp, &pvctrl.request, struct ctrl_run_req,
			      lst)
	{
		if (it->req != req)
			continue;

		dl_list_del(&it->lst);
		free(it);
		return;
	}
}

static void ctrl_auto_remove_req(struct evhttp_request *req, void *ctx)
{
	(void)ctx;
	ctrl_remove_req(req);
}

static void crtl_add_request(struct evhttp_request *req)
{
	struct ctrl_run_req *runq = calloc(1, sizeof(struct ctrl_run_req));
	if (!runq) {
		pv_log(DEBUG, "couldn't add request to the running list");
		return;
	}

	evhttp_request_set_on_complete_cb(req, ctrl_auto_remove_req, NULL);
	runq->req = req;

	dl_list_init(&runq->lst);
	dl_list_add(&pvctrl.request, &runq->lst);
}

static int ctrl_router_cb(struct evhttp_request *req, void *ctx)
{
	if (strcmp(evhttp_request_get_host(req), "localhost") != 0)
		return -1;

	const char *uri = evhttp_request_get_uri(req);
	pv_log(DEBUG, "New HTTP request recived: %s", uri);

	char inc_split[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	int inc_sz = pv_ctrl_utils_split_path(uri, inc_split);

	int err = 0;

	struct pv_ctrl_cb *it, *tmp;
	dl_list_for_each_safe(it, tmp, &pvctrl.custom_cb, struct pv_ctrl_cb,
			      lst)
	{
		if (!ctrl_uri_equals(uri, it->uri))
			continue;

		struct pv_ctrl_caller caller = { 0 };
		if (pv_ctrl_caller_init(&caller, req) != 0) {
			pv_log(WARN, "couldn't get caller info");
			pv_ctrl_utils_send_error(
				req, HTTP_INTERNAL,
				"Internal error, unknown caller");
			return 0;
		}

		if (!(caller.method & it->methods)) {
			err = 1;
			continue;
		}

		if (it->need_mgmt && !caller.is_privileged) {
			err = 2;
			continue;
		}

		err = 0;
		crtl_add_request(req);
		it->fn(req, it);
		break;
	}

	if (err == 1) {
		pv_log(WARN, "HTTP method not supported for this endpoint");
		pv_ctrl_utils_send_error(
			req, HTTP_BADREQUEST,
			"Method not supported for this endpoint");

	} else if (err == 2) {
		pv_log(WARN, "request not sent from mgmt platform");
		pv_ctrl_utils_send_error(req, HTTP_FORBIDDEN,
					 "Request not sent from mgmt platform");
	}

	return 0;
}

static int ctrl_add_custom(const char *path, const int methods, bool mgmt,
			   pv_ctrl_fn fn)
{
	struct pv_ctrl_cb *cb = pv_ctrl_cb_new(path, methods, mgmt, fn);
	if (!cb) {
		pv_log(DEBUG, "couldn't allocate new callback");
		return -1;
	}

	dl_list_add(&pvctrl.custom_cb, &cb->lst);

	return 0;
}

static int ctrl_add_normal(const char *path, const int methods, bool mgmt,
			   pv_ctrl_fn fn)
{
	struct pv_ctrl_cb *cb = pv_ctrl_cb_new(path, methods, mgmt, fn);
	if (!cb) {
		pv_log(DEBUG, "couldn't allocate new callback");
		return -1;
	}

	dl_list_add(&pvctrl.normal_cb, &cb->lst);

	return evhttp_set_cb(pvctrl.srv, path, fn, cb);
}

int pv_ctrl_add_endpoint(const char *path, const int methods, bool mgmt,
			 pv_ctrl_fn fn)
{
	char path_split[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(path, path_split);

	for (int i = 0; i < size; i++) {
		if (!strcmp(path_split[i], "{}")) {
			return ctrl_add_custom(path, methods, mgmt, fn);
		}
	}

	return ctrl_add_normal(path, methods, mgmt, fn);
}

static int ctrl_set_req_cb(struct evhttp_request *req, void *ctx)
{
	(void)ctx;

	evhttp_request_set_header_cb(req, ctrl_router_cb);
	return 0;
}

static void ctrl_default_cb(struct evhttp_request *req, void *ctx)
{
	(void)ctx;

	if (ctrl_is_running_req(req)) {
		evbuffer_add_printf(evhttp_request_get_output_buffer(req),
				    "done");
		return;
	}

	const char *uri = evhttp_request_get_uri(req);
	pv_log(WARN, "HTTP request received to an unknown endpoint: %s", uri);

	char msg[PATH_MAX + 30] = { 0 };
	snprintf(msg, PATH_MAX + 30, "%s: %s", "unknown endpoint", uri);

	pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, msg);
}

static void ctrl_add_endpoints()
{
	pv_ctrl_endpoints_containers_init();
	pv_ctrl_endpoints_groups_init();
	pv_ctrl_endpoints_signal_init();
	pv_ctrl_endpoints_objects_init();
	pv_ctrl_endpoints_steps_init();
	pv_ctrl_endpoints_usrmeta_init();
	pv_ctrl_endpoints_devmeta_init();
	pv_ctrl_endpoints_buildinfo_init();
	pv_ctrl_endpoints_drivers_init();
	pv_ctrl_endpoints_commands_init();
	pv_ctrl_endpoints_config_init();
}

int pv_ctrl_start()
{
	pv_log(DEBUG, "starting server");
	if (pvctrl.srv) {
		pv_log(DEBUG, "server is already created");
		return 0;
	}

	char sock_path[PATH_MAX] = { 0 };
	pv_paths_pv_file(sock_path, PATH_MAX - 1, PVCTRL_FNAME);

	pvctrl.srv = pv_http_server_new(sock_path);

	if (!pvctrl.srv) {
		pv_log(DEBUG, "couldn't create server");
		return -1;
	}

	dl_list_init(&pvctrl.custom_cb);
	dl_list_init(&pvctrl.normal_cb);
	dl_list_init(&pvctrl.request);

	ctrl_add_endpoints();

	evhttp_set_newreqcb(pvctrl.srv, ctrl_set_req_cb, NULL);
	evhttp_set_gencb(pvctrl.srv, ctrl_default_cb, NULL);
	evhttp_set_errorcb(pvctrl.srv, ctrl_error_cb, NULL);

	return 0;
}

static void ctrl_free_cb_list(struct dl_list *cb_list)
{
	struct pv_ctrl_cb *it, *tmp;
	dl_list_for_each_safe(it, tmp, cb_list, struct pv_ctrl_cb, lst)
	{
		pv_ctrl_cb_free(it);
	}
}

static void ctrl_free_request_list(struct dl_list *req_list)
{
	struct ctrl_run_req *it, *tmp;
	dl_list_for_each_safe(it, tmp, req_list, struct ctrl_run_req, lst)
	{
		free(it);
	}
}

void pv_ctrl_stop()
{
	evhttp_free(pvctrl.srv);
	pvctrl.srv = NULL;

	ctrl_free_cb_list(&pvctrl.custom_cb);
	ctrl_free_cb_list(&pvctrl.normal_cb);
	ctrl_free_request_list(&pvctrl.normal_cb);

	pv_log(DEBUG, "server stopped");
}

static int ctrl_init(struct pv_init *this)
{
	return pv_ctrl_start();
}

struct pv_init pv_init_ctrl = {
	.init_fn = ctrl_init,
	.flags = 0,
};