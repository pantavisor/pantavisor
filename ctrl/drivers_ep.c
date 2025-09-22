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
#include "ctrl/utils.h"
#include "drivers.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>
#include <linux/limits.h>

#define MODULE_NAME "drivers-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void drivers_list(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };

	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, false);

	if (!snd)
		return;

	char *drivers = pv_drivers_state_all(snd->plat);

	if (!drivers) {
		pv_log(DEBUG, "couldn't get drivers");
		goto out;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, drivers);
out:
	pv_ctrl_sender_free(snd);
	free(drivers);
}

static void drivers_load_all(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_PUT, -1 };

	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	int ret = pv_platform_load_drivers(snd->plat, NULL, DRIVER_MANUAL);
	if (ret != 0) {
		pv_log(WARN, "Error loading drivers");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Error loading drivers");
		goto out;
	}

	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
out:
	pv_ctrl_sender_free(snd);
}

static void drivers_unload_all(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_PUT, -1 };

	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	pv_platform_unload_drivers(snd->plat, NULL, DRIVER_MANUAL);
	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
}

static void driver_load(struct evhttp_request *req, const char *name)
{
	int methods[] = { EVHTTP_REQ_PUT, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	int ret = pv_platform_load_drivers(snd->plat, (char *)name,
					   DRIVER_MANUAL);
	if (ret != 0) {
		pv_log(WARN, "Error loading driver %s", name);
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Error loading driver");
		goto out;
	}

	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
out:
	pv_ctrl_sender_free(snd);
}

static void driver_unload(struct evhttp_request *req, const char *name)
{
	int methods[] = { EVHTTP_REQ_PUT, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	pv_platform_unload_drivers(snd->plat, (char *)name, DRIVER_MANUAL);
	evhttp_send_reply(req, HTTP_OK, NULL, NULL);
	pv_ctrl_sender_free(snd);
}

static void driver_status(struct evhttp_request *req, const char *name)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };
	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	struct evbuffer *buf = evbuffer_new();
	if (!buf) {
		pv_log(WARN, "couldn't allocate response buffer");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Error quering driver status");
		goto out;
	}

	evhttp_add_header(evhttp_request_get_output_headers(req),
			  "Content-Type", "text/plain");
	evbuffer_add_printf(buf, "%s", pv_drivers_state_str((char *)name));
	evhttp_send_reply(req, HTTP_OK, NULL, buf);
out:
	pv_ctrl_sender_free(snd);
}

static int driver_handler(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char parts[PV_CTRL_UTILS_MAX_PARTS][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, parts);

	if (size == 0 || size > 3 || strcmp(parts[0], "drivers") != 0)
		return -1;

	if (size == 1) {
		drivers_list(req);
	} else if (size == 2) {
		if (!strcmp(parts[1], "load"))
			drivers_load_all(req);
		else if (!strcmp(parts[1], "unload"))
			drivers_unload_all(req);
		else
			driver_status(req, parts[1]);

	} else if (size == 3) {
		if (!strcmp(parts[2], "load"))
			driver_load(req, parts[1]);
		else if (!strcmp(parts[2], "unload"))
			driver_unload(req, parts[1]);
	}

	return 0;
}

struct pv_ctrl_handler driver_hnd = {
	.path = "/drivers",
	.fn = driver_handler,
};