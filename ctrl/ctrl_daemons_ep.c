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
#include "ctrl_util.h"
#include "daemons.h"
#include "init.h"
#include "utils/json.h"

#include <event2/http.h>
#include <event2/buffer.h>
#include <signal.h>
#include <string.h>
#include <linux/limits.h>

#define MODULE_NAME "daemons-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void ctrl_daemons_get(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	struct pv_json_ser js;
	struct pv_init_daemon *daemons = pv_init_get_daemons();
	int i;

	pv_json_ser_init(&js, 1024);
	pv_json_ser_array(&js);

	for (int i = 0; daemons[i].name; i++) {
		pv_json_ser_object(&js);
		pv_json_ser_key(&js, "name");
		pv_json_ser_string(&js, daemons[i].name);
		pv_json_ser_key(&js, "pid");
		pv_json_ser_number(&js, daemons[i].pid);
		pv_json_ser_key(&js, "respawn");
		pv_json_ser_bool(&js, daemons[i].respawn);
		pv_json_ser_object_pop(&js);
	}

	pv_json_ser_array_pop(&js);

	pv_ctrl_utils_send_json(req, HTTP_OK, "OK", pv_json_ser_str(&js));
}

static void ctrl_daemons_put(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	pv_log(INFO, "PUT request for daemons");
	char *name = NULL;
	char *data = NULL;
	char *action = NULL;
	struct pv_init_daemon *daemons = pv_init_get_daemons();
	struct pv_init_daemon *daemon = NULL;
	int tokc;
	jsmntok_t *tokv = NULL;

	const char *uri = evhttp_request_get_uri(req);
	char split[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, split);

	if (size == 2) {
		name = split[1];
	}

	if (!name) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Missing daemon name");
		return;
	}

	for (int i = 0; daemons[i].name; i++) {
		if (strcmp(daemons[i].name, name) == 0) {
			daemon = &daemons[i];
			break;
		}
	}

	if (!daemon) {
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "Daemon not found");
		return;
	}

	struct evbuffer *in_buf = evhttp_request_get_input_buffer(req);
	if (in_buf) {
		pv_log(INFO, "input buffer length: %zd",
		       evbuffer_get_length(in_buf));
	} else {
		pv_log(INFO, "no input buffer");
	}

	data = pv_ctrl_utils_get_data(req, 1024, NULL);
	if (!data) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, "No data");
		return;
	}

	jsmn_parser p;
	jsmn_init(&p);
	tokc = jsmn_parse(&p, data, strlen(data), NULL, 0);
	if (tokc < 0) {
		free(data);
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, "Invalid JSON");
		return;
	}
	tokv = calloc(tokc, sizeof(jsmntok_t));
	jsmn_init(&p);
	jsmn_parse(&p, data, strlen(data), tokv, tokc);

	action = pv_json_get_value(data, "action", tokv, tokc);

	if (action) {
		if (strcmp(action, "stop") == 0) {
			pv_log(INFO, "Stopping daemon %s via ctrl",
			       daemon->name);
			daemon->respawn = 0;
			if (daemon->pid > 0) {
				kill(daemon->pid, SIGTERM);
			}
		} else if (strcmp(action, "start") == 0) {
			pv_log(INFO, "Starting daemon %s via ctrl",
			       daemon->name);
			daemon->respawn = 1;
			if (daemon->pid <= 0) {
				if (daemon->pid < 0)
					daemon->pid = 0;
				pv_init_spawn_daemons(
					pv_config_get_system_init_mode());
			}
		}
		free(action);
	}

	free(tokv);
	free(data);

	pv_ctrl_utils_send_ok(req);
}

int pv_ctrl_endpoints_daemons_init()
{
	pv_ctrl_add_endpoint("/daemons", EVHTTP_REQ_GET, true,
			     ctrl_daemons_get);
	pv_ctrl_add_endpoint("/daemons/{}", EVHTTP_REQ_PUT, true,
			     ctrl_daemons_put);
	return 0;
}