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
#include "ctrl_util.h"
#include "state.h"
#include "pantavisor.h"
#include "platforms.h"
#include "group.h"
#include "utils/json.h"

#include <event2/http.h>
#include <event2/buffer.h>
#include <linux/limits.h>

#include <string.h>

#define MODULE_NAME "containers-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void ctrl_containers_list(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	struct pantavisor *pv = pv_get_instance();
	char *cont = pv_state_get_containers_json(pv->state);

	if (!cont) {
		pv_log(WARN, "couldn't get container list");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Cannot get container list");
		return;
	}

	pv_ctrl_utils_send_json(req, HTTP_OK, NULL, cont);
}

static void ctrl_container_put(struct evhttp_request *req, void *ctx)
{
	char *name = NULL;
	char *data = NULL;
	char *action = NULL;
	struct pv_platform *p = NULL;
	int tokc;
	jsmntok_t *tokv = NULL;

	struct pantavisor *pv = pv_get_instance();

	const char *uri = evhttp_request_get_uri(req);
	char split[PV_CTRL_MAX_SPLIT][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, split);

	if (size >= 2) {
		name = split[1];
	}

	if (!name || strlen(name) == 0) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Missing container name");
		return;
	}

	p = pv_state_fetch_platform(pv->state, name);
	if (!p) {
		pv_ctrl_utils_send_error(req, HTTP_NOTFOUND,
					 "Container not found");
		return;
	}

	// Only allow control of containers with restart_policy "container"
	if (p->restart_policy != RESTART_CONTAINER) {
		pv_ctrl_utils_send_error(
			req, HTTP_BADREQUEST,
			"Container has restart_policy 'system' and cannot be stopped/started via API. Only containers with restart_policy 'container' can be controlled.");
		return;
	}

	data = pv_ctrl_utils_get_data(req, 1024, NULL);
	if (!data) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, "No data");
		return;
	}

	jsmn_parser parser;
	jsmn_init(&parser);
	tokc = jsmn_parse(&parser, data, strlen(data), NULL, 0);
	if (tokc < 0) {
		free(data);
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST, "Invalid JSON");
		return;
	}
	tokv = calloc(tokc, sizeof(jsmntok_t));
	jsmn_init(&parser);
	jsmn_parse(&parser, data, strlen(data), tokv, tokc);

	action = pv_json_get_value(data, "action", tokv, tokc);

	if (!action) {
		free(tokv);
		free(data);
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Missing 'action' field");
		return;
	}

	if (strcmp(action, "stop") == 0) {
		pv_log(INFO, "Stopping container %s via ctrl", p->name);

		if (pv_platform_is_stopped(p)) {
			pv_log(INFO, "Container %s is already stopped",
			       p->name);
		} else {
			// Disable auto-recovery during explicit stop
			p->auto_recovery.type = RECOVERY_NO;
			// Set status goal to STOPPED so pv_state_run() doesn't
			// treat this as an unexpected crash requiring reboot
			pv_platform_set_status_goal(p, PLAT_STOPPED);
			// Use force_stop for reliable stop via API
			// This stops the container immediately and sets status to STOPPED
			pv_platform_force_stop(p);
		}
	} else if (strcmp(action, "start") == 0) {
		pv_log(INFO, "Starting container %s via ctrl", p->name);

		if (pv_platform_is_started(p) || pv_platform_is_starting(p) ||
		    pv_platform_is_ready(p)) {
			pv_log(INFO, "Container %s is already running",
			       p->name);
		} else if (pv_platform_is_stopped(p)) {
			// Restore status goal to group default (usually READY)
			pv_platform_set_status_goal(
				p, p->group->default_status_goal);
			// Volumes remain mounted when container is stopped,
			// so we can just restart it
			pv_platform_set_mounted(p);
			pv_platform_start(p);
		} else {
			free(action);
			free(tokv);
			free(data);
			pv_ctrl_utils_send_error(
				req, HTTP_BADREQUEST,
				"Container must be in STOPPED state to start. Current state does not allow start.");
			return;
		}
	} else if (strcmp(action, "restart") == 0) {
		pv_log(INFO, "Restarting container %s via ctrl", p->name);

		if (pv_platform_is_stopped(p)) {
			// Container already stopped, just start it
			pv_platform_set_status_goal(
				p, p->group->default_status_goal);
			pv_platform_set_mounted(p);
			pv_platform_start(p);
		} else if (pv_platform_is_started(p) ||
			   pv_platform_is_starting(p) ||
			   pv_platform_is_ready(p)) {
			// Container running, stop it first then start
			// Disable auto-recovery during restart
			p->auto_recovery.type = RECOVERY_NO;
			pv_platform_set_status_goal(p, PLAT_STOPPED);
			pv_platform_force_stop(p);
			// Restore status goal and restart
			pv_platform_set_status_goal(
				p, p->group->default_status_goal);
			pv_platform_set_mounted(p);
			pv_platform_start(p);
		} else {
			free(action);
			free(tokv);
			free(data);
			pv_ctrl_utils_send_error(
				req, HTTP_BADREQUEST,
				"Container state does not allow restart.");
			return;
		}
	} else {
		free(action);
		free(tokv);
		free(data);
		pv_ctrl_utils_send_error(
			req, HTTP_BADREQUEST,
			"Invalid action. Use 'start', 'stop', or 'restart'");
		return;
	}

	free(action);
	free(tokv);
	free(data);

	pv_ctrl_utils_send_ok(req);
}

int pv_ctrl_endpoints_containers_init()
{
	pv_ctrl_add_endpoint("/containers", EVHTTP_REQ_GET, true,
			     ctrl_containers_list);
	pv_ctrl_add_endpoint("/containers/{}", EVHTTP_REQ_PUT, true,
			     ctrl_container_put);
	return 0;
}
