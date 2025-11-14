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
#include "ctrl_cmd.h"
#include "ctrl_caller.h"
#include "ctrl_util.h"

#include <event2/http.h>

#define MODULE_NAME "commands-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void ctrl_command_run(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0) {
		pv_ctrl_utils_drain_req(req);
		return;
	}

	char *data = pv_ctrl_utils_get_data(req, PV_CTRL_CMD_MAX_SIZE, NULL);
	if (!data) {
		pv_log(WARN, "request without command")
			pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
						 "No command found");
		return;
	}

	pv_log(DEBUG, "new command arrive: %s", data);

	struct pv_ctrl_cmd *cmd = pv_ctrl_cmd_parse(data);
	if (!cmd) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Command has bad format");
		return;
	}

	char *err = NULL;
	if (pv_ctrl_cmd_add(cmd, err) != 0) {

		if (err)
			pv_ctrl_utils_send_error(req, PV_HTTP_CONFLICT, err);
		return;
	}

	pv_ctrl_utils_send_ok(req);
}

int pv_ctrl_endpoints_commands_init()
{
	pv_ctrl_add_endpoint("/commands", EVHTTP_REQ_POST, true,
			     ctrl_command_run);
	return 0;
}