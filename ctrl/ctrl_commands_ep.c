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

#include "ctrl/utils.h"
#include "ctrl/incdata.h"
#include "ctrl/handler.h"
#include "ctrl/sender.h"
#include "ctrl/ctrl_cmd.h"
#include "pantavisor.h"
#include "updater.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>

#define MODULE_NAME "commands-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static int command_set(struct evhttp_request *req, struct pv_cmd *cmd)
{
	if (!cmd)
		return -1;

	const char *errstr = NULL;

	struct pantavisor *pv = pv_get_instance();

	if (!pv->remote_mode && (cmd->op == CMD_UPDATE_METADATA)) {
		errstr = "Cannot do this operation while on local mode";
		goto err;
	}

	if (pv->update && pv->update->status != UPDATE_APPLIED &&
	    ((cmd->op == CMD_REBOOT_DEVICE) ||
	     (cmd->op == CMD_POWEROFF_DEVICE) || (cmd->op == CMD_LOCAL_RUN) ||
	     (cmd->op == CMD_LOCAL_APPLY) ||
	     (cmd->op == CMD_LOCAL_RUN_COMMIT) ||
	     (cmd->op == CMD_MAKE_FACTORY))) {
		errstr = "Cannot do this operation while update is ongoing";
		goto err;
	}

	if (!pv->unclaimed && (cmd->op == CMD_MAKE_FACTORY)) {
		errstr =
			"Cannot do this operation if device is already claimed";
		goto err;
	}

	if (!pv_config_get_bool(PV_CONTROL_REMOTE) &&
	    (cmd->op == CMD_GO_REMOTE)) {
		errstr =
			"Cannot do this operation when remote mode is disabled by config";
		goto err;
	}

	if (!pv_config_get_bool(PV_DEBUG_SHELL) &&
	    (cmd->op == CMD_DEFER_REBOOT)) {
		errstr =
			"Cannot do this operation when debug shell is not active";
		goto err;
	}

	if (pv->remote_mode && (cmd->op == CMD_GO_REMOTE)) {
		errstr = "Already in remote mode";
		goto err;
	}

	if (pv->cmd) {
		errstr = "A command is already in progress. Try again";
		goto err;
	}

	pv->cmd = cmd;

	return 0;
err:
	pv_log(DEBUG, "operation not allowed");
	pv_ctrl_utils_send_error(req, PV_HTTP_CONFLICT, errstr);
	return -1;
}

static struct pv_cmd *commands_parse(char *buf)
{
	struct pv_cmd *cmd = calloc(1, sizeof(struct pv_cmd));
	if (!cmd) {
		pv_log(ERROR, "cmd could not be allocated");
		return NULL;
	}

	int tokc = 0;
	jsmntok_t *tokv = NULL;
	jsmnutil_parse_json(buf, &tokv, &tokc);

	char *op_str = pv_json_get_value(buf, "op", tokv, tokc);
	if (!op_str) {
		pv_log(WARN, "unable to get op value from command");
		goto err;
	}

	cmd->op = pv_ctrl_int_cmd_operation(op_str, strlen(op_str));
	if (!cmd->op) {
		pv_log(WARN, "op from command unknown");
		goto err;
	}

	cmd->payload = pv_json_get_value(buf, "payload", tokv, tokc);
	if (!cmd->payload) {
		pv_log(WARN, "unable to get payload value from command");
		goto err;
	}

	goto out;

err:
	pv_ctrl_free_cmd(cmd);
	cmd = NULL;

out:
	if (tokv)
		free(tokv);

	if (op_str)
		free(op_str);

	return cmd;
}

static void commands_process(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };

	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	char *data = pv_ctrl_incdata_get_data(req, PV_CTRL_REQ_MAX, NULL);
	if (!data)
		return;

	struct pv_cmd *cmd = commands_parse(data);

	if (!cmd) {
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Command has bad format");
		return;
	}

	command_set(req, cmd);
}

static int commands_handler(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char parts[PV_CTRL_UTILS_MAX_PARTS][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, parts);

	if (size < 1 || size > 1 || strcmp(parts[0], "commands") != 0)
		return -1;

	commands_process(req);
	return 0;
}

struct pv_ctrl_handler commands_hnd = {
	.path = "/commands",
	.fn = commands_handler,
};