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

#include "ctrl_cmd.h"
#include "json.h"
#include "pantavisor.h"
#include "config.h"

#include <stdlib.h>

#define MODULE_NAME "cmd"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pv_ctrl_cmd *pv_ctrl_cmd_parse(const char *buf)
{
	struct pv_ctrl_cmd *cmd = calloc(1, sizeof(struct pv_ctrl_cmd));
	if (!cmd) {
		pv_log(ERROR, "cmd could not be allocated");
		goto out;
	}

	int tokc = 0;
	jsmntok_t *tokv = NULL;
	jsmnutil_parse_json(buf, &tokv, &tokc);

	char *op_str = pv_json_get_value(buf, "op", tokv, tokc);

	if (!op_str) {
		pv_log(WARN, "unable to get op value from command");
		goto err;
	}

	cmd->op = pv_ctrl_cmd_op_from_str(op_str, strlen(op_str));
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
	pv_ctrl_cmd_free(cmd);
	cmd = NULL;

out:
	if (tokv)
		free(tokv);
	if (op_str)
		free(op_str);

	return cmd;
}

int pv_ctrl_cmd_add(struct pv_ctrl_cmd *cmd, char *err)
{
	if (!cmd)
		return -1;

	struct pantavisor *pv = pv_get_instance();

	if (!pv->remote_mode && cmd->op == CMD_UPDATE_METADATA) {
		err = "Cannot do this operation while on local mode";
		return -1;
	}

	if (pv->update &&
	    ((cmd->op == CMD_REBOOT_DEVICE) ||
	     (cmd->op == CMD_POWEROFF_DEVICE) || (cmd->op == CMD_LOCAL_RUN) ||
	     (cmd->op == CMD_LOCAL_RUN_COMMIT) ||
	     (cmd->op == CMD_MAKE_FACTORY))) {
		err = "Cannot do this operation while update is ongoing";
		return -1;
	}

	if (!pv->unclaimed && cmd->op == CMD_MAKE_FACTORY) {
		err = "Cannot do this operation if device is already claimed";
		return -1;
	}

	if (!pv_config_get_bool(PV_CONTROL_REMOTE) &&
	    cmd->op == CMD_GO_REMOTE) {
		err = "Cannot do this operation when remote mode is disabled by config";
		return -1;
	}

	if (!pv_config_get_bool(PV_DEBUG_SHELL) &&
	    cmd->op == CMD_DEFER_REBOOT) {
		err = "Cannot do this operation when debug shell is not active";
		pv_log(WARN,
		       "Cannot do this operation when debug shell is not active");

		return -1;
	}

	if (pv->remote_mode && cmd->op == CMD_GO_REMOTE) {
		err = "Already in remote mode";
		return -1;
	}

	if (pv->cmd) {
		err = "A command is already in progress. Try again";
		return -1;
	}

	pv->cmd = cmd;

	return 0;
}

void pv_ctrl_cmd_free(struct pv_ctrl_cmd *cmd)
{
	if (!cmd)
		return;

	if (cmd->payload)
		free(cmd->payload);

	free(cmd);
}