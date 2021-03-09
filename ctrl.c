/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdint.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "ctrl.h"
#include "utils.h"
#include "pvlogger.h"
#include "state.h"
#include "init.h"

#define MODULE_NAME             "ctrl"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#ifndef _GNU_SOURCE
struct  ucred {
	pid_t pid;
	uid_t uid;
	gid_t gid;
};
#endif

static int pv_ctrl_socket_open(char *path)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(ERROR, "unable to open control socket");
		goto out;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0) {
		pv_log(ERROR, "unable to bind control socket fd=%d", fd);
		close(fd);
		fd = -1;
		goto out;
	}

	// queue 15 commands
	listen(fd, 15);

out:
	return fd;
}

void pv_ctrl_socket_close(int ctrl_fd)
{
	if (ctrl_fd > 0) {
		pv_log(DEBUG, "closing ctrl socket");
		close(ctrl_fd);
	}
}

static int pv_ctrl_parse_command(char *buf, struct pv_cmd *cmd)
{
	int tokc;
	uint8_t ret = -1;
	jsmntok_t *tokv;
	char *op_string = NULL;

	jsmnutil_parse_json(buf, &tokv, &tokc);

	op_string = get_json_key_value(buf, "op", tokv, tokc);
	if(!op_string) {
		pv_log(WARN, "Unable to get op value from command");
		goto out;
	}

	cmd->op = pv_ctrl_int_cmd_operation(op_string, strlen(op_string));
	if (!cmd->op) {
		pv_log(WARN, "op from command unknown");
		goto out;
	}

	cmd->payload = get_json_key_value(buf, "payload", tokv, tokc);
	if (!cmd->payload) {
		pv_log(WARN, "Unable to get payload value from command");
		goto out;
	}

	ret = 0;

out:
	if (tokv)
		free(tokv);
	if (op_string)
		free(op_string);

	return ret;
}

static struct pv_cmd* pv_ctrl_process_cmd(int fd)
{
	struct pv_cmd *cmd = NULL;
	char req[4096], res[8];

	memset(req, 0, sizeof(req));
	memset(res, 0, sizeof(res));

	cmd = calloc(1, sizeof(struct pv_cmd));
	if (!cmd) {
		pv_log(ERROR, "cmd could not be allocated");
		goto err;
	}

	// read request
	if (read(fd, req, 4096) <= 0) {
		pv_log(ERROR, "cmd request could not be received from ctrl socket");
		goto err;
	}

	if (!pv_ctrl_parse_command(req, cmd)) {
		pv_log(DEBUG, "received command with op %d and payload %s", cmd->op, cmd->payload);
		sprintf(res, "%s", "OK");
	} else {
		pv_log(WARN, "json command has wrong format");
		sprintf(res, "%s", "ERROR");
	}

	// write response
	if (write(fd, res, strlen(res)) < 0) {
		pv_log(ERROR, "cmd response could not be sent to ctrl socket");
		goto err;
	}

	return cmd;

err:
	pv_ctrl_free_cmd(cmd);
	return NULL;
}

static void pv_ctrl_process_put_object(int fd)
{
	pv_log(DEBUG, "received put object. NOT IMPLEMENTED");
}

static void pv_ctrl_process_get_object(int fd)
{
	pv_log(DEBUG, "received get object. NOT IMPLEMENTED");
}

struct pv_cmd* pv_ctrl_socket_wait(int ctrl_fd, int timeout)
{
	int req_fd = 0, ret;
	fd_set fdset;
	struct timeval tv;
	char ctrl_code;
	struct pv_cmd *cmd = NULL;

	if (ctrl_fd < 0) {
		pv_log(WARN, "control socket not setup");
		goto out;
	}

	FD_ZERO(&fdset);
	FD_SET(ctrl_fd, &fdset);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	// select with blocking time
	ret = select(ctrl_fd + 1, &fdset, 0, 0, &tv);
	if (!ret)
		goto out;
	else if (ret < 0) {
		pv_log(ERROR, "select wait failed");
		goto out;
	}

	// create dedicated fd
	req_fd = accept(ctrl_fd, 0, 0);
	if (req_fd <= 0) {
		goto out;
	}


	if (read(req_fd, &ctrl_code, sizeof(char)) != sizeof(char)) {
		pv_log(WARN, "unknown command format received");
		goto out;
	}

	// process request
	switch (ctrl_code) {
	case CTRL_CMD:
		cmd = pv_ctrl_process_cmd(req_fd);
		break;
	case CTRL_PUT_OBJECT:
		pv_ctrl_process_put_object(req_fd);
		break;
	case CTRL_GET_OBJECT:
		pv_ctrl_process_get_object(req_fd);
		break;
	default:
		pv_log(DEBUG, "received unknown ctrl request %d", ctrl_code);
	}

out:
	close(req_fd);
	return cmd;
}

void pv_ctrl_free_cmd(struct pv_cmd *cmd)
{
	if (!cmd)
		return;

	if (cmd->payload)
		free(cmd->payload);

	free(cmd);
}

static int pv_ctrl_init(struct pv_init *this)
{
	struct pantavisor *pv = get_pv_instance();

	pv->ctrl_fd = pv_ctrl_socket_open("/pv/pv-ctrl");
	if (pv->ctrl_fd <= 0) {
		pv_log(ERROR, "ctrl socket could not be initialized");
		return -1;
	}

	return 0;
}

struct pv_init pv_init_ctrl = {
	.init_fn = pv_ctrl_init,
	.flags = 0,
};
