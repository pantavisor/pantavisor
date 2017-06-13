/*
 * Copyright (c) 2017 Pantacor Ltd.
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

#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define MODULE_NAME             "cmd"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "cmd.h"

int pv_cmd_socket_open(struct pantavisor *pv, char *path)
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
		fd = -1;
		goto out;
	}

	// queue 5 commands
	listen(fd, 1);

	pv->ctrl_fd = fd;
	
out:
	return fd;		
}

void pv_cmd_socket_close(struct pantavisor *pv)
{
	if (pv->ctrl_fd > 0) {
		pv_log(DEBUG, "closing control socket");
		close(pv->ctrl_fd);
	}
}

pv_cmd_t *pv_cmd_socket_wait(struct pantavisor *pv, int timeout)
{
	int fd, ret;
	char buf[4096];
	struct timeval tv;
	fd_set fdset;
	pv_cmd_t *cmd = 0;

	fd = pv->ctrl_fd;
	if (fd <= 0) {
		pv_log(WARN, "control socket not setup");
		goto out;
	}

	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);		

	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	ret = select(fd + 1, &fdset, 0, 0, &tv);

	if (!ret)
		goto out;
	
	if (ret < 0) {
		pv_log(ERROR, "error reading from socket fd");
		goto out;
	}

	// process command
	fd = accept(fd, 0, 0);
	cmd = calloc(1, sizeof(pv_cmd_t));
	cmd->type = CMD_TRY_ONCE;
	ret = recv(fd, buf, sizeof(buf), 0);
	cmd->args = calloc(1, ret + 1);
	cmd->args = strncpy(cmd->args, buf, ret);
	cmd->args[ret] = '\0';
	close(fd);

out:
	return cmd;
}
