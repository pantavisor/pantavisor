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

#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <errno.h>

#define MODULE_NAME             "cmd"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "cmd.h"
#include "utils.h"
#include "pvlogger.h"
#include "platforms.h"
#include "state.h"
#include "init.h"

#ifndef _GNU_SOURCE
struct  ucred {
	pid_t pid;
	uid_t uid;
	gid_t gid;
};
#endif

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
		close(fd);
		fd = -1;
		goto out;
	}

	// queue 15 commands
	listen(fd, 15);

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

static uint8_t parse_cmd_req(char *buf, struct pv_cmd_req *cmd)
{
	int tokc;
	uint8_t ret = 1;
	jsmntok_t *tokv;
	char *op_string = NULL;

	jsmnutil_parse_json(buf, &tokv, &tokc);

	op_string = get_json_key_value(buf, "op", tokv, tokc);
	if(!op_string) {
		pv_log(WARN, "Unable to get op value from command");
		goto out;
	}

	cmd->json_operation = int_cmd_operation(op_string, strlen(op_string));
	if (!cmd->json_operation) {
		pv_log(WARN, "op from command unknown");
		goto out;
	}

	cmd->data = get_json_key_value(buf, "payload", tokv, tokc);
	if (!cmd->data) {
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

struct pv_cmd_req *pv_cmd_socket_wait(struct pantavisor *pv, int timeout)
{
	int fd, ret;
	char buf[4096];
	struct timeval tv;
	struct pv_cmd_req *c = 0;
	fd_set fdset;
	struct ucred peer_cred;
	socklen_t peer_size = sizeof(peer_cred);
	int data_written = 0;
	int avail = 0;

	fd = pv->ctrl_fd;
	if (fd < 0) {
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

	c = calloc(1, sizeof(struct pv_cmd_req));

	if (!getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer_cred, &peer_size)) {
		struct pv_platform *p, *tmp_p;
		struct pv_log_info *l, *tmp_l;
		struct dl_list *head_platforms, *head_logger;
		bool found = false;
		head_platforms = &pv->state->platforms;
		dl_list_for_each_safe(p, tmp_p, head_platforms,
				struct pv_platform, list) {
			head_logger = &p->logger_list;
			found = false;
			dl_list_for_each_safe(l, tmp_l, head_logger,
					struct pv_log_info, next) {
				if (l->logger_pid == peer_cred.pid) {
					c->platform = (l->name ? strdup(l->name) : NULL);
					found = true;
					break;
				}
			}
			if (found)
				break;
		}
	}

	if (!c->platform) {
		char buf[64];
		snprintf(buf, sizeof(buf), "/proc/%d/comm", peer_cred.pid);
		FILE *fp = fopen(buf, "r");
		if (fp) {
			fscanf(fp, "%s", buf);
			fclose(fp);
		} else {
			snprintf(buf, sizeof(buf), "from pid = %d", peer_cred.pid);
		}
		c->platform = strdup(buf);
	}

select_:
	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	ret = select(fd + 1, &fdset, 0, 0, &tv);
	if (ret < 0) {
		if (errno != EINTR)
			goto err;
		else
			goto select_;
	}

	ret = read(fd, &c->cmd, sizeof(char));
	if (ret != sizeof(char)) {
		pv_log(WARN, "unknown command format received");
		goto err;
	}

	do {
		fd_set readset;
		int retries = 5;
		avail = sizeof(buf) - data_written;
select_again:
		FD_ZERO(&readset);
		FD_SET(fd, &readset);
		tv.tv_sec = 1;
		tv.tv_usec = 5000;
		ret = select(fd + 1, &readset, 0, 0, &tv);

		if ( retries > 0 && ret < 0 && errno == EINTR) {
			retries -= 1;
			goto select_again;
		}

		if (ret > 0 ) {
read_again:
			ret = read(fd, ((char*)buf) + data_written, avail);
			if (ret < 0) {
				if (errno == EINTR && retries > 0) {
					retries -= 1;
					goto read_again;
				}

				pv_log(WARN, "unable to read command data");
				goto err;
			}
			data_written += ret;
		}
	}while (ret > 0 && avail > 0);

	if (c->cmd != CMD_JSON) {
		c->data = calloc(1, data_written);
		c->data = memcpy(c->data, buf, data_written);
		c->len = data_written;
	} else {
		ret = parse_cmd_req(buf, c);
		if (ret) {
			pv_log(WARN, "json command has wrong format");
			goto err;
		}
		pv_log(DEBUG, "new json command op=%d payload=%s", c->json_operation, c->data);
	}
	close(fd);
out:
	return c;
err:
	close(fd);
	if (c) {
		if (c->data)
			free(c->data);
		if (c->platform)
			free(c->platform);
		free(c);
	}
	return NULL;
}

void pv_cmd_req_remove(struct pantavisor *pv)
{
	struct pv_cmd_req *req = pv->req;

	if (!req)
		return;

	pv_log(DEBUG, "removing cmd req");

	if (req->data)
		free(req->data);
	if (req->platform)
		free(req->platform);

	free(req);
	pv->req = NULL;
}

static int pv_cmd_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;

	pv = get_pv_instance();
	if (!pv)
		return -1;

	if (pv_cmd_socket_open(pv, "/pv/pv-ctrl") < 0)
		pv_log(DEBUG, "control socket initialized fd=%d", pv->ctrl_fd);

	return 0;
}

struct pv_init pv_init_cmd = {
	.init_fn = pv_cmd_init,
	.flags = 0,
};
