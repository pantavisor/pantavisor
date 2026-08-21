/*
 * Copyright (c) 2026 Pantacor Ltd.
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

#include "logserver_socket.h"
#include "logserver_internal.h"
#include "paths.h"
#include "log.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <linux/limits.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdalign.h>

static int client_socket()
{
	struct sockaddr_un addr = { 0 };

	errno = 0;
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (fd == -1)
		return -1;
	return fd;
}

static void get_address(const char *path, struct sockaddr_un *addr)
{
	memset(addr, 0, sizeof(struct sockaddr_un));
	addr->sun_family = AF_UNIX;
	pv_paths_pv_file(addr->sun_path, sizeof(addr->sun_path) - 1, path);
}

ssize_t logserver_sck_get(int sock, struct logserver_sck_data *data)
{
	size_t ctrl_size = CMSG_SPACE(data->aux.len);
	char *ctrl = calloc(1, ctrl_size);
	if (!ctrl)
		return -1;

	struct msghdr msg = {
		.msg_iov = data->vec,
		.msg_iovlen = data->len,
		.msg_control = ctrl,
		.msg_controllen = ctrl_size,
	};

	ssize_t ret = -1;
	errno = 0;
	ssize_t bytes = recvmsg(sock, &msg, 0);
	if (bytes < 0)
		goto err;

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	if (cmsg && cmsg->cmsg_level == data->aux.level &&
	    cmsg->cmsg_type == data->aux.type &&
	    cmsg->cmsg_len >= CMSG_LEN(data->aux.len)) {
		memcpy(data->aux.data, CMSG_DATA(cmsg), data->aux.len);
	} else if (data->aux.type == SCM_RIGHTS) {
		memset(data->aux.data, -1, data->aux.len);
	} else {
		memset(data->aux.data, 0, data->aux.len);
	}

	ret = bytes;
err:
	free(ctrl);

	return ret;
}

ssize_t logserver_sck_send_fd(int type, int fd, char *plat, char *src,
			      size_t bufsz, int loglevel)
{
	struct sockaddr_un addr = { 0 };
	get_address(LOGFD_FNAME, &addr);

	struct iovec vec[] = {
		{ .iov_base = plat, .iov_len = bufsz },
		{ .iov_base = src, .iov_len = bufsz },
		{ .iov_base = &loglevel, .iov_len = sizeof(loglevel) },
		{ .iov_base = &type, .iov_len = sizeof(type) },
	};

	struct msghdr msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof(addr),
		.msg_iov = vec,
		.msg_iovlen = sizeof(vec) / sizeof(vec[0]),
	};

	alignas(struct cmsghdr) char ctrl[CMSG_SPACE(sizeof(int))];
	if (fd >= 0) {
		msg.msg_control = ctrl;
		msg.msg_controllen = sizeof(ctrl);

		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	}

	int sock = client_socket();
	if (sock < 0)
		return -1;

	ssize_t ret = sendmsg(sock, &msg, 0) > 0;
	close(sock);

	return ret ? 0 : -1;
}

int logserver_sck_create(const char *name, bool passcred)
{
	struct sockaddr_un addr = { 0 };
	int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1)
		return -1;

	addr.sun_family = AF_UNIX;
	pv_paths_pv_file(addr.sun_path, sizeof(addr.sun_path) - 1, name);

	unlink(addr.sun_path);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(sock);
		return -1;
	}

	if (passcred) {
		int val = 1;
		setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val));
	}

	return sock;
}

ssize_t logserver_sck_send_to(void *data, size_t len)
{
	int sock = client_socket();
	if (sock < 0)
		return -1;

	struct sockaddr_un addr = { 0 };
	get_address(LOGCTRL_FNAME, &addr);

	ssize_t bytes = sendto(sock, data, len, 0, (struct sockaddr *)&addr,
			       sizeof(addr));

	close(sock);

	return bytes;
}

void logserver_sck_close(int sock, const char *name)
{
	if (sock < 0)
		return;

	char path[PATH_MAX];
	pv_paths_pv_file(path, PATH_MAX, name);
	close(sock);
	unlink(path);
}
