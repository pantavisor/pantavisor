/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "phlogger.h"
#include "phlogger_service.h"
#include "phlogger_json_buffer.h"
#include "phlogger_client.h"
#include "phlogger_range.h"
#include "paths.h"
#include "config.h"
#include "buffer.h"
#include "utils/fs.h"
#include "utils/json.h"
#include "pvctl_utils.h"
#include <jsmn/jsmnutil.h>

#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define MODULE_NAME "phlogger"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PHLOGGER_PUSH_MAX_EV (5)
#define PHLOGGER_PUSH_BACKLOG (20)

typedef enum {
	PHLOGER_CMD_NULL = 0,
	PHLOGER_CMD_EXIT,
} phlogger_cmd_t;

struct phlogger {
	int epfd;
	int sock;
	char *buf;
	struct phlogger_client *client;
	struct phlogger_service srv;
};

static int phlogger_init(void);
static void phlogger_receive_data(void);

// global instance
static struct phlogger phlogger = {
	.epfd = -1,
	.sock = -1,
	.buf = NULL,
	.client = NULL,
	.srv = {
		.name = MODULE_NAME,
		.type = PHLOGGER_SERVICE_DAEMON,
		.pid = -1,
		.flags = 0,
		.rev = NULL,
		.init = phlogger_init,
		.proc = phlogger_receive_data,
	},
};

static int phlogger_epoll_cmd(int fd, int cmd)
{
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP,
		.data.fd = fd,
	};

	errno = 0;
	return epoll_ctl(phlogger.epfd, cmd, fd, &ev);
}

// static void phlogger_clean()
// {
// 	if (phlogger.epfd >= 0)
// 		close(phlogger.epfd);

// 	if (phlogger.sock >= 0)
// 		close(phlogger.sock);

// 	if (phlogger.storage_fd >= 0)
// 		close(phlogger.storage_fd);

// 	if (phlogger.conn.client)
// 		trest_free(phlogger.conn.client);

// 	if (phlogger.conn.endpoint)
// 		free(phlogger.conn.endpoint);

// 	if (phlogger.srv.rev)
// 		free(phlogger.srv.rev);
// }

static int phlogger_event_wait(struct epoll_event *ev)
{
	int ready = 0;
	errno = 0;
	do {
		ready = epoll_wait(phlogger.epfd, ev, PHLOGGER_PUSH_MAX_EV, -1);

		if (errno != 0 && errno != EINTR) {
			pv_log(ERROR, "error calling epoll_wait: %s",
			       strerror(errno));
			return 0;
		}
	} while (ready < 0);

	return ready;
}

static bool phlogger_events_ok(int events)
{
	if (events & EPOLLIN)
		return true;

	if (events & EPOLLRDHUP || events & EPOLLHUP || events & EPOLLERR)
		return false;

	return true;
}

static int phlogger_accept_connection(int sock)
{
	int fd = -1;

	do {
		fd = accept(sock, NULL, NULL);
		if (errno != 0 && errno != EINTR) {
			pv_log(DEBUG, "couldn't accept connection: %s",
			       strerror(errno));
			return -1;
		}
	} while (fd < 0);

	return fd;
}

static void phlogger_remove_fd(int fd)
{
	phlogger_epoll_cmd(fd, EPOLL_CTL_DEL);
	close(fd);
}

static ssize_t phlogger_get_data(int fd, struct buffer **buf)
{
	*buf = pv_buffer_get(true);
	if (!(*buf))
		return -1;

	ssize_t len = pv_fs_file_read_nointr(fd, (*buf)->buf, (*buf)->size);
	if (len < 0) {
		pv_buffer_drop(*buf);
		return -1;
	}

	return len;
}

static void phlogger_process_command(int cmd)
{
	switch (cmd) {
	case PHLOGER_CMD_NULL:
		pv_log(WARN, "unknown command received");
		break;
	case PHLOGER_CMD_EXIT:
		pv_log(DEBUG, "exit command received");
		phlogger.srv.flags = PHLOGGER_SERVICE_FLAG_STOP;
		break;
	}
}

static void phlogger_process_log(const char *log, size_t len)
{
	if (pv_phlogger_json_buffer_need_flush(phlogger.buf, len)) {
		if (!phlogger.client) {
			phlogger.client = pv_phlogger_client_new();

			if (!phlogger.client)
				return;
		}

		if (pv_phlogger_client_send_logs(phlogger.client, phlogger.buf))
			pv_phlogger_json_buffer_init(&phlogger.buf);
	}

	if (pv_phlogger_json_buffer_add(&phlogger.buf, log) != 0)
		pv_log(WARN, "couldn't add logs, some logs could be lost");
}

static void phlogger_process_data(int fd)
{
	struct buffer *buf;

	int tokc;
	jsmntok_t *tokv = NULL;

	ssize_t len = phlogger_get_data(fd, &buf);
	if (len < 0) {
		pv_log(WARN, "couldn't retrieve data, some logs could be lost");
		return;
	}

	char *json = calloc(len + 1, sizeof(char));
	if (!json) {
		pv_buffer_drop(buf);
		return;
	}

	memcpy(json, buf->buf, len);
	pv_buffer_drop(buf);

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		free(json);
		return;
	}

	char *type = pv_json_get_value(json, "type", tokv, tokc);
	if (type && strncmp(type, "cmd", 3)) {
		int cmd = pv_json_get_value_int(json, "cmd", tokv, tokc);
		phlogger_process_command(cmd);
	} else {
		phlogger_process_log(json, len);
	}

	if (type)
		free(type);
	free(json);
	free(tokv);
}

static void phlogger_receive_data()
{
	struct epoll_event ev[PHLOGGER_PUSH_MAX_EV] = { 0 };
	int n_events = phlogger_event_wait(ev);
	if (n_events < 1)
		return;

	for (int i = 0; i < n_events; ++i) {
		int cur_fd = ev[i].data.fd;

		// check events
		if (!phlogger_events_ok(ev[i].events)) {
			phlogger_remove_fd(cur_fd);
			continue;
		}

		// add the fd to the epoll list if the connection is accepted
		if (cur_fd == phlogger.sock) {
			int fd = phlogger_accept_connection(cur_fd);
			if (fd < 0)
				continue;

			if (phlogger_epoll_cmd(fd, EPOLL_CTL_ADD)) {
				phlogger_remove_fd(fd);
				continue;
			}
		} else {
			phlogger_process_data(cur_fd);
			phlogger_remove_fd(cur_fd);
		}
	}
}

static int phlogger_open_socket(const char *name)
{
	struct sockaddr_un addr = { 0 };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		pv_log(ERROR, "unable to open socket: %d", errno);
		return -1;
	}

	size_t size = sizeof(addr.sun_path);
	addr.sun_family = AF_UNIX;
	pv_paths_pv_file(addr.sun_path, size - 1, name);

	// sometimes, the socket file still exists after reboot
	unlink(addr.sun_path);

	if (bind(fd, (const struct sockaddr *)&addr, size) == -1) {
		pv_log(ERROR, "unable to bind socket: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (listen(fd, PHLOGGER_PUSH_BACKLOG) == -1) {
		pv_log(ERROR, "unable to listen to control socket: %d",
		       strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static int phlogger_init_socket()
{
	phlogger.epfd = epoll_create1(0);
	if (phlogger.epfd < 0) {
		pv_log(ERROR, "could not create phlogger epoll fd");
		goto err;
	}

	phlogger.sock = phlogger_open_socket(LOGPUSH_FNAME);
	if (phlogger.sock < 0)
		goto err;

	if (phlogger_epoll_cmd(phlogger.sock, EPOLL_CTL_ADD) == -1) {
		pv_log(ERROR, "couldn't add socket to epoll list");
		goto err;
	}

	pv_log(DEBUG, "socket initialized");
	return 0;
err:
	pv_log(ERROR, "unable to start phlogger service: %s", strerror(errno));

	if (phlogger.sock >= 0)
		close(phlogger.sock);

	if (phlogger.epfd >= 0)
		close(phlogger.epfd);

	return -1;
}

static int phlogger_init()
{
	if (phlogger_init_socket() != 0)
		return -1;

	int err = pv_phlogger_json_buffer_init(&phlogger.buf);

	pv_phlogger_range_start(phlogger.srv.rev);

	return err;
}

static void phlogger_send_cmd(phlogger_cmd_t code)
{
	const char *tmp = "{\"type\": \"cmd\", \"cmd\": %d}";
	char *cmd = NULL;
	if (asprintf(&cmd, tmp, code) == -1) {
		pv_log(DEBUG, "couldn't send stop command");
		return;
	}

	char path[PATH_MAX] = { 0 };
	pv_paths_pv_file(path, PATH_MAX, LOGPUSH_FNAME);

	pvctl_write_to_path(path, cmd, strlen(cmd));
	free(cmd);
}

void phlogger_stop_lenient()
{
	phlogger_send_cmd(PHLOGER_CMD_EXIT);
	phlogger_service_stop_lenient(&phlogger.srv);
}

void phlogger_stop_force()
{
	phlogger_service_stop_force(&phlogger.srv);
}

void phlogger_toggle(const char *rev)
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	if (pv_config_get_bool(PV_LOG_PUSH) && pv->remote_mode) {
		if (phlogger_service_start(&phlogger.srv, rev) == 0)
			pv_log(DEBUG, "service started");

	} else {
		phlogger_stop_lenient();
		phlogger_stop_force();
	}
}