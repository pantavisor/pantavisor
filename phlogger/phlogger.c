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
#include "trestclient.h"
#include "pantahub.h"
#include "pantavisor.h"
#include "phlogger_service.h"
#include "paths.h"
#include "buffer.h"
#include "config.h"
#include "utils/fs.h"

#include <trest.h>

#include <stdio.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define MODULE_NAME "phlogger"
#include "log.h"

#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PHLOGGER_PUSH_MAX_EV (5)
#define PHLOGGER_PUSH_BACKLOG (20)
#define PHLOGGER_MAX_ID_SIZE (21)
#define PHLOGGER_LOG_DELIM (0x1E)
#define PHLOGGER_MAX_LOG_SENT (5)

struct phlogger {
	int epfd;
	int sock;
	int storage_fd;
	size_t delete_data;
	struct {
		trest_ptr *client;
		struct pv_connection *endpoint;
	} conn;
	struct phlogger_service srv;
};

static int phlogger_init(void);
static void phlogger_loop(void);

// global instance
static struct phlogger phlogger = {
	.epfd = -1,
	.sock = -1,
	.storage_fd = -1,
	.delete_data = 0,
	.conn = {
		.client = NULL,
		.endpoint = NULL,
	},
	.srv = {
		.name = MODULE_NAME,
		.pid = -1,
		.flags = 0,
		.rev = NULL,
		.init = phlogger_init,
		.loop = phlogger_loop,
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

static int phlogger_init_endpoint()
{
	if (phlogger.conn.endpoint)
		return 0;

	phlogger.conn.endpoint = pv_get_instance_connection();
	if (!phlogger.conn.endpoint) {
		pv_log(ERROR, "couldn't allocate endpoint");
		return -1;
	}

	return 0;
}

static int phlogger_rest_client_new()
{
	if (phlogger.conn.client) {
		trest_free(phlogger.conn.client);
		phlogger.conn.client = NULL;
	}

	phlogger.conn.client =
		pv_get_trest_client(pv_get_instance(), phlogger.conn.endpoint);

	if (!phlogger.conn.client) {
		pv_log(ERROR, "couldn't allocate rest client");
		free(phlogger.conn.endpoint);
		return -1;
	}
	return 0;
}

static int phlogger_init_hub_connection()

{
	if (phlogger_init_endpoint() != 0)
		return -1;

	if (phlogger_rest_client_new() != 0)
		return -1;

	return 0;
}

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

static off_t phlogger_get_storage_size()
{
	struct stat s = { 0 };
	if (fstat(phlogger.storage_fd, &s) != 0)
		return -1;

	return s.st_size;
}

static void phlogger_storage_path(char *fname)
{
	char *folder = pv_config_get_str(PH_CACHE_QUEUE_PATH);
	pv_fs_path_concat(fname, 2, folder, "phlogger.cache");
}

static int phlogger_init_storage()
{
	char fname[PATH_MAX] = { 0 };

	phlogger_storage_path(fname);

	int fd = open(fname, O_RDWR | O_CLOEXEC | O_CREAT, 0600);
	if (fd < 0) {
		pv_log(ERROR, "couldn't open log temporal storage %s: %s",
		       fname, strerror(errno));
		return -1;
	}

	phlogger.storage_fd = fd;
	return 0;
}

static void phlogger_clean_queue()
{
	if (!phlogger.delete_data)
		return;

	off_t size = phlogger_get_storage_size();
	if (size < 0) {
		pv_log(WARN, "couldn't determine the storage size");
		return;
	}

	char tmp_tmpl[] = "/tmp/pv-phlog-XXXXXX";

	int tmpfd = mkstemp(tmp_tmpl);
	if (tmpfd < 0)
		return;

	FILE *phfd = fdopen(phlogger.storage_fd, "r");

	size_t len = 0;
	ssize_t nread = 0;
	ssize_t total = 0;
	char *log = NULL;

	while ((nread = getdelim(&log, &len, PHLOGGER_LOG_DELIM, phfd)) != -1) {
		if (total < phlogger.delete_data) {
			total += nread;
			continue;
		}

		pv_fs_file_write_nointr(tmpfd, log, nread);
	}
	close(tmpfd);

	char phlogger_storage[PATH_MAX] = { 0 };
	phlogger_storage_path(phlogger_storage);
	rename(tmp_tmpl, phlogger_storage);

	phlogger_init_storage();
}

static void phlogger_data_save(int fd)
{
	struct buffer *logbuf = pv_buffer_get(true);

	if (!logbuf)
		return;

	char delim = PHLOGGER_LOG_DELIM;

	ssize_t size = pv_fs_file_read_nointr(fd, logbuf->buf, logbuf->size);

	if (size < 1) {
		pv_log(INFO, "couldn't write data (size = %zd): %s", size,
		       strerror(errno));

		pv_buffer_drop(logbuf);
		return;
	}

	// sanitize the string, remove any PHLOGGER_LOG_DELIM present
	for (ssize_t i = 0; i < size; ++i) {
		if (logbuf->buf[i] == PHLOGGER_LOG_DELIM)
			logbuf->buf[i] = ' ';
	}

	// check the file size to avoid to write more than the size set
	off_t max_size = pv_config_get_int(PH_CACHE_QUEUE_MAX_SIZE);
	off_t file_size = phlogger_get_storage_size();

	if (file_size + size > max_size) {
		if (phlogger.delete_data < size)
			phlogger.delete_data = size;
		phlogger_clean_queue();
	}

	lseek(phlogger.storage_fd, 0, SEEK_END);
	pv_fs_file_write_nointr(phlogger.storage_fd, logbuf->buf, size);
	pv_fs_file_write_nointr(phlogger.storage_fd, &delim, sizeof(char));

	pv_buffer_drop(logbuf);
}

static void phlogger_receive_data()
{
	struct epoll_event ev[PHLOGGER_PUSH_MAX_EV] = { 0 };
	int n_events = phlogger_event_wait(ev);

	if (n_events < 1)
		return;

	for (int i = 0; i < n_events; ++i) {
		int cur_fd = ev[i].data.fd;

		if (!phlogger_events_ok(ev[i].events)) {
			phlogger_remove_fd(cur_fd);
			continue;
		}

		if (cur_fd == phlogger.sock) {
			int fd = phlogger_accept_connection(cur_fd);
			if (fd < 0)
				continue;

			if (phlogger_epoll_cmd(fd, EPOLL_CTL_ADD)) {
				phlogger_remove_fd(fd);
				continue;
			}
		} else {
			phlogger_data_save(cur_fd);
		}
	}
}

static char *phlogger_logs_from_file()
{
	int fd = dup(phlogger.storage_fd);
	if (fd < 0) {
		pv_log(INFO, "couldn't read the log file");
		return NULL;
	}

	FILE *f = fdopen(fd, "r");

	size_t len = 0;
	ssize_t nread = 0;
	char *line = NULL;
	char *logs = strdup("[");
	size_t total_size = 1;
	int i = 0;

	rewind(f);

	while ((nread = getdelim(&line, &len, PHLOGGER_LOG_DELIM, f)) != -1 &&
	       i < PHLOGGER_MAX_LOG_SENT) {
		char *tmp = realloc(logs, nread + total_size + 1);
		if (!tmp)
			break;

		logs = tmp;
		memcpy(logs + total_size, line, nread);
		total_size += nread + 1;
		logs[total_size - 2] = ',';
		logs[total_size - 1] = ' ';
		++i;
	}

	logs[total_size - 2] = ']';
	logs[total_size - 1] = '\0';

	free(line);
	fclose(f);

	return logs;
}

static void phlogger_push_logs()
{
	if (!phlogger.conn.client) {
		if (phlogger_rest_client_new() != 0) {
			pv_log(INFO,
			       "couldn't connect with the hub, trying again in next iteration");
			return;
		}
	}

	char *logs = phlogger_logs_from_file();
	if (!logs)
		return;

	trest_request_ptr req = NULL;
	trest_response_ptr rsp = NULL;
	trest_auth_status_enum status = trest_update_auth(phlogger.conn.client);

	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(DEBUG, "couldn't authenticate with the hub");
		goto out;
	}

	req = trest_make_request(THTTP_METHOD_POST, "/logs/", logs);
	if (!req) {
		pv_log(DEBUG, "couldn't create the request");
		goto out;
	}

	rsp = trest_do_json_request(phlogger.conn.client, req);
	if (!rsp) {
		pv_log(WARN,
		       "HTTP request POST /logs/ could not be initialized");
		goto out;
	} else if (!rsp->code && rsp->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request POST /logs/ could not auth (status = %d)",
		       rsp->status);
	} else if (rsp->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request POST /logs/ returned HTTP error (code = %d; body = '%s')",
		       rsp->code, rsp->body);
	} else {
		phlogger.delete_data = strlen(logs);
	}
out:
	if (logs)
		free(logs);
	if (req)
		trest_request_free(req);
	if (rsp)
		trest_response_free(rsp);
}

static void phlogger_loop()
{
	phlogger_receive_data();
	phlogger_push_logs();
	phlogger_clean_queue();
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
		pv_log(ERROR, "could not create %s epoll fd",
		       phlogger.srv.name);
		goto err;
	}

	phlogger.sock = phlogger_open_socket(LOGPUSH_FNAME);
	if (phlogger.sock < 0)
		goto err;

	if (phlogger_epoll_cmd(phlogger.sock, EPOLL_CTL_ADD) == -1) {
		pv_log(ERROR, "couldn't add socket to epoll list");
		goto err;
	}

	return 0;
err:
	pv_log(ERROR, "unable to start service %s: %s", phlogger.srv.name,
	       strerror(errno));

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

	if (phlogger_init_storage() != 0)
		return -1;

	if (phlogger_init_hub_connection() != 0)
		return -1;

	return 0;
}

void phlogger_stop_lenient()
{
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
		if (phlogger_service_start(&phlogger.srv, rev) != 0) {
			if (!pv_config_get_bool(PV_LOG_PUSH))
				pv_log(DEBUG,
				       "PV_LOG_PUSH is set to false, service will not be started");
			if (pv->remote_mode)
				pv_log(DEBUG,
				       "remote mode is not activated, service will not be started");
		}
	} else {
		phlogger_stop_lenient();
		phlogger_stop_force();
	}
}