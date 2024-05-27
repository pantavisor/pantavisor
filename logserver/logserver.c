/*
 * Copyright (c) 2022 Pantacor Ltd.
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

#include <linux/limits.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <inttypes.h>
#include <libgen.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <inttypes.h>

#include "logserver_out.h"
#include "logserver_utils.h"
#include "logserver_null.h"
#include "logserver_filetree.h"
#include "logserver_singlefile.h"
#include "logserver_update.h"
#include "logserver_stdout.h"
#include "logserver.h"
#include "utils/timer.h"
#include "utils/fs.h"
#include "utils/json.h"
#include "utils/system.h"
#include "utils/list.h"
#include "utils/socket.h"
#include "utils/pvsignals.h"
#include "pvctl_utils.h"
#include "config.h"

#include "pantavisor.h"
#include "buffer.h"
#include "paths.h"
#include "config.h"
#include "wdt.h"

#include "log.h"

#define PH_LOGGER_MAX_EPOLL_FD (50)
#define LOGSERVER_FLAG_STOP (1 << 0)
#define LOGSERVER_BACKLOG (20)
#define LOGSERVER_MAX_EV (5)
#define LOGSERVER_MAX_HEADER_LEN (50)

#define MODULE_NAME "logserver"

typedef enum {
	LOG_CMD_NULL = 0,
	LOG_CMD_EXIT,
	LOG_CMD_START_UPDATE,
	LOG_CMD_STOP_UPDATE,
	LOG_CMD_TRANSITION,
} log_cmd_code_t;

struct logserver_msg {
	log_protocol_code_t code;
	int len;
	char buf[0];
};

struct logserver_fd {
	char *platform;
	char *src;
	int lvl;
	int fd;
	struct dl_list list;
};

struct logserver {
	pid_t pid;
	pid_t cmd_pid;
	int flags;
	int epfd;
	int logsock;
	int fdsock;
	int active_out;
	char *running_rev;
	char *updated_rev;
	// logserver_fd
	struct dl_list fdlst;
	// tmp store for fd returned by connect
	// only if was sent to the fd_sock
	struct dl_list tmplst;
	struct dl_list outputs;
};

static struct logserver logserver = {
	.pid = -1,
	.flags = 0,
	.epfd = -1,
	.logsock = -1,
	.fdsock = -1,
	.active_out = LOG_SERVER_OUTPUT_NULL_SINK,
	.running_rev = NULL,
	.updated_rev = NULL,
};

typedef struct logserver_out *(*logserver_outputs_builder_t)(void);

#define LOGSERVER_MAX_OUTPUTS (8)

static logserver_outputs_builder_t
	logserver_outputs_new[LOGSERVER_MAX_OUTPUTS] = {
		logserver_null_new,
		logserver_singlefile_new,
		logserver_filetree_new,
		logserver_null_new,
		logserver_update_new,
		logserver_stdout_new,
		logserver_stdout_containers_new,
		logserver_stdout_pantavisor_new
	};

static int logserver_log_msg_data(const struct logserver_log *log, int output)
{
	if ((output > 0 && !(logserver.active_out & output)) || output < 0)
		return -1;

	struct logserver_out *it, *tmp;
	dl_list_for_each_safe(it, tmp, &logserver.outputs, struct logserver_out,
			      list)
	{
		if (output == 0) {
			if (logserver.active_out & it->id)
				it->add(it, log);
		} else {
			if (!(it->id & output))
				continue;
			it->add(it, log);
		}
	}

	return 0;
}

static int pv_log(int level, char *msg, ...)
{
	va_list args;
	va_start(args, msg);

	if (logserver.pid == 0) {
		struct buffer *pv_buffer = pv_buffer_get(true);
		char *buf = pv_buffer->buf;
		int buf_len;

		buf_len = vsnprintf(buf, pv_buffer->size, msg, args);

		struct logserver_log data = {
			.code = LOG_PROTOCOL_LEGACY,
			.lvl = level,
			.tsec = timer_get_current_time_sec(RELATIV_TIMER),
			.time = time(NULL),
			.plat = PV_PLATFORM_STR,
			.src = "logserver",
			.running_rev = logserver.running_rev,
			.updated_rev = logserver.updated_rev,
			.data.buf = buf,
			.data.len = buf_len
		};

		logserver_log_msg_data(&data, 0);

		pv_buffer_drop(pv_buffer);
	} else {
		pv_logserver_send_vlog(false, PV_PLATFORM_STR, MODULE_NAME,
				       level, msg, args);
	}

	va_end(args);
	return 0;
}

static void sigchld_handler(int signum)
{
	/*
	 * Reap the child procs.
	 */
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}

static int logserver_msg_parse_data(struct logserver_msg *msg,
				    struct logserver_log *log)
{
	int bytes_read = 0;
	int ret;
	log->code = msg->code;
	switch (log->code) {
	case LOG_PROTOCOL_LEGACY:
		sscanf(msg->buf, "%d", &log->lvl);
		bytes_read += strlen(msg->buf) + 1;
		//+ 1 to Skip over the NULL byte post level
		log->plat = msg->buf + strlen(msg->buf) + 1;
		bytes_read += strlen(log->plat) + 1;
		log->src = log->plat + strlen(log->plat) + 1;
		log->running_rev = logserver.running_rev;
		log->updated_rev = logserver.updated_rev;
		bytes_read += strlen(log->src) + 1;

		log->data.buf = log->src + strlen(log->src) + 1;
		log->data.len = msg->len - bytes_read;
		log->tsec = timer_get_current_time_sec(RELATIV_TIMER);
		log->tnano = 0;
		log->time = time(NULL), ret = 0;
		break;
	case LOG_PROTOCOL_CMD:
		log->data.buf = msg->buf;
		log->data.len = msg->len;
		ret = 0;
		break;
	default:
		pv_log(WARN, "got unkown logserver message version %d",
		       log->code);
		ret = -1;
		break;
	}
	return ret;
}

static void logserver_rename_update(const char *rev)
{
	char path_tmp[PATH_MAX];
	pv_paths_storage_trail_pv_file(path_tmp, PATH_MAX, rev, LOGS_TMP_FNAME);

	char path_perm[PATH_MAX];
	pv_paths_storage_trail_pv_file(path_perm, PATH_MAX, rev, LOGS_FNAME);

	// we rename the log.tmp file into the definitive one if it exists
	pv_fs_path_rename(path_tmp, path_perm);
}

static int logserver_process_cmd(const struct logserver_log *log,
				 pid_t sender_pid)
{
	if (sender_pid != logserver.cmd_pid) {
		pv_log(WARN,
		       "logserver command received from pid %d while authorized pid is %d only",
		       sender_pid, logserver.cmd_pid);
		return -1;
	}

	int tokc;
	jsmntok_t *tokv = NULL;
	jsmnutil_parse_json(log->data.buf, &tokv, &tokc);

	log_cmd_code_t cmd_code;
	cmd_code = pv_json_get_value_int(log->data.buf, "code", tokv, tokc);

	char *data;
	data = pv_json_get_value(log->data.buf, "data", tokv, tokc);

	switch (cmd_code) {
	case LOG_CMD_EXIT:
		pv_log(DEBUG, "exit command received");
		logserver.flags = LOGSERVER_FLAG_STOP;
		break;
	case LOG_CMD_START_UPDATE:
		pv_log(DEBUG,
		       "start update command received with revision '%s'",
		       data);
		if (logserver.updated_rev)
			free(logserver.updated_rev);
		logserver.updated_rev = strdup(data);
		break;
	case LOG_CMD_STOP_UPDATE:
		pv_log(DEBUG, "stop update command received");
		logserver_rename_update(logserver.updated_rev);
		if (logserver.updated_rev)
			free(logserver.updated_rev);
		logserver.updated_rev = NULL;
		break;
	case LOG_CMD_TRANSITION:
		pv_log(DEBUG, "transition command received with revision '%s'",
		       data);
		if (logserver.running_rev)
			free(logserver.running_rev);
		logserver.running_rev = strdup(data);
		break;
	case LOG_CMD_NULL:
		pv_log(WARN, "unknown command received");
		break;
	}

	if (tokv)
		free(tokv);
	if (data)
		free(data);

	return 0;
}

static int logserver_handle_msg(struct logserver_msg *msg, pid_t sender_pid)
{
	struct logserver_log log;
	int ret;

	ret = logserver_msg_parse_data(msg, &log);
	if (ret != 0) {
		pv_log(WARN, "logserver message could not be handled");
		return ret;
	}

	switch (msg->code) {
	case LOG_PROTOCOL_LEGACY:
		ret = logserver_log_msg_data(&log, 0);
		break;
	case LOG_PROTOCOL_CMD:
		ret = logserver_process_cmd(&log, sender_pid);
		break;
	}

	return ret;
}

static int logserver_epoll_command(int fd, int cmd)
{
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.fd = fd;
	errno = 0;
	return epoll_ctl(logserver.epfd, cmd, fd, &ev);
}

static int logserver_epoll_add(int fd)
{
	return logserver_epoll_command(fd, EPOLL_CTL_ADD);
}

static int logserver_epoll_del(int fd)
{
	return logserver_epoll_command(fd, EPOLL_CTL_DEL);
}

static int logserver_accept_connection(int sockd)
{
	int fd = -1;
	errno = 0;

	do {
		fd = accept(sockd, NULL, NULL);
		if (errno != 0 && errno != EINTR) {
			pv_log(ERROR, "could not accept: %s", strerror(errno));
			return -1;
		}
	} while (fd < 0);

	return fd;
}

static struct logserver_fd *logserver_fd_new(char *platform, char *src, int fd,
					     int level)
{
	struct logserver_fd *lfd = calloc(1, sizeof(struct logserver_fd));
	if (!lfd)
		return NULL;

	if (platform)
		lfd->platform = strdup(platform);
	if (src)
		lfd->src = strdup(src);
	lfd->fd = fd;
	lfd->lvl = level;

	dl_list_init(&lfd->list);

	return lfd;
}

static void logserver_fd_free(struct logserver_fd *lfd)
{
	if (!lfd)
		return;

	if (lfd->platform)
		free(lfd->platform);
	if (lfd->src)
		free(lfd->src);
	free(lfd);
}

static bool logserver_list_exists(struct dl_list *lst, int fd)
{
	struct logserver_fd *it = NULL, *tmp = NULL;

	dl_list_for_each_safe(it, tmp, lst, struct logserver_fd, list)
	{
		if (fd == it->fd)
			return true;
	}

	return false;
}

static void logserver_list_del(struct dl_list *lst, int fd,
			       const char *platform)
{
	struct logserver_fd *it, *tmp;
	dl_list_for_each_safe(it, tmp, lst, struct logserver_fd, list)
	{
		if (platform) {
			if (strcmp(it->platform, platform) == 0) {
				dl_list_del(&it->list);
				logserver_fd_free(it);
				return;
			}
		} else {
			if (it->fd == fd) {
				dl_list_del(&it->list);
				logserver_fd_free(it);
				return;
			}
		}
	}
}

static int logserver_list_add(struct dl_list *tmplst, struct logserver_fd *lfd)
{
	if (!lfd)
		return -1;
	dl_list_add(tmplst, &lfd->list);
	return 0;
}

static struct logserver_fd *logserver_fetch_fd_from_list(struct dl_list *l,
							 int fd)
{
	struct logserver_fd *it, *tmp;
	dl_list_for_each_safe(it, tmp, l, struct logserver_fd, list)
	{
		if (it->fd == fd) {
			return it;
		}
	}
	return NULL;
}

static struct logserver_fd *logserver_get_fd(int sockfd)
{
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} ctrl;

	char platform[LOGSERVER_MAX_HEADER_LEN] = { 0 };
	char src[LOGSERVER_MAX_HEADER_LEN] = { 0 };
	int loglevel = -1;
	int add = 0;

	struct iovec iov[4];
	iov[0] = (struct iovec){ .iov_base = platform,
				 .iov_len = LOGSERVER_MAX_HEADER_LEN };
	iov[1] = (struct iovec){ .iov_base = src,
				 .iov_len = LOGSERVER_MAX_HEADER_LEN };
	iov[2] =
		(struct iovec){ .iov_base = &loglevel, .iov_len = sizeof(int) };
	iov[3] = (struct iovec){ .iov_base = &add, .iov_len = sizeof(int) };

	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 4,
		.msg_control = ctrl.buf,
		.msg_controllen = sizeof(ctrl.buf),
	};

	errno = 0;
	if (recvmsg(sockfd, &msg, 0) < 0) {
		pv_log(ERROR, "error receiving fd: %s", strerror(errno));
		return NULL;
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		pv_log(ERROR, "error receiving fd, NULL structure");
		return NULL;
	}

	int fd = -1;

	if (add)
		memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));

	return logserver_fd_new(platform, src, fd, loglevel);
}

static int logserver_epoll_wait(struct epoll_event *ev)
{
	int ready = 0;
	errno = 0;
	do {
		ready = epoll_wait(logserver.epfd, ev, LOGSERVER_MAX_EV, -1);

		if (errno != 0 && errno != EINTR) {
			pv_log(ERROR, "error calling epoll_wait: %s",
			       strerror(errno));
			return 0;
		}
	} while (ready < 0);

	return ready;
}

static void logserver_remove_fd(int fd)
{
	if (fd < 0)
		return;

	if (logserver_list_exists(&logserver.fdlst, fd)) {
		struct logserver_fd *lfd =
			logserver_fetch_fd_from_list(&logserver.fdlst, fd);

		pv_log(DEBUG, "fd (%d) for platform %s:%s unsubscribed",
		       lfd->fd, lfd->platform, lfd->src);

		logserver_list_del(&logserver.fdlst, fd, NULL);

	} else if (logserver_list_exists(&logserver.tmplst, fd))
		logserver_list_del(&logserver.tmplst, fd, NULL);

	logserver_epoll_del(fd);
	close(fd);
}

static void logserver_consume_log_data(int fd)
{
	struct buffer *buffer = pv_buffer_get(true);

	if (!buffer)
		return;

	errno = 0;
	if (pv_fs_file_read_nointr(fd, buffer->buf, buffer->size) > 0) {
		pid_t sender_pid = pv_socket_get_sender_pid(fd);
		struct logserver_msg *msg = (struct logserver_msg *)buffer->buf;
		logserver_handle_msg(msg, sender_pid);
	} else if (errno != EAGAIN) {
		pv_log(DEBUG, "dead fd (%d) found trying to read: %s", errno,
		       strerror(errno));
		logserver_remove_fd(fd);
	}

	pv_buffer_drop(buffer);
}

static void logserver_consume_fd(int fd)
{
	struct buffer *buffer = pv_buffer_get(true);
	ssize_t size = 0;
	if (!buffer)
		return;

	errno = 0;
	size = pv_fs_file_read_nointr(fd, buffer->buf, buffer->size);

	if (size > 0) {
		struct logserver_fd *lfd =
			logserver_fetch_fd_from_list(&logserver.fdlst, fd);

		struct logserver_log d = {
			.code = LOG_PROTOCOL_LEGACY,
			.lvl = lfd->lvl,
			.tsec = timer_get_current_time_sec(RELATIV_TIMER),
			.time = time(NULL),
			.plat = lfd->platform,
			.src = lfd->src,
			.running_rev = logserver.running_rev,
			.updated_rev = logserver.updated_rev,
			.data.buf = buffer->buf,
			.data.len = size,
		};

		logserver_log_msg_data(&d, 0);
	} else if (errno != EAGAIN) {
		pv_log(DEBUG,
		       "dead fd subscribed found (%d) trying to read: %s",
		       errno, strerror(errno));
		logserver_remove_fd(fd);
	}
	pv_buffer_drop(buffer);
}

static int logserver_process_fd(int curfd)
{
	int ret = 0;
	struct logserver_fd *lfd = NULL;

	lfd = logserver_get_fd(curfd);

	if (!lfd) {
		ret = -1;
		goto clean_all;
	}

	// unsubscribe the platform
	if (lfd->fd < 0) {
		logserver_remove_fd(curfd);
		goto clean_all;
	}

	// subcribe new fd
	if (logserver_list_add(&logserver.fdlst, lfd) != 0) {
		ret = -1;
		goto clean_all;
	}

	if (logserver_epoll_add(lfd->fd) != 0) {
		ret = -1;
		goto clean_all;
	}

	pv_log(DEBUG, "new fd (%d) for %s:%s subscribed", lfd->fd,
	       lfd->platform, lfd->src);
	return ret;

clean_all:
	if (ret != 0) {
		if (lfd)
			pv_log(DEBUG, "couldn't subscribe fd (%d) for %s:%s",
			       lfd->fd, lfd->platform, lfd->src);
		else
			pv_log(DEBUG, "couldn't subcribe fd (lfd == NULL)");
	}

	if (lfd)
		logserver_fd_free(lfd);

	return ret;
}

static void logserver_loop()
{
	struct epoll_event ev[LOGSERVER_MAX_EV];
	int n_events = logserver_epoll_wait(ev);

	if (n_events < 1) {
		return;
	}

	int logsock = logserver.logsock;
	int fdsock = logserver.fdsock;
	struct dl_list *tmplst = &logserver.tmplst;
	struct dl_list *fdlst = &logserver.fdlst;

	int curfd = -1;
	int curev = 0;
	for (int i = 0; i < n_events; ++i) {
		curfd = ev[i].data.fd;
		curev = ev[i].events;
		if (!(curev & EPOLLIN)) {
			if (curev & EPOLLRDHUP || curev & EPOLLHUP ||
			    curev & EPOLLERR) {
				pv_log(DEBUG, "dead fd found (fd = %d)", curfd);
				logserver_remove_fd(curfd);
			}

			continue;
		}

		if (curfd == logsock || curfd == fdsock) {
			int fd = logserver_accept_connection(curfd);
			if (fd < 0) {
				continue;
			}

			if (logserver_epoll_add(fd) != 0) {
				logserver_remove_fd(fd);
				continue;
			}

			if (curfd == fdsock) {
				struct logserver_fd *lfd =
					logserver_fd_new(NULL, NULL, fd, ALL);

				if (logserver_list_add(tmplst, lfd) != 0) {
					logserver_fd_free(lfd);
					logserver_remove_fd(fd);
				}
			}
		} else if (logserver_list_exists(tmplst, curfd)) {
			logserver_process_fd(curfd);
			logserver_remove_fd(curfd);
		} else {
			bool sub = logserver_list_exists(fdlst, curfd);

			if (!sub) {
				logserver_consume_log_data(curfd);
				logserver_remove_fd(curfd);
			} else {
				logserver_consume_fd(curfd);
			}
		}
	}
}

static int logserver_open_client_socket(const char *fname)
{
	struct sockaddr_un addr = { 0 };

	errno = 0;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		pv_log(ERROR, "unable to open control socket: %s", errno);
		return -1;
	}

	addr.sun_family = AF_UNIX;
	pv_paths_pv_file(addr.sun_path, sizeof(addr.sun_path) - 1, fname);

	int r = connect(fd, (struct sockaddr *)&addr,
			sizeof(struct sockaddr_un));
	if (r == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

static int logserver_open_server_socket(const char *fname)
{
	struct sockaddr_un addr = { 0 };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		pv_log(ERROR, "unable to open control socket: %d", errno);
		return -1;
	}

	addr.sun_family = AF_UNIX;
	pv_paths_pv_file(addr.sun_path, sizeof(addr.sun_path) - 1, fname);

	// sometimes, the socket file still exists after reboot
	unlink(addr.sun_path);

	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr.sun_path)) ==
	    -1) {
		pv_log(ERROR, "unable to bind control socket: %s",
		       strerror(errno));
		close(fd);
		return -1;
	}

	// queue upto LOGSERVER_BACKLOG commands
	if (listen(fd, LOGSERVER_BACKLOG) == -1) {
		pv_log(ERROR, "unable to listen to control socket: %d",
		       strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static void logserver_drop_fds(struct dl_list *lst)
{
	struct logserver_fd *it, *tmp;
	dl_list_for_each_safe(it, tmp, lst, struct logserver_fd, list)
	{
		logserver_epoll_del(it->fd);
		dl_list_del(&it->list);
		logserver_fd_free(it);
	}
}

static pid_t logserver_start_service(const char *running_revision)
{
	sigset_t oldmask;
	logserver.cmd_pid = getpid();
	if (pvsignals_block_chld(&oldmask)) {
		pv_log(ERROR,
		       "failed to block SIGCHLD for starting logserver: ",
		       strerror(errno));
		return -1;
	}
	logserver.pid = fork();
	if (logserver.pid == 0) {
		signal(SIGCHLD, sigchld_handler);
		if (pvsignals_setmask(&oldmask)) {
			pv_log(ERROR,
			       "Unable to reset sigmask of logserver child: %s",
			       strerror(errno));
			_exit(-1);
		}

		pv_wdt_stop();

		if (logserver.running_rev)
			free(logserver.running_rev);
		logserver.running_rev = strdup(running_revision);

		pv_log(DEBUG, "starting logserver loop");

		while (!(logserver.flags & LOGSERVER_FLAG_STOP)) {
			logserver_loop();
		}

		logserver_drop_fds(&logserver.fdlst);
		logserver_drop_fds(&logserver.tmplst);

		_exit(EXIT_SUCCESS);
	}

	if (pvsignals_setmask(&oldmask)) {
		pv_log(ERROR, "Unable to reset sigmask in logserver parent: %s",
		       strerror(errno));
	}

	return logserver.pid;
}

static void logserver_start(const char *running_revision)
{
	if (logserver.pid == -1) {
		logserver_start_service(running_revision);
		pv_log(DEBUG, "starting log service with pid %d",
		       (int)logserver.pid);

		if (logserver.pid > 0) {
			pv_log(DEBUG, "started log service with pid %d",
			       (int)logserver.pid);
		} else {
			pv_log(ERROR, "unable to start log service");
		}
	}
}

// XXX: this is bad code now. stop must never happen here; we
// should kill this function and do the starting directly in the main
// lifecycle code that currently calls this; disabling log capture
// should happen through a "nullsink".
void pv_logserver_toggle(struct pantavisor *pv, const char *running_rev)
{
	if (!pv)
		return;

	// only start if we have log_capture configured
	if (pv_config_get_bool(PV_LOG_CAPTURE)) {
		logserver_start(running_rev);
	}
}

static void logserver_capture_dmesg()
{
	errno = 0;
	int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		pv_log(WARN, "could not susbcribe dmesg to logserver %s",
		       strerror(errno));
		return;
	}

	pv_logserver_subscribe_fd(fd, "pantavisor", "dmesg", INFO);
	pv_log(DEBUG, "subscribing dmesg to logserver");
}

static void pv_logserver_delete_outputs()
{
	struct logserver_out *it, *tmp;
	dl_list_for_each_safe(it, tmp, &logserver.outputs, struct logserver_out,
			      list)
	{
		dl_list_del(&it->list);
		logserver_out_free(it);
	}
}

static void logserver_load_outputs()
{
	dl_list_init(&logserver.outputs);
	for (int i = 0; i < LOGSERVER_MAX_OUTPUTS; i++) {
		struct logserver_out *out = logserver_outputs_new[i]();
		if (!out) {
			pv_log(WARN, "cannot create output %s",
			       logserver_utils_output_to_str(1 << i));
			continue;
		}
		dl_list_add(&logserver.outputs, &out->list);
	}
}

int pv_logserver_init(const char *rev)
{
	if (!rev)
		return -1;

	if (pv_config_get_bool(PV_LOG_CAPTURE)) {
		logserver.active_out = pv_config_get_log_server_outputs();
		logserver_load_outputs();
	}

	errno = 0;
	logserver.epfd = epoll_create1(0);

	if (logserver.epfd < 0) {
		pv_log(ERROR, "could not create logserver epoll fd");
		return -1;
	}

	logserver.logsock = logserver_open_server_socket(LOGCTRL_FNAME);
	if (logserver.logsock < 0)
		pv_log(WARN,
		       "could not initialize log socket, logs will not be captured");

	logserver.fdsock = logserver_open_server_socket(LOGFD_FNAME);
	if (logserver.fdsock < 0)
		pv_log(WARN,
		       "could not open fd socket, some containers logs will be lost");

	if (logserver_epoll_add(logserver.logsock) == -1) {
		pv_log(WARN,
		       "could not init log socket, logs will not be captured");
		goto out;
	}

	if (logserver_epoll_add(logserver.fdsock) == -1) {
		pv_log(WARN,
		       "could not init fd socket, some containers logs will be lost");
		goto out;
	}

	dl_list_init(&logserver.fdlst);
	dl_list_init(&logserver.tmplst);
	logserver_start_service(rev);
	pv_log(DEBUG, "started log service with pid %d", (int)logserver.pid);

	if (pv_config_get_bool(PV_LOG_CAPTURE_DMESG))
		logserver_capture_dmesg();

	return 0;
out:
	if (logserver.logsock >= 0)
		close(logserver.logsock);
	if (logserver.fdsock >= 0)
		close(logserver.fdsock);
	if (logserver.epfd >= 0)
		close(logserver.epfd);

	return -1;
}

static int logserver_msg_fill(struct logserver_log *log,
			      struct logserver_msg *msg)
{
	int avail_len = msg->len;
	ssize_t written = 0;
	int to_copy = 0;
	msg->code = log->code;
	switch (msg->code) {
	case LOG_PROTOCOL_LEGACY:
		//Copy level.
		written += snprintf(msg->buf + written, avail_len, "%d%c",
				    log->lvl, '\0');
		avail_len = msg->len - written;

		written += snprintf(msg->buf + written, avail_len, "%s%c",
				    log->plat, '\0');
		avail_len = msg->len - written;

		written += snprintf(msg->buf + written, avail_len, "%s%c",
				    log->src, '\0');
		avail_len = msg->len - written;

		to_copy = (log->data.len <= avail_len) ? log->data.len :
							       avail_len;
		memcpy(msg->buf + written, log->data.buf, to_copy);
		msg->len = written + to_copy;

		return to_copy;
	case LOG_PROTOCOL_CMD:
		to_copy = log->data.len;
		memcpy(msg->buf + written, log->data.buf, to_copy);
		msg->len = written + to_copy;
		break;
	default:
		return 0;
	}
	return 0;
}
int pv_logserver_send_vlog(bool is_platform, char *platform, char *src,
			   int level, const char *msg, va_list args)
{
	struct logserver_log log = {
		.code = LOG_PROTOCOL_LEGACY,
		.lvl = level,
		.tsec = timer_get_current_time_sec(RELATIV_TIMER),
		.tnano = 0,
		.time = time(NULL),
		.plat = platform,
		.src = src,
	};

	if ((level != FATAL) && (level > pv_config_get_int(PV_LOG_LEVEL)))
		return 0;

	struct buffer *log_buf = pv_buffer_get(true);
	if (!log_buf)
		return -1;

	log.data.buf = (char *)log_buf->buf;
	log.data.len = log_buf->size;

	log.data.len = vsnprintf(log.data.buf, log.data.len, msg, args);

	if (((pv_config_get_log_server_outputs() & LOG_SERVER_OUTPUT_STDOUT) &&
	     (logserver.pid < 0)) ||
	    (pv_config_get_log_server_outputs() &
	     LOG_SERVER_OUTPUT_STDOUT_DIRECT) ||
	    (level == FATAL)) {
		logserver_utils_stdout(&log);
	}

	if (logserver.pid < 1) {
		pv_buffer_drop(log_buf);
		return 0;
	}

	struct buffer *msg_buf = pv_buffer_get(true);
	if (!msg_buf) {
		pv_buffer_drop(log_buf);
		return -1;
	}

	struct logserver_msg *lsmsg = (struct logserver_msg *)msg_buf->buf;
	lsmsg->len = msg_buf->size - sizeof(*lsmsg);

	int len = logserver_msg_fill(&log, lsmsg);

	char path[PATH_MAX] = { 0 };
	pv_paths_pv_file(path, PATH_MAX, LOGCTRL_FNAME);

	pvctl_write_to_path(is_platform ? PLATFORM_LOG_CTRL_PATH : path,
			    (char *)lsmsg, lsmsg->len + sizeof(*lsmsg));

	pv_buffer_drop(log_buf);
	pv_buffer_drop(msg_buf);
	return len;
}

int pv_logserver_send_log(bool is_platform, char *platform, char *src,
			  int level, const char *msg, ...)
{
	va_list args;
	int ret;
	va_start(args, msg);

	ret = pv_logserver_send_vlog(is_platform, platform, src, level, msg,
				     args);

	va_end(args);
	return ret;
}

static void logserver_close_socket(int sockd, const char *name)
{
	if (sockd < 0)
		return;

	char path[PATH_MAX];
	pv_paths_pv_file(path, PATH_MAX, name);
	close(sockd);
	unlink(path);

	pv_log(DEBUG, "closed '%s' with fd %d", path, sockd);
}

static void pv_logserver_close(void)
{
	if (logserver.logsock >= 0) {
		pv_log(DEBUG, "closing logsock...");
		logserver_close_socket(logserver.logsock, LOGCTRL_FNAME);
		logserver.logsock = -1;
	}
	if (logserver.fdsock >= 0) {
		pv_log(DEBUG, "closing fdsock...");
		logserver_close_socket(logserver.fdsock, LOGFD_FNAME);
		logserver.fdsock = -1;
	}

	if (logserver.epfd >= 0) {
		pv_log(DEBUG, "closing epfd...");
		close(logserver.epfd);
		logserver.epfd = -1;
	}
}

static void pv_logserver_send_cmd(log_cmd_code_t code, const char *data)
{
	struct logserver_log log = {
		.code = LOG_PROTOCOL_CMD,
	};

	static const unsigned int CMD_BUF_SIZE = 256;
	char log_buf[CMD_BUF_SIZE];
	memset(log_buf, 0, CMD_BUF_SIZE);

	log.data.buf = (char *)log_buf;
	log.data.len = CMD_BUF_SIZE;

	log.data.len = snprintf(log.data.buf, log.data.len,
				"{\"code\":%d,\"data\":\"%s\"}", code, data);

	char msg_buf[CMD_BUF_SIZE];
	memset(msg_buf, 0, CMD_BUF_SIZE);

	struct logserver_msg *lsmsg = (struct logserver_msg *)msg_buf;
	lsmsg->len = CMD_BUF_SIZE - sizeof(*lsmsg);

	logserver_msg_fill(&log, lsmsg);

	char path[PATH_MAX] = { 0 };
	pv_paths_pv_file(path, PATH_MAX, LOGCTRL_FNAME);

	pvctl_write_to_path(path, (char *)lsmsg, lsmsg->len + sizeof(*lsmsg));
}

void pv_logserver_transition(const char *rev)
{
	if (!rev)
		return;

	pv_log(DEBUG, "transitioning logserver to rev '%s'", rev);
	pv_logserver_send_cmd(LOG_CMD_TRANSITION, rev);
}

static void pv_logserver_free()
{
	if (logserver.running_rev)
		free(logserver.running_rev);
	if (logserver.updated_rev)
		free(logserver.updated_rev);
}

void pv_logserver_stop(void)
{
	if (logserver.pid < 0)
		return;

	pv_log(DEBUG, "stopping logserver service with PID %d...",
	       logserver.pid);

	pv_logserver_send_cmd(LOG_CMD_EXIT, NULL);

	pv_system_kill_force(logserver.pid);
	logserver.pid = -1;

	pv_logserver_close();
	pv_logserver_delete_outputs();
	pv_logserver_free();

	pv_log(DEBUG, "stopped logserver service");
}

void pv_logserver_start_update(const char *rev)
{
	if (!rev)
		return;

	pv_log(DEBUG, "starting logserver update with rev '%s'", rev);
	pv_logserver_send_cmd(LOG_CMD_START_UPDATE, rev);
}

void pv_logserver_stop_update(const char *rev)
{
	pv_log(DEBUG, "stopping logserver update with rev '%s'", rev);
	pv_logserver_send_cmd(LOG_CMD_STOP_UPDATE, NULL);

	// we wait 5 seconds max to make sure we collect update logs
	char path[PATH_MAX];
	pv_paths_storage_trail_pv_file(path, PATH_MAX, rev, LOGS_FNAME);
	if (!pv_fs_path_exist_timeout(path, 5))
		pv_log(DEBUG, "update logs in path '%s' does not exist", path);
}

static int logserver_send_subs_msg(int type, int fd, const char *platform,
				   const char *src, int loglevel)
{
	char plat_buf[LOGSERVER_MAX_HEADER_LEN] = { 0 };
	char src_buf[LOGSERVER_MAX_HEADER_LEN] = { 0 };

	strncpy(plat_buf, platform, LOGSERVER_MAX_HEADER_LEN - 1);
	strncpy(src_buf, src, LOGSERVER_MAX_HEADER_LEN - 1);

	struct iovec iov[4];
	iov[0] = (struct iovec){ .iov_base = plat_buf,
				 .iov_len = LOGSERVER_MAX_HEADER_LEN };
	iov[1] = (struct iovec){ .iov_base = src_buf,
				 .iov_len = LOGSERVER_MAX_HEADER_LEN };
	iov[2] =
		(struct iovec){ .iov_base = &loglevel, .iov_len = sizeof(int) };
	iov[3] = (struct iovec){ .iov_base = &type, .iov_len = sizeof(int) };

	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} ctrl;

	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = iov,
		.msg_iovlen = 4,
		.msg_control = ctrl.buf,
		.msg_controllen = sizeof(ctrl.buf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	int sockfd = logserver_open_client_socket(LOGFD_FNAME);

	int r = sendmsg(sockfd, &msg, 0);

	return r;
}

int pv_logserver_subscribe_fd(int fd, const char *platform, const char *src,
			      int loglevel)
{
	return logserver_send_subs_msg(1, fd, platform, src, loglevel);
}

int pv_logserver_unsubscribe_fd(const char *platform, const char *src)
{
	return logserver_send_subs_msg(0, -1, platform, src, 0);
}
