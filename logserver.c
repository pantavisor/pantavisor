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

#include "logserver.h"

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
#include <time.h>

#include "utils/fs.h"
#include "utils/fs.h"
#include "utils/json.h"
#include "utils/system.h"
#include "pvctl_utils.h"
#include "bootloader.h"

#ifdef DEBUG
#define WARN_ONCE(msg, args...)                                                \
	do {                                                                   \
		static bool __warned = false;                                  \
		if (!__warned) {                                               \
			printf(msg, ##args);                                   \
			__warned = true;                                       \
		}                                                              \
	} while (0)
#else
#define WARN_ONCE(msg, args...)

#endif

#include "pantavisor.h"
#include "buffer.h"
#include "paths.h"
#include "config.h"

#include "log.h"

#define PH_LOGGER_MAX_EPOLL_FD (50)
#define LOGSERVER_FLAG_STOP (1 << 0)
#define LOGSERVER_BACKLOG (20)
#define LOGSERVER_MAX_EV (5)

#define LOG_PROTOCOL_LEGACY 0

#define MODULE_NAME "logserver"

#define LOGSERVER_JSON_FORMAT                                                  \
	",\n{\"tsec\":%" PRId64 ", \"tnano\":%" PRId32 ", "                    \
	"\"plat\":\"%s\", \"lvl\":\"%s\", \"src\":\"%s\", "                    \
	"\"msg\": \"%.*s\"}"

struct logserver_msg {
	int version;
	int len;
	char buffer[0];
};

struct logserver_console_log {
	char *name;
	int ttyfd;
	int masterfd;
};

struct logserver {
	pid_t service_pid;
	int flags;
	int epoll_fd;
	int log_sock;
	int fd_sock;
	char *revision;
	struct dl_list console_fd;
};

struct logserver_msg_data {
	int version;
	int level;
	/* char pointers point to start address in logserver_msg */
	uint64_t tsec;
	uint32_t tnano;
	char *platform;
	char *source;
	int data_len;
	char *data;
};

static struct logserver logserver_g = { .service_pid = -1,
					.flags = 0,
					.epoll_fd = -1,
					.log_sock = -1,
					.fd_sock = -1,
					.revision = NULL };

static int
logserver_log_msg_data_file_tree(const struct logserver_msg_data *msg_data)
{
	char pathname[PATH_MAX];
	int log_fd = -1;
	int ret = -1;
	char *dup_pathname = NULL;
	char *fname = NULL;
	struct stat st;
	const int MAX_SIZE = 2 * 1024 * 1024;
	bool source_is_pv = !strncmp(msg_data->platform, PV_PLATFORM_STR,
				     strlen(PV_PLATFORM_STR));

	pv_paths_pv_log_file(pathname, sizeof(pathname), logserver_g.revision,
			     msg_data->platform,
			     source_is_pv ? "pantavisor.log" :
						  msg_data->source);
	dup_pathname = strdup(pathname);
	fname = dirname(dup_pathname);
	/*
	 * Create directory for logged item according to platform and source.
	 */
	if (pv_fs_mkdir_p(fname, 0755))
		goto error;
	log_fd = open(pathname, O_CREAT | O_SYNC | O_RDWR | O_APPEND, 0644);
	if (log_fd >= 0) {
		if (!fstat(log_fd, &st)) {
			/* Do we need to make a zip out of it?*/
			if (st.st_size >= MAX_SIZE)
				ftruncate(log_fd, 0);
		}
		if (source_is_pv) {
			dprintf(log_fd,
				"[pantavisor] %" PRIu64 " %s\t -- [%s]: %.*s\n",
				msg_data->tsec,
				pv_log_level_name(msg_data->level),
				msg_data->source, msg_data->data_len,
				msg_data->data);
		} else {
			dprintf(log_fd, "%.*s\n", msg_data->data_len,
				msg_data->data);
		}
		close(log_fd);
		ret = 0;
	} else {
		WARN_ONCE("Error opening file %s/%s, "
			  "errno = %d\n",
			  platform, source, errno);
	}
error:
	free(dup_pathname);
	return ret;
}

static int
logserver_log_msg_data_single_file(const struct logserver_msg_data *msg_data)
{
	char pathname[PATH_MAX];
	int ret = -1;
	size_t json_len;
	int log_fd;
	char *json = NULL;
	struct stat st;
	const int MAX_SIZE = 2 * 1024 * 1024;
	struct logserver_msg_data msg_data_json_escaped = {
		.version = msg_data->version,
		.level = msg_data->level,
		.tsec = msg_data->tsec,
		.platform = pv_json_format(msg_data->platform,
					   strlen(msg_data->platform)),
		.source = pv_json_format(msg_data->source,
					 strlen(msg_data->source)),
		.data = pv_json_format(msg_data->data, msg_data->data_len)
	};

	json_len = snprintf(NULL, 0, LOGSERVER_JSON_FORMAT,
			    msg_data_json_escaped.tsec,
			    msg_data_json_escaped.tnano,
			    msg_data_json_escaped.platform,
			    pv_log_level_name(msg_data_json_escaped.level),
			    msg_data_json_escaped.source,
			    (int)strlen(msg_data_json_escaped.data),
			    msg_data_json_escaped.data) +
		   1; // 0 byte

	json = calloc(1, json_len); // 0 byte

	snprintf(json, json_len, LOGSERVER_JSON_FORMAT,
		 msg_data_json_escaped.tsec, msg_data_json_escaped.tnano,
		 msg_data_json_escaped.platform,
		 pv_log_level_name(msg_data_json_escaped.level),
		 msg_data_json_escaped.source,
		 (int)strlen(msg_data_json_escaped.data),
		 msg_data_json_escaped.data);

	free(msg_data_json_escaped.platform);
	free(msg_data_json_escaped.source);
	free(msg_data_json_escaped.data);

	pv_paths_pv_log(pathname, sizeof(pathname), logserver_g.revision);
	if (pv_fs_mkdir_p(pathname, 0755))
		goto out;
	pv_paths_pv_log_plat(pathname, sizeof(pathname), logserver_g.revision,
			     "pv.log");
	log_fd = open(pathname, O_CREAT | O_SYNC | O_RDWR | O_APPEND, 0644);
	if (log_fd >= 0) {
		if (!fstat(log_fd, &st)) {
			/* Do we need to make a zip out of it?*/
			if (st.st_size >= MAX_SIZE)
				ftruncate(log_fd, 0);
		}
		dprintf(log_fd, "%s", json);
		close(log_fd);
		ret = 0;
	} else {
		WARN_ONCE("Error opening file %s/%s/pv.log, "
			  "errno = %d\n",
			  logdri, logserver_g.revision, errno);
	}

out:
	if (json)
		free(json);
	return ret;
}

static int logserver_log_msg_data(const struct logserver_msg_data *msg_data)
{
	if (pv_config_get_log_server_output_file_tree())
		logserver_log_msg_data_file_tree(msg_data);

	if (pv_config_get_log_server_output_single_file())
		logserver_log_msg_data_single_file(msg_data);

	return 0;
}

static int pv_log(int level, char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	if (logserver_g.service_pid < 0) {
		__log_to_console(MODULE_NAME, level, msg, args);
	} else if (logserver_g.service_pid == 0) {
		struct buffer *pv_buffer = pv_buffer_get(true);
		char *buf = pv_buffer->buf;
		int buf_len;

		buf_len = vsnprintf(buf, pv_buffer->size, msg, args);

		struct logserver_msg_data data = { .version =
							   LOG_PROTOCOL_LEGACY,
						   .level = level,
						   .tsec = (uint64_t)time(NULL),
						   .platform = PV_PLATFORM_STR,
						   .source = "logserver",
						   .data = buf,
						   .data_len = buf_len };

		logserver_log_msg_data(&data);

		pv_buffer_drop(pv_buffer);
	} else {
		pv_logserver_send_vlog(false, PV_PLATFORM_STR, MODULE_NAME,
				       level, msg, args);
	}

	va_end(args);
	return 0;
}

static void sigterm_handler(int signum)
{
	logserver_g.flags = LOGSERVER_FLAG_STOP;
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
				    struct logserver_msg_data *msg_data)
{
	int bytes_read = 0;
	int ret;
	msg_data->version = msg->version;
	switch (msg_data->version) {
	case LOG_PROTOCOL_LEGACY:
		sscanf(msg->buffer, "%d", &msg_data->level);
		bytes_read += strlen(msg->buffer) + 1;
		//+ 1 to Skip over the NULL byte post level
		msg_data->platform = msg->buffer + strlen(msg->buffer) + 1;
		bytes_read += strlen(msg_data->platform) + 1;
		msg_data->source =
			msg_data->platform + strlen(msg_data->platform) + 1;
		bytes_read += strlen(msg_data->source) + 1;

		msg_data->data =
			msg_data->source + strlen(msg_data->source) + 1;
		msg_data->data_len = msg->len - bytes_read;

		msg_data->tsec = (uint64_t)time(NULL);
		msg_data->tnano = 0;
		ret = 0;
		break;
	default:
		pv_log(WARN, "got unkown logserver message version %d",
		       msg_data->version);
		ret = -1;
		break;
	}
	return ret;
}

static int logserver_handle_msg(struct logserver *logserver,
				struct logserver_msg *msg)
{
	struct logserver_msg_data msg_data;
	int ret;

	ret = logserver_msg_parse_data(msg, &msg_data);
	if (ret != 0) {
		pv_log(WARN, "logserver message could not be handled");
		return ret;
	}

	ret = logserver_log_msg_data(&msg_data);
	return ret;
}

static int logserver_epoll_add(struct epoll_event *ev, int fd)
{
	ev->events = EPOLLIN;
	ev->data.fd = fd;
	errno = 0;
	if (epoll_ctl(logserver_g.epoll_fd, EPOLL_CTL_ADD, fd, ev)) {
		pv_log(ERROR, "could not epoll_ctl: %s", strerror(errno));
		close(fd);
		return -1;
	}

	return 0;
}

static int logserver_accept_connection(struct epoll_event *ev, int socket,
				       int epoll)
{
	struct sockaddr none;
	socklen_t size = sizeof(none);
	int fd = -1;
	errno = 0;

	do {
		fd = accept(socket, &none, &size);
		if (errno != 0 && errno != EINTR) {
			pv_log(ERROR, "could not accept: %s", strerror(errno));
			return -1;
		}
	} while (fd < 0);

	return fd;
}

static void logserver_read_data(struct logserver *logserver,
				struct epoll_event *ev, int fd)
{
	struct buffer *buffer = pv_buffer_get(true);
	if (buffer) {
		struct logserver_msg *msg = (struct logserver_msg *)buffer->buf;
		ssize_t read =
			pv_fs_file_read_nointr(fd, buffer->buf, buffer->size);

		if (read > 0)
			logserver_handle_msg(logserver, msg);
	}
	ev->events = EPOLLIN;
	epoll_ctl(logserver->epoll_fd, EPOLL_CTL_DEL, fd, ev);
	close(fd);
	pv_buffer_drop(buffer);
}

static void logserver_loop(struct logserver *logserver)
{
	struct epoll_event ev[LOGSERVER_MAX_EV];
	int ready = 0;
	errno = 0;
	do {
		ready = epoll_wait(logserver->epoll_fd, ev, LOGSERVER_MAX_EV,
				   -1);

		if (errno != 0 && errno != EINTR) {
			pv_log(ERROR, "error calling epoll_wait: %s",
			       strerror(errno));
			return;
		}
	} while (ready < 0);

	int cur_fd = -1;
	for (int i = 0; i < ready; ++i) {
		cur_fd = ev[i].data.fd;
		if (cur_fd == logserver->log_sock) {
			int fd = logserver_accept_connection(
				&ev[i], logserver->log_sock,
				logserver->epoll_fd);

			memset(ev, 0, sizeof(struct epoll_event));
			logserver_epoll_add(&ev[i], fd);

		} else {
			logserver_read_data(logserver, &ev[i], cur_fd);
		}
	}
}

static int logserver_open_socket(const char *fname)
{
	int fd;
	struct sockaddr_un addr;
	char path[108]; // size of sockaddr_un sun_path
	pv_paths_pv_file(path, PATH_MAX, fname);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		pv_log(ERROR, "unable to open control socket: %d", errno);
		goto out;
	}

	unlink(path); // sometimes, the socket file still exists after reboot

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));

	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr.sun_path)) ==
	    -1) {
		pv_log(ERROR, "unable to bind control socket: %s",
		       strerror(errno));
		close(fd);
		fd = -1;
		goto out;
	}

	// queue upto LOGSERVER_BACKLOG commands
	if (listen(fd, LOGSERVER_BACKLOG) == -1) {
		pv_log(ERROR, "unable to listen to control socket: %d\n",
		       strerror(errno));
	}
out:
	return fd;
}

static pid_t logserver_start_service(struct logserver *logserver,
				     const char *revision)
{
	logserver->service_pid = fork();
	if (logserver->service_pid == 0) {
		if (logserver_g.revision)
			free(logserver_g.revision);
		logserver_g.revision = strdup(revision);

		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));

		sa.sa_handler = sigterm_handler;
		sa.sa_flags = SA_RESTART;
		sigaction(SIGTERM, &sa, NULL);

		sa.sa_handler = sigchld_handler;
		sigaction(SIGCHLD, &sa, NULL);

		pv_log(DEBUG, "starting logserver loop");

		while (!(logserver->flags & LOGSERVER_FLAG_STOP)) {
			logserver_loop(logserver);
		}
		_exit(EXIT_SUCCESS);
	}

	return logserver->service_pid;
}

static void logserver_start(struct logserver *logserver, const char *revision)
{
	if (logserver->service_pid == -1) {
		logserver_start_service(logserver, revision);
		pv_log(DEBUG, "starting log service with pid %d",
		       (int)logserver->service_pid);

		if (logserver->service_pid > 0) {
			pv_log(DEBUG, "started log service with pid %d",
			       (int)logserver->service_pid);
		} else {
			pv_log(ERROR, "unable to start log service");
		}
	}
}

static void logserver_stop()
{
	pv_log(DEBUG, "stopping logserver service...");

	if (logserver_g.service_pid > 0) {
		pv_system_kill_lenient(logserver_g.service_pid);
		pv_system_kill_force(logserver_g.service_pid);
		pv_log(DEBUG, "stopped logserver service with pid %d",
		       logserver_g.service_pid);
	}

	logserver_g.service_pid = -1;
}

void pv_logserver_toggle(struct pantavisor *pv, const char *rev)
{
	if (!pv)
		return;

	if (pv_config_get_log_capture()) {
		logserver_start(&logserver_g, rev);
	} else
		logserver_stop();
}

int pv_logserver_init()
{
	struct epoll_event ev[2];
	logserver_g.log_sock = logserver_open_socket(LOGCTRL_FNAME);
	logserver_g.fd_sock = logserver_open_socket(LOGFD_FNAME);
	logserver_g.epoll_fd = epoll_create1(0);

	if (logserver_g.epoll_fd < 0 || logserver_g.log_sock < 0) {
		pv_log(DEBUG, "logserver_g epoll_fd = %d",
		       logserver_g.epoll_fd);
		pv_log(DEBUG, "logserver_g log sock = %d",
		       logserver_g.log_sock);
		pv_log(DEBUG, "logserver_g fd sock = %d", logserver_g.fd_sock);
		pv_log(DEBUG, "errno  =%d", errno);
		goto out;
	}

	if (logserver_epoll_add(&ev[0], logserver_g.log_sock) == -1)
		goto out;
	if (logserver_epoll_add(&ev[1], logserver_g.fd_sock) == -1)
		goto out;

	logserver_start_service(&logserver_g, pv_bootloader_get_rev());
	pv_log(DEBUG, "started log service with pid %d",
	       (int)logserver_g.service_pid);

	dl_list_init(&logserver_g.console_fd);

	return 0;
out:
	close(logserver_g.log_sock);
	close(logserver_g.epoll_fd);

	return -1;
}

static int logserver_msg_fill(struct logserver_msg_data *msg_data,
			      struct logserver_msg *msg)
{
	int avail_len = msg->len;
	ssize_t written = 0;
	int to_copy = 0;
	msg->version = msg_data->version;
	switch (msg->version) {
	case LOG_PROTOCOL_LEGACY:
		//Copy level.
		written += snprintf(msg->buffer + written, avail_len, "%d%c",
				    msg_data->level, '\0');
		avail_len = msg->len - written;

		written += snprintf(msg->buffer + written, avail_len, "%s%c",
				    msg_data->platform, '\0');
		avail_len = msg->len - written;

		written += snprintf(msg->buffer + written, avail_len, "%s%c",
				    msg_data->source, '\0');
		avail_len = msg->len - written;

		to_copy = (msg_data->data_len <= avail_len) ?
					msg_data->data_len :
					avail_len;
		if (msg->buffer)
			memcpy(msg->buffer + written, msg_data->data, to_copy);
		msg->len = written + to_copy;

		return to_copy;
	}
	return 0;
}

int pv_logserver_send_vlog(bool is_platform, char *platform, char *src,
			   int level, const char *msg, va_list args)
{
	struct logserver_msg *logserver_msg = NULL;
	int ret;
	char path[PATH_MAX];
	struct buffer *vmsg_buffer = NULL;
	struct buffer *logserver_msg_buffer = NULL;

	struct logserver_msg_data msg_data = {
		.version = LOG_PROTOCOL_LEGACY,
		.level = level,
		.tsec = time(NULL),
		.tnano = 0,
		.platform = platform,
		.source = src,
	};

	if (logserver_g.service_pid <= 0 ||
	    level > pv_config_get_log_loglevel())
		return -1;

	vmsg_buffer = pv_buffer_get(true);
	if (!vmsg_buffer) {
		ret = -1;
		goto out_no_buffer;
	}

	logserver_msg_buffer = pv_buffer_get(true);
	if (!logserver_msg_buffer) {
		ret = -1;
		goto out_no_buffer;
	}

	logserver_msg = (struct logserver_msg *)logserver_msg_buffer->buf;
	logserver_msg->len =
		logserver_msg_buffer->size - sizeof(*logserver_msg);

	msg_data.data = (char *)vmsg_buffer->buf;
	msg_data.data_len = vmsg_buffer->size;

	msg_data.data_len =
		vsnprintf(msg_data.data, msg_data.data_len, msg, args);

	ret = logserver_msg_fill(&msg_data, logserver_msg);
	pv_paths_pv_file(path, PATH_MAX, LOGCTRL_FNAME);
	pvctl_write_to_path(is_platform ? PLATFORM_LOG_CTRL_PATH : path,
			    (char *)logserver_msg,
			    logserver_msg->len + sizeof(*logserver_msg));

out_no_buffer:
	pv_buffer_drop(vmsg_buffer);
	pv_buffer_drop(logserver_msg_buffer);
	return ret;
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

void pv_logserver_stop(void)
{
	return logserver_stop();
}

void pv_logserver_close()
{
	char path[PATH_MAX];

	if (logserver_g.log_sock >= 0) {
		pv_paths_pv_file(path, PATH_MAX, LOGCTRL_FNAME);
		pv_log(DEBUG, "closing %s with fd %d", path,
		       logserver_g.log_sock);
		close(logserver_g.log_sock);
		unlink(path);
	}
}

void pv_logserver_send_fd(int fd)
{
	return;
}
