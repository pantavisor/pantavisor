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

#include "logsink.h"

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
#include "utils/file.h"
#include "utils/json.h"
#include "pvctl_utils.h"
#include "bootloader.h"

#ifdef DEBUG
#define WARN_ONCE(msg, args...) 	\
do {\
	static bool __warned = false; 	\
	if (! __warned) { 		\
		printf(msg, ##args); 	\
		__warned = true; 	\
	}\
}while(0)
#else
#define WARN_ONCE(msg, args...)

#endif


#include "pantavisor.h"
#include "buffer.h"
#include "paths.h"
#include "config.h"

#include "log.h"

#define PH_LOGGER_MAX_EPOLL_FD 	(50)
#define LOGSINK_FLAG_STOP (1 << 0)
#define LOGSINK_BACKLOG	(20)


#define MODULE_NAME "logsink"

#define LOGSINK_JSON_FORMAT     ",\n{\"tsec\":%"PRId64", \"tnano\":%"PRId32", "\
		"\"plat\":\"%s\", \"lvl\":\"%s\", \"src\":\"%s\", "\
		"\"msg\": \"%.*s\"}"

struct logsink_msg {
	int version;
	int len;
	char buffer[0];
};

struct logsink {
	pid_t service_pid;
	int flags;
	int epoll_fd;
	int sock_fd;
	char *revision;
};

struct logsink_msg_data {
	int version;
	int level;
	/* char pointers point to start address in logsink_msg */
	uint64_t tsec;
	uint32_t tnano;
	char *platform;
	char *source;
	int data_len;
	char *data;
};

static struct logsink logsink_g = {
	.service_pid = -1,
	.flags = 0,
	.epoll_fd = -1,
	.sock_fd = -1,
	.revision = NULL
};

static int logsink_log_msg_data_file_tree(const struct logsink_msg_data *msg_data)
{
	char pathname[PATH_MAX];
	int log_fd = -1;
	int ret = -1;
	char *dup_pathname = NULL;
	char *fname = NULL;
	struct stat st;
	const int MAX_SIZE = 2 * 1024 * 1024;
	bool source_is_pv = !strncmp(msg_data->platform, PV_PLATFORM_STR, strlen(PV_PLATFORM_STR));

	pv_paths_pv_log_file(pathname,
			sizeof (pathname),
			logsink_g.revision,
			msg_data->platform,
			source_is_pv ? "pantavisor.log" : msg_data->source);
	dup_pathname = strdup(pathname);
	fname = dirname(dup_pathname);
	/*
	 * Create directory for logged item according to platform and source.
	 */
	if (mkdir_p(fname, 0755))
		goto error;
	log_fd = open(pathname, O_CREAT | O_SYNC | O_RDWR | O_APPEND, 0644);
	if (log_fd >= 0) {
		if (!fstat(log_fd, &st)) {
			/* Do we need to make a zip out of it?*/
			if (st.st_size >= MAX_SIZE)
				ftruncate(log_fd, 0);
		}
		if (source_is_pv) {
			dprintf(log_fd, "[pantavisor] %"PRIu64" %s\t -- [%s]: %.*s\n",
					msg_data->tsec,
					pv_log_level_name(msg_data->level),
					msg_data->source,
					msg_data->data_len,
					msg_data->data);
		} else {
			dprintf(log_fd, "%.*s\n",
				msg_data->data_len, msg_data->data);
		}
		close(log_fd);
		ret = 0;
	} else {
		WARN_ONCE("Error opening file %s/%s, "
				"errno = %d\n", platform, source, errno);
	}
error:
	free(dup_pathname);
	return ret;
}

static int logsink_log_msg_data_single_file(const struct logsink_msg_data *msg_data)
{
	char pathname[PATH_MAX];
	int ret = -1;
	size_t json_len;
	int log_fd;
	char *json = NULL;
	struct stat st;
	const int MAX_SIZE = 2 * 1024 * 1024;
	struct logsink_msg_data msg_data_json_escaped = {
		.version = msg_data->version,
		.level = msg_data->level,
		.tsec = msg_data->tsec,
		.platform = pv_json_format(msg_data->platform, strlen(msg_data->platform)),
		.source = pv_json_format(msg_data->source, strlen(msg_data->source)),
		.data = pv_json_format(msg_data->data, msg_data->data_len)
	};

	json_len = snprintf(NULL, 0, LOGSINK_JSON_FORMAT,
			msg_data_json_escaped.tsec, msg_data_json_escaped.tnano,
			msg_data_json_escaped.platform,
			pv_log_level_name(msg_data_json_escaped.level),
			msg_data_json_escaped.source,
			(int) strlen(msg_data_json_escaped.data),
			msg_data_json_escaped.data) + 1; // 0 byte

	json = calloc(1, json_len); // 0 byte

	snprintf(json, json_len, LOGSINK_JSON_FORMAT,
			msg_data_json_escaped.tsec, msg_data_json_escaped.tnano,
			msg_data_json_escaped.platform,
			pv_log_level_name(msg_data_json_escaped.level),
			msg_data_json_escaped.source,
			(int) strlen(msg_data_json_escaped.data),
			msg_data_json_escaped.data);

	free(msg_data_json_escaped.platform);
	free(msg_data_json_escaped.source);
	free(msg_data_json_escaped.data);

	pv_paths_pv_log(pathname, sizeof (pathname), logsink_g.revision);
	if (mkdir_p(pathname, 0755))
		goto out;
	pv_paths_pv_log_plat(pathname, sizeof (pathname), logsink_g.revision, "pv.log");
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
				"errno = %d\n", logdri, logsink_g.revision, errno);
	}

out:
	if (json)
		free(json);
	return ret;
}

static int (*logsink_log_msg_data_handlers[LOG_PROTOCOL_SIZE])(const struct logsink_msg_data *) =
{
	[LOG_CONSUMER_FILE_TREE_LOG2] = &logsink_log_msg_data_file_tree,
	[LOG_CONSUMER_SINGLE_FILE_LOG2] = &logsink_log_msg_data_single_file
};

static int logsink_log_msg_data(const struct logsink_msg_data *msg_data)
{
	log_consumer_bm_t consumers = pv_config_get_log_consumers();

	for (int i = 0; i < LOG_CONSUMER_BITMASK_LOG2_SIZE; i++) {
		if ((1 << i) & consumers) {
			logsink_log_msg_data_handlers[i](msg_data);
		}
	}

	return 0;
}

static int pv_log(int level, char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	if (logsink_g.service_pid < 0) {
		__log_to_console(MODULE_NAME, level, msg, args);
	} else if (logsink_g.service_pid == 0) {
		struct buffer *pv_buffer = pv_buffer_get(true);
		char *buf = pv_buffer->buf;
		int buf_len;

		buf_len = vsnprintf(buf, pv_buffer->size, msg, args);

		struct logsink_msg_data data = {
			.version = pv_config_get_log_useprotocol(),
			.level = level,
			.tsec = (uint64_t) time(NULL),
			.platform = PV_PLATFORM_STR,
			.source = "logsink",
			.data = buf,
			.data_len = buf_len
		};

		logsink_log_msg_data(&data);

		pv_buffer_drop(pv_buffer);
	} else {
		pv_logsink_send_vlog(false, PV_PLATFORM_STR, MODULE_NAME, level, msg, args);
	}

	va_end(args);
	return 0;
}

static void sigterm_handler(int signum)
{
	logsink_g.flags = LOGSINK_FLAG_STOP;
}

static void sigchld_handler(int signum)
{
	/*
	 * Reap the child procs.
	 */
	while(waitpid(-1, NULL, WNOHANG) > 0)
		;	
}

static int logsink_msg_parse_data(struct logsink_msg * msg, struct logsink_msg_data *msg_data)
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
		msg_data->source =  msg_data->platform + strlen(msg_data->platform) + 1;
		bytes_read += strlen(msg_data->source) + 1;

		msg_data->data =  msg_data->source + strlen(msg_data->source) + 1;
		msg_data->data_len = msg->len - bytes_read;

		msg_data->tsec = (uint64_t) time(NULL);
		msg_data->tnano = 0;
		ret = 0;
		break;
	default:
		pv_log(WARN, "Got unkown logsink message version %d!", msg_data->version);
		ret = -1;
		break;
	}
	return ret;
}

static int logsink_handle_msg(struct logsink *logsink, struct logsink_msg *msg)
{
	struct logsink_msg_data msg_data;
	int ret;

	ret = logsink_msg_parse_data(msg, &msg_data);
	if (ret != 0) {
		pv_log(WARN, "Logsink message could not be handled!");
		return ret;
	}

	ret = logsink_log_msg_data(&msg_data);
	return ret;
}

static int logsink_read_write(struct logsink *logsink)
{
	struct epoll_event ep_event[LOGSINK_FLAG_STOP];
	int ret = 0;
	int nr_logs = 0;
again:
	ret = epoll_wait(logsink->epoll_fd, ep_event, LOGSINK_FLAG_STOP, -1);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;
		else {
			perror("logsink service: error in epoll_wait: ");
			return -1;
		}
	}
	while(ret > 0) {
		int work_fd;
		/* Only one way comm.*/
		struct sockaddr __unused;
		/* index into event array*/
		ret -= 1;
		work_fd = ep_event[ret].data.fd;

		if (work_fd == logsink->sock_fd) {
			socklen_t sock_size = sizeof(__unused);
			int client_fd = -1;
accept_again:
			client_fd = accept(logsink->sock_fd, &__unused, &sock_size);
			if (client_fd >= 0) {
				/* reuse ep_event to add the new client_fd
				 * to epoll.
				 */
				memset(&ep_event[ret], 0, sizeof(ep_event[ret]));
				ep_event[ret].events = EPOLLIN;
				ep_event[ret].data.fd = client_fd;

				if (epoll_ctl(logsink->epoll_fd, EPOLL_CTL_ADD, client_fd, &ep_event[ret])) {
#ifdef DEBUG
					pv_log(ERROR, "Error adding to epoll %s\n",
							strerror(errno));
#endif
					close(client_fd);/*So client would know*/
				}
			} else if (client_fd < 0 && errno == EINTR)
				goto accept_again;
			else {
#ifdef DEBUG
				pv_log(ERROR, "Error accepting %s\n", strerror(errno));
#endif
			}
		} else {
			/* We've data to read.*/
			struct buffer *log_buffer = NULL;

			log_buffer = pv_buffer_get(true);
			if (log_buffer) {
				int nr_read = 0;
				struct logsink_msg *msg = (struct logsink_msg*)log_buffer->buf;

				nr_read = pv_file_read_nointr(work_fd, log_buffer->buf, log_buffer->size);
				if (nr_read > 0) {
					logsink_handle_msg(logsink, msg);
					nr_logs++;
				}
			}
			ep_event[ret].events = EPOLLIN;
			epoll_ctl(logsink->epoll_fd, EPOLL_CTL_DEL, work_fd,&ep_event[ret]);
			close(work_fd);
			pv_buffer_drop(log_buffer);
		}
	}
	return nr_logs;
}

static int logsink_open_socket(const char *path)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		pv_log(ERROR, "ERROR: unable to open control socket: %d", errno);
		goto out;
	}

	unlink(path);	// sometimes, the socket file still exists after reboot

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr.sun_path)) == -1) {
		pv_log(ERROR, "ERROR: unable to bind control socket: %d\n", errno);
		close(fd);
		fd = -1;
		goto out;
	}

	// queue upto LOGSINK_BACKLOG commands
	if (listen(fd, LOGSINK_BACKLOG) == -1) {
		pv_log(ERROR, "ERROR: unable to listen to control socket: %d\n", errno);
		perror("Listen error!\n");
	}
out:
	return fd;
}

static pid_t logsink_start_service(struct logsink *logsink, const char *revision)
{
	logsink->service_pid = fork();
	if (logsink->service_pid == 0) {
		if (logsink_g.revision)
			free(logsink_g.revision);
		logsink_g.revision = strdup(revision);

		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));

		sa.sa_handler = sigterm_handler;
		sa.sa_flags = SA_RESTART;
		sigaction(SIGTERM, &sa, NULL);

		sa.sa_handler = sigchld_handler;
		sigaction(SIGCHLD, &sa, NULL);

		pv_log(DEBUG, "Starting logsink loop");

		while (!(logsink->flags & LOGSINK_FLAG_STOP)) {
			logsink_read_write(logsink);
		}
		_exit(EXIT_SUCCESS);
	}

	return logsink->service_pid;
}

static void logsink_start(struct logsink *logsink, const char *revision)
{
	if (logsink->service_pid == -1) {
		logsink_start_service(logsink, revision);
		pv_log(DEBUG, "starting log service with pid %d", (int) logsink->service_pid);

		if (logsink->service_pid > 0) {
			pv_log(DEBUG, "started log service with pid %d", (int) logsink->service_pid);
		} else {
			pv_log(ERROR, "unable to start log service");
		}
	}
}

static void logsink_stop()
{
	if (logsink_g.service_pid > 0) {
		pv_log(DEBUG, "Stopping logsink service pid with pid %d", logsink_g.service_pid);
		kill(logsink_g.service_pid, SIGKILL);
	}

	logsink_g.service_pid = -1;
}

void pv_logsink_toggle(struct pantavisor *pv, const char *rev)
{
	if (!pv)
		return;

	if (pv_config_get_log_capture()) {
		logsink_start(&logsink_g, rev);
	} else
		logsink_stop();
}

int pv_logsink_init()
{
	struct epoll_event ep_event;
	char path[PATH_MAX];

	pv_paths_pv_log(path, sizeof (path), LOGCTRL_FNAME);
	logsink_g.sock_fd = logsink_open_socket(path);
	logsink_g.epoll_fd = epoll_create1(0);

	if (logsink_g.epoll_fd < 0 || logsink_g.sock_fd < 0) {
		pv_log(DEBUG, "logsink_g epoll_fd = %d\n",logsink_g.epoll_fd);
		pv_log(DEBUG, "logsink_g sock_fd = %d\n",logsink_g.sock_fd);
		pv_log(DEBUG, "errno  =%d\n", errno);
		goto out;
	}

	ep_event.events = EPOLLIN;
	ep_event.data.fd = logsink_g.sock_fd;
	if (epoll_ctl(logsink_g.epoll_fd, EPOLL_CTL_ADD, ep_event.data.fd, &ep_event))
		goto out;

	logsink_start_service(&logsink_g, pv_bootloader_get_rev());
	pv_log(DEBUG, "started log service with pid %d", (int) logsink_g.service_pid);

	return 0;
out:
	close(logsink_g.sock_fd);
	close(logsink_g.epoll_fd);

	return -1;

}

/**************************
 **** CLIENT INTERFACE ****
 **************************/

static int logsink_msg_fill(struct logsink_msg_data *msg_data, struct logsink_msg *msg)
{
	int avail_len = msg->len;
	ssize_t written = 0;
	int to_copy = 0;
	msg->version = msg_data->version;
	switch (msg->version) {
	case LOG_PROTOCOL_LEGACY:
		//Copy level.
		written += snprintf(msg->buffer + written, avail_len, "%d%c", msg_data->level,'\0');
		avail_len = msg->len - written;

		written += snprintf(msg->buffer + written, avail_len, "%s%c", msg_data->platform,'\0');
		avail_len = msg->len - written;

		written += snprintf(msg->buffer + written, avail_len, "%s%c", msg_data->source,'\0');
		avail_len = msg->len - written;

		to_copy = (msg_data->data_len <= avail_len) ? msg_data->data_len : avail_len;
		if (msg->buffer)
			memcpy(msg->buffer + written, msg_data->data, to_copy);
		msg->len = written + to_copy;

		return to_copy;
	}
	return 0;
}

int pv_logsink_send_vlog(bool is_platform, char *platform, char *src, int level, const char *msg, va_list args)
{
	struct logsink_msg *logsink_msg = NULL;
	int ret;
	char path[PATH_MAX];
	struct buffer *vmsg_buffer = NULL;
	struct buffer *logsink_msg_buffer = NULL;

	struct logsink_msg_data msg_data = {
		.version = LOG_PROTOCOL_LEGACY,
		.level = level,
		.tsec = time(NULL),
		.tnano = 0,
		.platform = platform,
		.source = src,
	};

	if (logsink_g.service_pid <= 0 || level > pv_config_get_log_loglevel())
		return -1;

	vmsg_buffer = pv_buffer_get(true);
	if (!vmsg_buffer) {
		ret = -1;
		goto out_no_buffer;
	}

	logsink_msg_buffer = pv_buffer_get(true);
	if (!logsink_msg_buffer) {
		ret = -1;
		goto out_no_buffer;
	}

	logsink_msg = (struct logsink_msg *) logsink_msg_buffer->buf;
	logsink_msg->len = logsink_msg_buffer->size - sizeof (*logsink_msg);

	msg_data.data = (char *) vmsg_buffer->buf;
	msg_data.data_len = vmsg_buffer->size;

	msg_data.data_len = vsnprintf(msg_data.data, msg_data.data_len, msg, args);

	ret = logsink_msg_fill(&msg_data, logsink_msg);
	pv_paths_pv_log(path, sizeof (path), LOGCTRL_FNAME);
	pvctl_write_to_path(
			is_platform ? PLATFORM_LOG_CTRL_PATH : path,
			(char *) logsink_msg,
			logsink_msg->len + sizeof(*logsink_msg));

out_no_buffer:
	pv_buffer_drop(vmsg_buffer);
	pv_buffer_drop(logsink_msg_buffer);
	return ret;
}

int pv_logsink_send_log(bool is_platform, char *platform, char *src, int level, const char *msg, ...)
{
	va_list args;
	int ret;
	va_start(args, msg);

	ret = pv_logsink_send_vlog(is_platform, platform, src, level, msg, args);

	va_end(args);
	return ret;
}

void pv_logsink_stop(void)
{
	return logsink_stop();
}
