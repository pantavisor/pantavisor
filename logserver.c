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
#include <inttypes.h>
#include <glob.h>

#include "utils/fs.h"
#include "utils/fs.h"
#include "utils/json.h"
#include "utils/system.h"
#include "pvctl_utils.h"
#include "bootloader.h"
#include "config.h"

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
#define LOGSERVER_MAX_HEADER_LEN (50)

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

struct logserver_fd {
	char *platform;
	char *src;
	int fd;
	struct dl_list list;
};

struct logserver_output {
	bool sfile;
	bool ftree;
};

struct logserver_log {
	int maxsize;
	int maxfile;
};

struct logserver {
	pid_t pid;
	int flags;
	int epfd;
	int logsock;
	int fdsock;
	char *revision;
	struct logserver_log log;
	struct logserver_output out;
	// logserver_fd
	struct dl_list fdlst;
	// tmp store for fd returned by connect
	// only if was sent to the fd_sock
	struct dl_list tmplst;
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

static struct logserver logserver_g = { .pid = -1,
					.flags = 0,
					.epfd = -1,
					.logsock = -1,
					.fdsock = -1,
					.log = { .maxsize = -1, .maxfile = 3 },
					.out = { .sfile = false,
						 .ftree = true },
					.revision = NULL };

static int
logserver_log_msg_data_null(const struct logserver_msg_data *msg_data)
{
	return 0;
}

static int logserver_openlog(const char *path)
{
	int fd = open(path, O_CREAT | O_SYNC | O_RDWR | O_APPEND, 0644);

	struct stat st;
	if (fstat(fd, &st) != 0)
		return fd;

	if (st.st_size < logserver_g.log.maxsize)
		return fd;

	char pattern[PATH_MAX] = { 0 };
	snprintf(pattern, PATH_MAX, "%s.*.gz", path);

	glob_t glist;
	int r = glob(pattern, 0, NULL, &glist);
	if (r != 0 && r != GLOB_NOMATCH)
		return fd;

	// looking for the newest file
	size_t max = 0;
	for (size_t i = 0; i < glist.gl_pathc; ++i) {
		char str[PATH_MAX] = { 0 };
		strcpy(str, glist.gl_pathv[i]);
		str[strlen(str) - 3] = '\0';
		size_t n = strtoumax(strrchr(str, '.') + 1, NULL, 10);
		if (n > max)
			max = n;
	}
	// next file
	++max;

	// only keep maxfile files
	if ((int)glist.gl_pathc >= logserver_g.log.maxfile) {
		char delete_path[PATH_MAX] = { 0 };
		snprintf(delete_path, PATH_MAX, "%s.%zd.gz", path,
			 max - logserver_g.log.maxfile);
		pv_fs_path_remove(delete_path, false);
	}

	globfree(&glist);

	char path_gz[PATH_MAX] = { 0 };
	snprintf(path_gz, PATH_MAX, "%s.%zd", path, max);
	pv_fs_file_gzip(path, path_gz);

	ftruncate(fd, 0);
	lseek(fd, 0, SEEK_SET);

	return fd;
}

static int
logserver_log_msg_data_file_tree(const struct logserver_msg_data *msg_data)
{
	char pathname[PATH_MAX];
	int log_fd = -1;
	int ret = -1;
	char *dup_pathname = NULL;
	char *fname = NULL;
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

	log_fd = logserver_openlog(pathname);
	if (log_fd >= 0) {
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

	log_fd = logserver_openlog(pathname);
	if (log_fd >= 0) {
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
	if (logserver_g.out.ftree)
		logserver_log_msg_data_file_tree(msg_data);

	if (logserver_g.out.sfile)
		logserver_log_msg_data_single_file(msg_data);

	return 0;
}

static int pv_log(int level, char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	if (logserver_g.pid < 0) {
		__log_to_console(MODULE_NAME, level, msg, args);
	} else if (logserver_g.pid == 0) {
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

static void sigusr1_handler(int signum)
{
	pv_log(DEBUG, "signal handler to reload revision before %s",
	       logserver_g.revision ? logserver_g.revision : "NULL");

	if (pv_bootloader_reload_pv_try()) {
		pv_log(ERROR,
		       "failed to reread revision after no reboot transition; continuing to log to previous revision");
		return;
	}

	char *sav = logserver_g.revision;
	if (pv_bootloader_get_try())
		logserver_g.revision = strdup(pv_bootloader_get_try());
	if (sav)
		free(sav);

	pv_log(DEBUG, "signal handler to reload revision after %s",
	       logserver_g.revision);
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

static int logserver_handle_msg(struct logserver_msg *msg)
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

static int logserver_epoll_command(int fd, int cmd)
{
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	errno = 0;
	return epoll_ctl(logserver_g.epfd, cmd, fd, &ev);
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

static struct logserver_fd *logserver_fd_new(char *platform, char *src, int fd)
{
	struct logserver_fd *lfd = calloc(1, sizeof(struct logserver_fd));
	if (!lfd)
		return NULL;

	if (platform)
		lfd->platform = strdup(platform);
	if (src)
		lfd->src = strdup(src);
	lfd->fd = fd;
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
	struct logserver_fd *it, *tmp;

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

	struct iovec iov[2];
	iov[0] = (struct iovec){ .iov_base = platform,
				 .iov_len = LOGSERVER_MAX_HEADER_LEN };
	iov[1] = (struct iovec){ .iov_base = src,
				 .iov_len = LOGSERVER_MAX_HEADER_LEN };

	struct msghdr msg = { .msg_name = NULL,
			      .msg_namelen = 0,
			      .msg_iov = iov,
			      .msg_iovlen = 2,
			      .msg_control = ctrl.buf,
			      .msg_controllen = sizeof(ctrl.buf) };

	errno = 0;
	if (recvmsg(sockfd, &msg, 0) < 0) {
		pv_log(ERROR, "error receiving fd: %s", strerror(errno));
		return NULL;
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		pv_log(ERROR, "error receiving fd, NULL structure\n");
		return NULL;
	}

	int fd;
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));

	return logserver_fd_new(platform, src, fd);
}

static int logserver_epoll_wait(struct epoll_event *ev)
{
	int ready = 0;
	errno = 0;
	do {
		ready = epoll_wait(logserver_g.epfd, ev, LOGSERVER_MAX_EV, -1);

		if (errno != 0 && errno != EINTR) {
			pv_log(ERROR, "error calling epoll_wait: %s",
			       strerror(errno));
			return 0;
		}
	} while (ready < 0);

	return ready;
}

static void logserver_consume_log_data(int fd)
{
	struct buffer *buffer = pv_buffer_get(true);

	if (!buffer)
		return;

	if (pv_fs_file_read_nointr(fd, buffer->buf, buffer->size) > 0) {
		struct logserver_msg *msg = (struct logserver_msg *)buffer->buf;
		logserver_handle_msg(msg);
	}

	pv_buffer_drop(buffer);
}

static void logserver_consume_fd(int fd)
{
	struct buffer *buffer = pv_buffer_get(true);
	ssize_t size = 0;
	if (!buffer)
		return;

	size = pv_fs_file_read_nointr(fd, buffer->buf, buffer->size);
	if (size > 0) {
		struct logserver_fd *lfd =
			logserver_fetch_fd_from_list(&logserver_g.fdlst, fd);

		struct logserver_msg_data d = { .version = LOG_PROTOCOL_LEGACY,
						.level = DEBUG,
						.tsec = (uint64_t)time(NULL),
						.platform = lfd->platform,
						.source = lfd->src,
						.data = buffer->buf,
						.data_len = size };
		logserver_log_msg_data(&d);
	}
	pv_buffer_drop(buffer);
}

static int logserver_process_fd(int curfd)
{
	int ret = 0;
	struct logserver_fd *lfd = NULL;

	logserver_list_del(&logserver_g.tmplst, curfd, NULL);
	logserver_epoll_del(curfd);

	lfd = logserver_get_fd(curfd);

	if (!lfd) {
		ret = -1;
		goto clean_all;
	}

	// unsubscribe the platform
	if (lfd->fd < 0) {
		logserver_list_del(&logserver_g.fdlst, 0, lfd->platform);
		pv_log(INFO, "fd (%d) for platform %s:%s unsubscribed", lfd->fd,
		       lfd->platform, lfd->src);
		ret = 0;
		goto clean_all;
	}

	// subcribe new fd
	if (logserver_list_add(&logserver_g.fdlst, lfd) != 0) {
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
	if (lfd)
		logserver_fd_free(lfd);

	if (ret != 0)
		pv_log(DEBUG, "couldn't subscribe fd (%d) for %s:%s", lfd->fd,
		       lfd->platform, lfd->src);

	return ret;
}

static void logserver_loop()
{
	struct epoll_event ev[LOGSERVER_MAX_EV];
	int n_events = logserver_epoll_wait(ev);

	if (n_events < 1) {
		return;
	}

	int logsock = logserver_g.logsock;
	int fdsock = logserver_g.fdsock;
	struct dl_list *tmplst = &logserver_g.tmplst;
	struct dl_list *fdlst = &logserver_g.fdlst;

	int curfd = -1;
	for (int i = 0; i < n_events; ++i) {
		curfd = ev[i].data.fd;
		if (curfd == logsock || curfd == fdsock) {
			int fd = logserver_accept_connection(curfd);
			if (fd < 0) {
				continue;
			}

			if (logserver_epoll_add(fd) != 0) {
				close(fd);
				continue;
			}

			if (curfd == fdsock) {
				struct logserver_fd *lfd =
					logserver_fd_new(NULL, NULL, fd);

				if (logserver_list_add(tmplst, lfd) != 0) {
					logserver_fd_free(lfd);
					logserver_epoll_del(fd);
					close(fd);
				}
			}
		} else if (logserver_list_exists(tmplst, curfd)) {
			logserver_process_fd(curfd);
			close(curfd);
		} else {
			bool sub = logserver_list_exists(fdlst, curfd);

			if (!sub) {
				logserver_consume_log_data(curfd);
				logserver_epoll_del(curfd);
				close(curfd);
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
		pv_log(ERROR, "unable to listen to control socket: %d\n",
		       strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static pid_t logserver_start_service(const char *revision)
{
	logserver_g.pid = fork();
	if (logserver_g.pid == 0) {
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

		sa.sa_handler = sigusr1_handler;
		sigaction(SIGUSR1, &sa, NULL);

		pv_log(DEBUG, "starting logserver loop");

		while (!(logserver_g.flags & LOGSERVER_FLAG_STOP)) {
			logserver_loop();
		}
		_exit(EXIT_SUCCESS);
	}

	return logserver_g.pid;
}

static void logserver_start(const char *revision)
{
	if (logserver_g.pid == -1) {
		logserver_start_service(revision);
		pv_log(DEBUG, "starting log service with pid %d",
		       (int)logserver_g.pid);

		if (logserver_g.pid > 0) {
			pv_log(DEBUG, "started log service with pid %d",
			       (int)logserver_g.pid);
		} else {
			pv_log(ERROR, "unable to start log service");
		}
	}
}

static void logserver_stop()
{
	pv_log(DEBUG, "stopping logserver service...");

	if (logserver_g.pid > 0) {
		pv_system_kill_lenient(logserver_g.pid);
		pv_system_kill_force(logserver_g.pid);
		pv_log(DEBUG, "stopped logserver service with pid %d",
		       logserver_g.pid);
	}

	logserver_g.pid = -1;
}

// XXX: this is bad code now. stop must never happen here; we
// should kill this function and do the starting directly in the main
// lifecycle code that currently calls this; disabling log capture
// should happen through a "nullsink".
void pv_logserver_toggle(struct pantavisor *pv, const char *rev)
{
	if (!pv)
		return;

	// only start if we have log_capture configured
	if (pv_config_get_log_capture()) {
		logserver_start(rev);
	}
}

int pv_logserver_init()
{
	logserver_g.log.maxsize = pv_config_get_log_logmax();

	if (pv_config_get_log_capture()) {
		logserver_g.out.sfile =
			pv_config_get_log_server_output_single_file();
		logserver_g.out.ftree =
			pv_config_get_log_server_output_file_tree();
	} else {
		logserver_g.out.sfile = false;
		logserver_g.out.ftree = false;
	}

	errno = 0;
	logserver_g.epfd = epoll_create1(0);

	if (logserver_g.epfd < 0) {
		pv_log(ERROR, "could not create logserver_g epoll fd");
		return -1;
	}

	logserver_g.logsock = logserver_open_server_socket(LOGCTRL_FNAME);
	if (logserver_g.logsock < 0)
		pv_log(WARN,
		       "could not initialize log socket, logs will not be captured");

	logserver_g.fdsock = logserver_open_server_socket(LOGFD_FNAME);
	if (logserver_g.fdsock)
		pv_log(WARN,
		       "could not open fd socket, some containers logs will be lost");

	if (logserver_epoll_add(logserver_g.logsock) == -1) {
		pv_log(WARN,
		       "could not init log socket, logs will not be captured");
		goto out;
	}

	if (logserver_epoll_add(logserver_g.fdsock) == -1) {
		pv_log(WARN,
		       "could not init fd socket, some containers logs will be lost");
		goto out;
	}

	dl_list_init(&logserver_g.fdlst);
	dl_list_init(&logserver_g.tmplst);
	logserver_start_service(pv_bootloader_get_rev());
	pv_log(DEBUG, "started log service with pid %d", (int)logserver_g.pid);

	return 0;
out:
	if (logserver_g.logsock >= 0)
		close(logserver_g.logsock);
	if (logserver_g.fdsock >= 0)
		close(logserver_g.fdsock);
	if (logserver_g.epfd >= 0)
		close(logserver_g.epfd);

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

	if (logserver_g.pid <= 0 || level > pv_config_get_log_loglevel())
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

void pv_logserver_reload(void)
{
	if (logserver_g.pid >= 0)
		kill(logserver_g.pid, SIGUSR1);
}

void pv_logserver_stop(void)
{
	return logserver_stop();
}

static void logserver_close(int sockd, const char *name)
{
	if (sockd < 0)
		return;

	char path[PATH_MAX];
	pv_paths_pv_file(path, PATH_MAX, name);
	pv_log(DEBUG, "closing %s with fd %d\n", path, sockd);
	close(sockd);
	unlink(path);
}

void pv_logserver_close()
{
	if (logserver_g.logsock >= 0)
		logserver_close(logserver_g.logsock, LOGCTRL_FNAME);
	if (logserver_g.fdsock >= 0)
		logserver_close(logserver_g.fdsock, LOGFD_FNAME);
}

int pv_logserver_subscribe_fd(int fd, const char *platform, const char *src)
{
	char plat_buf[LOGSERVER_MAX_HEADER_LEN] = { 0 };
	char src_buf[LOGSERVER_MAX_HEADER_LEN] = { 0 };

	strncpy(plat_buf, platform, LOGSERVER_MAX_HEADER_LEN - 1);
	strncpy(src_buf, src, LOGSERVER_MAX_HEADER_LEN - 1);

	struct iovec iov[2];
	iov[0] = (struct iovec){ .iov_base = plat_buf,
				 .iov_len = LOGSERVER_MAX_HEADER_LEN };
	iov[1] = (struct iovec){ .iov_base = src_buf,
				 .iov_len = LOGSERVER_MAX_HEADER_LEN };

	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} ctrl;

	struct msghdr msg = { .msg_name = NULL,
			      .msg_namelen = 0,
			      .msg_iov = iov,
			      .msg_iovlen = 2,
			      .msg_control = ctrl.buf,
			      .msg_controllen = sizeof(ctrl.buf) };

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	int sockfd = logserver_open_client_socket(LOGFD_FNAME);

	int r = sendmsg(sockfd, &msg, 0);

	return r;
}

int pv_logserver_unsubscribe_fd(const char *platform, const char *src)
{
	return pv_logserver_subscribe_fd(-1, platform, src);
}
