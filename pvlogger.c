/*
 * Copyright (c) 2018 Pantacor Ltd.
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
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <pthread.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include "cmd.h"


#ifndef MODULE_NAME
#define MODULE_NAME             "pvlogger"
#endif

static const char *module_name = MODULE_NAME;

#include "log.h"

#include "log.h"
#include "logger.h"
#include <limits.h>
#include <sys/inotify.h>
#include "pvctl_utils.h"
#include "pvlogger.h"

#define pv_log(level, msg, args...)\
({\
 	char buffer[128];\
	buffer[0] = CMD_LOG;\
	snprintf(&buffer[1], sizeof(buffer) - 1, "[%s]" msg, module_name, ##args);\
	pvctl_write(buffer, strlen(buffer));\
 })

static char logger_cmd [4096];
static struct log default_log;
static int logger_pos = 0;

static int pvlogger_flush(struct log *log, char *buf, int buflen)
{
	int bytes_written = 0;
	char *const __logger_cmd = &logger_cmd[1];
	logger_cmd[0] = CMD_LOG;

	while (buflen > 0) {
		int avail_buflen = 0;
		char *new_line_at = NULL;
try_again:
		avail_buflen = sizeof(logger_cmd) - logger_pos - 1;

		if (avail_buflen > 0) {
			/*
			 * buf may not have a null byte, or it may have
			 * one at a place > buflen .To make sure
			 * we don't go past the amount actually sent to
			 * us, limit it using buflen for the incoming
			 * buffer.
			 * */
			int written = snprintf(__logger_cmd + logger_pos, avail_buflen,
						"%.*s", buflen, buf);
			if (written > avail_buflen)
				written = avail_buflen;
			bytes_written += written;
			logger_pos += written;
		}
		else {
			pvctl_write(logger_cmd, sizeof(logger_cmd));

			logger_pos = 0;
			goto try_again;
		}
		buflen -= bytes_written;
		buf += bytes_written;
write_again:
		new_line_at = strchr(__logger_cmd, '\n');

		if (new_line_at) {
			ssize_t to_write = new_line_at - __logger_cmd + 1;
			pvctl_write(logger_cmd, to_write + 1);
			if (logger_pos - to_write >= 0) {
				memmove(__logger_cmd, new_line_at + 1, logger_pos - to_write);
				logger_pos -= to_write;
				memset(__logger_cmd + logger_pos, 0, sizeof(logger_cmd) - logger_pos - 1);
				goto write_again;
			} else {
				pv_log(WARN, "BUG on logger_pos =%d, to_write = %zd\n", 
						logger_pos, to_write);
				logger_pos = 0;
			}
		}
	}
	return 0;
}

static int stop_logger = 0;


static int pvlogger_start(struct log *log, int was_init_ok)
{
	pv_log(INFO, "Started pvlogger\n");
	
	if (was_init_ok != LOG_OK) {
		pv_log(WARN, "Waiting for log file\n");
	}
	return was_init_ok;
}

#define INOTIFY_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)

/*
 * There's a window where while we're setting up the watch
 * the file has been created and hence no event will come to us.
 * This function should thus be called in a loop.
 * */
static int wait_for_logfile(const char *logfile)
{
	const char *parent_dir = NULL;
	char *tmp_buf = NULL;
	int fd_dir_notify = -1;
	struct timeval tv;
	int ret = LOG_OK;
	const char *filename = NULL;
	struct inotify_event *inotify_ev = NULL;
	fd_set fdset;
	struct stat stbuf;

	FD_ZERO(&fdset);

	if (!logfile) {
		ret = LOG_NOK;
		goto out;
	}

	if (!stat(logfile, &stbuf)) {
		ret = LOG_OK;
		goto out;
	}

	if (logfile[0] == '/') {
		parent_dir = strrchr(logfile, '/');
		if (!parent_dir) {
			ret = LOG_NOK;
			goto out;
		}
		filename = parent_dir + 1;
	}
	else {
		tmp_buf = (char*)calloc(1, PATH_MAX);
		if (!tmp_buf) {
			ret = LOG_NOK;
			goto out;
		}
		getcwd(tmp_buf, PATH_MAX);
		parent_dir = tmp_buf;
		filename = logfile;
	}

	fd_dir_notify = inotify_init1(IN_NONBLOCK);

	if (fd_dir_notify < 0) {
		ret = LOG_NOK;
		goto out;
	}
	
	if (inotify_add_watch(fd_dir_notify, parent_dir, IN_CREATE) < 0 ) {
		ret = LOG_NOK;
		goto out;
	}

	inotify_ev = (struct inotify_event*)calloc(1, INOTIFY_SIZE);

	if (!inotify_ev) {
		ret = LOG_NOK;
		goto out;
	}
	
	FD_SET(fd_dir_notify, &fdset);

read_again:
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	ret = select(fd_dir_notify + 1, &fdset, NULL, NULL, &tv);
	if (ret < 0) {
		if (errno == EINTR)
			goto read_again;
		else {
			ret = LOG_NOK;
			goto out;
		}
	}
	while (read(fd_dir_notify, inotify_ev, INOTIFY_SIZE) < 0 
			&& errno == EINTR)
		;

	if (!strncmp(inotify_ev->name, filename, strlen(filename)))
		ret = LOG_OK;
	else
		ret = LOG_NOK;

out:
	if (tmp_buf)
		free(tmp_buf);

	if (inotify_ev)
		free(inotify_ev);

	close(fd_dir_notify);
	return ret;
}

int start_pvlogger(const char *logfile, const char *platform)
{
	int ret = -1;
	struct timeval tv = {
		.tv_sec = 2,
		.tv_usec = 0
	};
	char pr_name[16] = {0};
	module_name = strdup(platform);
	snprintf(pr_name, sizeof(pr_name), "pvlogger-%s", module_name);
	prctl(PR_SET_NAME, (unsigned long)pr_name,0,0,0);

init_again:
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	memset(&default_log, 0, sizeof(default_log));
	default_log.do_start_log = pvlogger_start;

	ret = log_init(&default_log, logfile ? logfile : "/var/log/messages");
	while (ret != LOG_OK) {
		pv_log(WARN, "Waiting for logfile for %s\n", module_name);
		ret = wait_for_logfile((logfile ? logfile : "/var/log/messages"));
		if (ret == LOG_OK)
			goto init_again;
	}
	/*
	 * These need to be set after initiliaztion
	 * is over.
	 * log.truncate needs to be set after log_init if
	 * it's required to truncate the backing file.
	 * */
	default_log.tv_notify = &tv;
	default_log.do_flush_log = pvlogger_flush;

	while (!stop_logger) {
		if (log_flush_pv(&default_log) < 0) {
			pv_log(WARN, "Stopping log for platform %s\n", module_name);
			log_stop(&default_log);
			goto init_again;
		}
		tv.tv_sec = 2;
		tv.tv_usec = 0;
	}
	pv_log(WARN, "Exiting, pv_logger for platform %s\n", module_name);
	return 0;
}
