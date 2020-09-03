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
#include <inttypes.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>
#include "cmd.h"
#include <sys/xattr.h>
#include <stdarg.h>


#ifndef MODULE_NAME
#define MODULE_NAME             "pvlogger"
#endif

static const char *module_name = MODULE_NAME;

#include "log.h"
#include "logger.h"
#include <limits.h>
#include <sys/inotify.h>
#include "pvctl_utils.h"
#include "pvlogger.h"
#include "pantavisor.h"
#include "utils.h"
#include "ph_logger/ph_logger.h"

static char *logger_cmd; //Leave some room to create json
static struct log default_log;
struct pv_log_info *pv_log_info = NULL;

#define PV_LOG_BUF_START_OFFSET 	(0)
#define PV_LOG_BUF_SIZE 		(4096)

static int logger_pos = PV_LOG_BUF_START_OFFSET;

static const char* pv_logger_get_logfile(struct pv_log_info *log_info)
{
	return log_info->logfile ? log_info->logfile : "/var/log/messages";
}
/*
 * Make ph_logger_msg.
 * Add 1 to include null in the log message.
 */

static void pv_log(int level, char *msg, ...)
{
	char __buffer[PV_LOG_BUF_SIZE + (PV_LOG_BUF_SIZE / 2 )];
	char __formatted[PV_LOG_BUF_SIZE + (PV_LOG_BUF_SIZE / 2 )];
	int to_write = 0;
	int written = 0;
	int offset = 0;
	va_list args;
	struct ph_logger_msg *ph_logger_msg =
		(struct ph_logger_msg*)__buffer;

	va_start(args, msg);
	vsnprintf(__formatted, sizeof(__formatted), msg, args);
	va_end(args);
	to_write = strlen(__formatted) + 1;

	while(to_write > 0) {
		ph_logger_msg->version = PH_LOGGER_V1;
		ph_logger_msg->len = sizeof(__buffer) - sizeof(struct ph_logger_msg);
		written = ph_logger_write_bytes(ph_logger_msg, __formatted + offset,
				level, pv_log_info->platform->name,
				pv_logger_get_logfile(pv_log_info), to_write);

		if (!pv_log_info->islxc) {
			int ret = pvctl_write(__buffer, 
					ph_logger_msg->len + sizeof(struct ph_logger_msg));
			if (ret < 0) {
				printf("Error in pvctl_write"
						" %d from pvlogger\n", ret);
			} 

		} else {
			int ret = pvctl_write_to_path(LOG_CTRL_PATH, 
					__buffer,
					ph_logger_msg->len + sizeof(struct ph_logger_msg));
			if (ret < 0) {
				printf("Error in pvctl_write_to_path "
						"%d from pvlogger\n", ret);
			}
		}
		offset += written;
		to_write -= written;
		if (!written)
			break;
	}
}

static int set_logger_xattr(struct log *log)
{
	char place_holder[32];
	off_t pos = ftello(log->backing_file);
	const char *fname = pv_logger_get_logfile(pv_log_info);

	if (pos < 0)
		return 0;
	snprintf(place_holder, sizeof(place_holder), "%" PRId64, pos);
	
	return set_xattr_on_file(fname, PV_LOGGER_POS_XATTR, place_holder);
}

static int pvlogger_flush(struct log *log, char *buf, int buflen)
{
	int ret = 0;

	while (buflen > 0) {
		int avail_buflen = PV_LOG_BUF_SIZE - 1 - logger_pos;
		char *new_line_at = NULL;
		int written = 0;
		int to_write = buflen;

		if (avail_buflen == 0) {
			pv_log(INFO, "%.*s", PV_LOG_BUF_SIZE - 1, logger_cmd);
			logger_pos = PV_LOG_BUF_START_OFFSET;
			avail_buflen = PV_LOG_BUF_SIZE - 1;
			memset(logger_cmd + PV_LOG_BUF_START_OFFSET,
					0, PV_LOG_BUF_SIZE - PV_LOG_BUF_START_OFFSET);
		}

		new_line_at = strchr(buf, '\n');
		if (new_line_at)
			to_write = new_line_at - buf;
		else {
			new_line_at = strchr(buf, '\r');
			if (new_line_at)
				to_write = new_line_at - buf;
		}

		if (to_write > avail_buflen) {
			snprintf(logger_cmd + logger_pos, avail_buflen + 1, "%.*s",
							avail_buflen, buf);
			written = avail_buflen;
		} else {
			snprintf(logger_cmd + logger_pos, avail_buflen + 1, "%.*s",
							to_write, buf);
			written = to_write;
		}
		
		buf += written;
		buflen -= written;
		logger_pos += written;

		if (new_line_at) {
			/*move past the new line.*/
			buf += 1;
			/*move past the new line.*/
			buflen -= 1;
			pv_log(INFO, "%s", logger_cmd);
			memset(logger_cmd + PV_LOG_BUF_START_OFFSET, 0, 
					PV_LOG_BUF_SIZE - PV_LOG_BUF_START_OFFSET);
			logger_pos = PV_LOG_BUF_START_OFFSET;
		}
	}
	ret = set_logger_xattr(log);
	if (ret < 0)
		pv_log(DEBUG, "Setting xattr failed, return code is %d ", ret);
	return 0;
}

static int stop_logger = 0;

static int get_logger_xattr(struct log *log)
{
	off_t stored_pos = 0;
	char buf[32];
	char *dst = buf;
	const char *fname = pv_logger_get_logfile(pv_log_info);

	if (get_xattr_on_file(fname, PV_LOGGER_POS_XATTR, &dst, NULL) < 0) {
		pv_log(DEBUG, "Attribute %s not present", PV_LOGGER_POS_XATTR);
	}
	else {
		sscanf(buf, "%" PRId64,&stored_pos);
	}
	return stored_pos;
}

static int pvlogger_start(struct log *log, int was_init_ok)
{
	int log_file_fd = -1;
	off_t stored_pos = 0;
	struct stat st;

	if (was_init_ok != LOG_OK) {
		pv_log(WARN, "Waiting for log file");
		goto out;
	}
	pv_log(INFO, "Started pvlogger\n");
	log_file_fd = fileno(log->backing_file);
	stored_pos = get_logger_xattr(log);
	if (!fstat(log_file_fd, &st)) {
		if (st.st_size < stored_pos)
			stored_pos = 0;
	}
	pv_log(DEBUG, "pvlogger %s seeking to position %" PRId64 "\n",
			module_name, stored_pos);
	fseek(log->backing_file, stored_pos, SEEK_SET);
out:
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
	char *parent_dir = NULL;
	int fd_dir_notify = -1;
	struct timeval tv;
	int ret = LOG_OK;
	const char *filename = NULL;
	struct inotify_event *inotify_ev = NULL;
	fd_set fdset;
	struct stat stbuf;
	char *file_dup = NULL;
	char *dir_dup = NULL;
	bool did_wait = false;

	FD_ZERO(&fdset);

	if (!logfile) {
		ret = LOG_NOK;
		goto out;
	}

	if (!stat(logfile, &stbuf)) {
		ret = LOG_OK;
		goto out;
	}
 	file_dup = strdup(logfile);
	dir_dup = strdup(logfile);

	if (!file_dup || !dir_dup) {
		pv_log(WARN, "Memory allocation failed for logfile duplication");
		ret = LOG_NOK;
		goto out;
	}
	parent_dir = dirname(dir_dup);
	filename = basename(file_dup);

	if ( (!strlen(filename)) || *filename == '/' || *filename == '.') {
		pv_log(WARN, "Configured log file name %s is not correct"
				".\n", logfile);
		ret = LOG_NOK;
		goto out;
	}
	fd_dir_notify = inotify_init1(IN_NONBLOCK);

	if (fd_dir_notify < 0) {
		pv_log(WARN, "Unable to initialize inotfy event watcher."
			"errno = %d (%s)\n", errno, strerror(errno));
		ret = LOG_NOK;
		goto out;
	}
	
	if (inotify_add_watch(fd_dir_notify, parent_dir, IN_CREATE) < 0 ) {
		pv_log(WARN, "Unable to create inotify watch."
			"errno = %d (%s)\n", errno, strerror(errno));
		ret = LOG_NOK;
		goto out;
	}

	inotify_ev = (struct inotify_event*)calloc(1, INOTIFY_SIZE);

	if (!inotify_ev) {
		pv_log(WARN, "Couldn't allocate memory for inotify event");
		ret = LOG_NOK;
		goto out;
	}
	
	FD_SET(fd_dir_notify, &fdset);

read_again:
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	did_wait = true;
	ret = select(fd_dir_notify + 1, &fdset, NULL, NULL, &tv);
	if (ret == 0) {
		goto read_again;
	} else if (ret < 0) {
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
	if (dir_dup)
		free(dir_dup);
	
	if (file_dup)
		free(file_dup);

	if (inotify_ev)
		free(inotify_ev);

	close(fd_dir_notify);
	if (!did_wait)
		sleep(PV_LOGGER_FILE_WAIT_TIMEOUT);
	return ret;
}

int start_pvlogger(struct pv_log_info *log_info, const char *platform)
{
	int ret = -1;
	struct timeval tv = {
		.tv_sec = 2,
		.tv_usec = 0
	};
	char pr_name[16] = {0};
	const char *logfile = NULL;

	logger_cmd = (char*)calloc(1, PV_LOG_BUF_SIZE);

	/*Can't log it only thing we can do is print it on console*/
	if (!logger_cmd)
		return -1;
	
	pv_log_info = log_info;
	module_name = strdup(platform);
	snprintf(pr_name, sizeof(pr_name), "pvlogger-%s", module_name);
	prctl(PR_SET_NAME, (unsigned long)pr_name,0,0,0);

	if (!pv_log_info) /*We can't even try and log cuz it maybe for lxc.*/
		return 0;
	logfile = pv_logger_get_logfile(pv_log_info);
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	memset(&default_log, 0, sizeof(default_log));
	default_log.do_start_log = pvlogger_start;

	if (logfile && logfile[0] != '/') {
		pv_log(WARN, "Logfile must be an absolute pathname"
				" %s\n", logfile);
		return -1;
	}

init_again:
	pv_log(INFO, "pvlogger %s has been setup.", module_name);
	ret = log_init(&default_log, pv_logger_get_logfile(pv_log_info));
	while (ret != LOG_OK) {
		ret = wait_for_logfile(pv_logger_get_logfile(pv_log_info));
		if (ret == LOG_OK)
			goto init_again;
	}
	/*
	 * These need to be set after initiliaztion
	 * is over.
	 * log.truncate needs to be set after log_init if
	 * it's required to truncate the backing file.
	 */
	default_log.tv_notify = &tv;
	default_log.do_flush_log = pvlogger_flush;
	if (pv_log_info->truncate_size)
		default_log.log_limit = pv_log_info->truncate_size;

	while (!stop_logger) {
		if (log_flush_pv(&default_log) < 0) {
			pv_log(WARN, "Stopping pvlogger %s", module_name);
			log_stop(&default_log);
			goto init_again;
		}
		tv.tv_sec = 2;
		tv.tv_usec = 0;
	}
	pv_log(WARN, "Exiting, pv_logger %s", module_name);
	return 0;
}
