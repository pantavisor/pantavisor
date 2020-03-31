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
#include "pantavisor.h"
#include "parser/cmd_json_log.h"

static char logger_cmd [4096];
static struct log default_log;
static int logger_pos = 0;
struct pv_log_info *pv_log_info = NULL;


#define pv_log(level, msg, args...)\
({\
 	char buffer[256];\
	buffer[0] = CMD_JSON;\
	snprintf(&buffer[1], sizeof(buffer) - 1,\
		"{\"op\":\"%s\",\"payload\":"\
		CMD_JSON_FMT(msg)"}", \
		string_cmd_operation(CMD_JSON_LOG),\
		module_name,\
		level,\
		##args);\
	if (!pv_log_info->islxc)\
		pvctl_write(buffer, strlen(buffer));\
	else\
		pvctl_write_to_path("/pv/pv-ctrl", buffer, strlen(buffer));\
 })

static int set_logger_xattr(struct log *log)
{
	int log_fd = fileno(log->backing_file);
	int val_len = fgetxattr(log_fd, PV_LOGGER_POS_XATTR, NULL, 0);
	int set_flag = XATTR_REPLACE;
	char place_holder[32];
	int ret = 0;
	off_t pos = ftello(log->backing_file);

	if (pos < 0)
		return ret;

	snprintf(place_holder, sizeof(place_holder), "%" PRId64, pos);

	if (val_len < 0 && errno == ENODATA)
		set_flag = XATTR_CREATE;
	ret = fsetxattr(log_fd, PV_LOGGER_POS_XATTR, place_holder,
				strlen(place_holder), set_flag);
	return ret < 0 ? errno : ret;
}

static int pvlogger_flush(struct log *log, char *buf, int buflen)
{
	int bytes_written = 0;
	int ret = 0;
	char *const __logger_cmd = &logger_cmd[1];
	logger_cmd[0] = CMD_LOG;

	while (buflen > 0) {
		int avail_buflen = 0;
		char *new_line_at = NULL;
		int written = 0;
try_again:
		avail_buflen = sizeof(logger_cmd) - logger_pos - 1;

		if (!avail_buflen) {
			if (pv_log_info->islxc)
				pvctl_write_to_path("/pv/pv-ctrl", logger_cmd, sizeof(logger_cmd));
			else
				pvctl_write(logger_cmd, sizeof(logger_cmd));
			logger_pos = 0;
			goto try_again;
		}
		/*
		 * buf may not have a null byte, or it may have
		 * one at a place > buflen .To make sure
		 * we don't go past the amount actually sent to
		 * us, limit it using buflen for the incoming
		 * buffer.
		 * */
		written = snprintf(__logger_cmd + logger_pos, avail_buflen,
				"%.*s", buflen, buf);
		if (written >= avail_buflen)
			written = avail_buflen;

		logger_pos += written;
		if (written < avail_buflen) {
			/*Account for the NULL byte in buf*/
			buf += 1;    
			buflen -= 1; 
		}
		bytes_written += written;
		buflen -= bytes_written;
		buf += bytes_written;
write_again:
		new_line_at = strchr(__logger_cmd, '\n');

		if (new_line_at) {
			ssize_t to_write = new_line_at - __logger_cmd + 1;
			if (pv_log_info->islxc)
				pvctl_write_to_path("/pv/pv-ctrl", logger_cmd, to_write + 1);
			else
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
	ret = set_logger_xattr(log);
	if (ret)
		pv_log(DEBUG, "Setting xattr failed, return code is %d \n", ret);
	return 0;
}

static int stop_logger = 0;

static int get_logger_xattr(int log_fd)
{
	int val_len = -1;
	off_t stored_pos = 0;

	val_len = fgetxattr(log_fd, PV_LOGGER_POS_XATTR, NULL, 0);
	if (val_len > 0) {
		char *value = (char*)calloc(1, val_len);
		if (value) {
			val_len = fgetxattr(log_fd, PV_LOGGER_POS_XATTR,
						value, val_len);
			if (val_len > 0)
				sscanf(value, "%" PRId64,&stored_pos);
			free(value);
		}
	} else
		pv_log(DEBUG, "Attribute %s not present\n", PV_LOGGER_POS_XATTR);

	return stored_pos;
}

static int pvlogger_start(struct log *log, int was_init_ok)
{
	int log_file_fd;
	off_t stored_pos = 0;

	if (was_init_ok != LOG_OK) {
		pv_log(WARN, "Waiting for log file\n");
		goto out;
	}

	pv_log(INFO, "Started pvlogger\n");
	log_file_fd = fileno(log->backing_file);
	stored_pos = get_logger_xattr(log_file_fd);
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
		pv_log(WARN, "Memory allocation failed for logfile duplication\n");
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
		pv_log(WARN, "Couldn't allocate memory for inotify event\n");
		ret = LOG_NOK;
		goto out;
	}
	
	FD_SET(fd_dir_notify, &fdset);

read_again:
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	did_wait = true;
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
	pv_log_info = log_info;
	module_name = strdup(platform);
	snprintf(pr_name, sizeof(pr_name), "pvlogger-%s", module_name);
	prctl(PR_SET_NAME, (unsigned long)pr_name,0,0,0);

	if (!pv_log_info) /*We can't even try and log cuz it maybe for lxc.*/
		return 0;
	logfile = pv_log_info->logfile;
init_again:
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	memset(&default_log, 0, sizeof(default_log));
	default_log.do_start_log = pvlogger_start;

	if (logfile && logfile[0] != '/') {
		if (!logfile)
			pv_log(WARN, "Logfile can't be null\n");
		else 
			pv_log(WARN, "Logfile must be an absolute pathname"
					" %s\n", logfile);
		return -1;
	}

	pv_log(INFO, "pvlogger %s has been setup.", module_name);
	ret = log_init(&default_log, logfile ? logfile : "/var/log/messages");
	while (ret != LOG_OK) {
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
	if (pv_log_info->truncate_size)
		default_log.log_limit = pv_log_info->truncate_size;

	while (!stop_logger) {
		if (log_flush_pv(&default_log) < 0) {
			pv_log(WARN, "Stopping pvlogger %s\n", module_name);
			log_stop(&default_log);
			goto init_again;
		}
		tv.tv_sec = 2;
		tv.tv_usec = 0;
	}
	pv_log(WARN, "Exiting, pv_logger %s\n", module_name);
	return 0;
}
