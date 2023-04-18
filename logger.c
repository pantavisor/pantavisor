/*
 * Copyright (c) 2019 Pantacor Ltd.
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

#include "logger.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <libgen.h>

#define INOTIFY_SIZE (sizeof(struct inotify_event) + NAME_MAX + 1)

static int log_direct_to_file(struct log *log, int show_perror)
{
	int fd = -1;
	if (strstr("XXXXXX", log->path_backing_file))
		fd = mkstemp(log->path_backing_file);
	else
		fd = open(log->path_backing_file, O_RDONLY);
	if (fd < 0 && show_perror) {
		perror("get_tmp_file failed:");
	}
	return fd;
}

static int log_set_backing_file(struct log *log, const char *path)
{
	int path_len = 0;
	/*
	 * There's no backing store specified for log
	 * and stdout has probably been redirected to
	 * some file not a tty. We need to get that
	 * file path.
	 * */
	if (!path && !isatty(1)) {
		char __temp_path[64];
		sprintf(__temp_path, "/proc/%d/fd/1", getpid());
		if (readlink(__temp_path, log->path_backing_file, PATH_MAX) >=
		    0) {
			goto shrink_path;
		} else
			return LOG_NOK;
	}
	if (!path) {
		snprintf(log->path_backing_file, PATH_MAX,
			 "/tmp/pvlogger_%d_XXXXXX", getpid());
	} else
		snprintf(log->path_backing_file, PATH_MAX, "%s", path);
shrink_path:
	path_len = strlen(log->path_backing_file);
	log->path_backing_file =
		(char *)realloc(log->path_backing_file, path_len + 1);
	return LOG_OK;
}

static int setup_inotify(struct log *log, uint32_t ev_mask)
{
	char tmpname[PATH_MAX] = { 0 };
	const char *dir = NULL;
	snprintf(tmpname, sizeof(tmpname), "%s", log->path_backing_file);
	dir = dirname(tmpname);
	if (!dir || !strcmp(".", dir))
		return LOG_NOK;

	log->notify_fd = inotify_init1(IN_NONBLOCK);
	if (log->notify_fd < 0) {
		perror("inotify_init failed:");
		return LOG_NOK;
	}
	/*
	 * Add the watch on directory containing the file.
	 * */
	ev_mask = ev_mask ? ev_mask : IN_ALL_EVENTS;
	if (inotify_add_watch(log->notify_fd, dir, ev_mask) < 0) {
		perror("inotify_add_watch failed:");
		close(log->notify_fd);
		log->notify_fd = -1;
		return LOG_NOK;
	}
	return LOG_OK;
}

int log_init(struct log *log, const char *backing_file)
{
	int ret = LOG_OK;
	int tmp_fd = -1;
	if (!log) {
		ret = LOG_NOK;
		goto out;
	}
	log->truncate = 0;
	log->path_backing_file = (char *)calloc(1, PATH_MAX);
	if (!log->path_backing_file) {
		ret = LOG_NOK;
		goto out;
	}
	log->tv_notify = NULL; /*Application should reset this after init*/
	log->log_limit = LOG_DEFAULT_LIMIT;

	if (log_set_backing_file(log, backing_file) != LOG_OK) {
		ret = LOG_NOK;
		goto out;
	}
	tmp_fd = log_direct_to_file(log, DEBUG);
	if (tmp_fd < 0) {
		if (DEBUG)
			perror("couldn't initialize log:");
		ret = LOG_NOK;
		goto out;
	}
	/*
	 * Redirect stdout to backing file.
	 * */
	if (dup2(tmp_fd, 1) < 0) {
		if (DEBUG)
			perror("couldn't initialize log, failed dup:");
		ret = LOG_NOK;
		goto out;
	}
	log->backing_file = fdopen(tmp_fd, "r");
	if (!log->backing_file) {
		if (DEBUG)
			perror("couldn't initialize log, fdopen failed:");
		ret = LOG_NOK;
		goto out;
	}
	if (setup_inotify(log, IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM) !=
	    LOG_OK) {
		ret = LOG_NOK;
		goto out;
	}
out:
	if (ret == LOG_NOK) {
		close(tmp_fd);
		if (log && log->has_tmp_backing_file && log->path_backing_file)
			unlink(log->path_backing_file);
	}
	if (log && log->do_start_log) {
		ret = log->do_start_log(log, ret);
	}
	return ret;
}

static int log_read_inotify(struct log *log)
{
	fd_set fdset;
	int ret = 0;
	struct inotify_event *inotify_ev = NULL;
	struct timeval tv;
	char tmpname[PATH_MAX] = { 0 };
	const char *filename = NULL;

	inotify_ev = (struct inotify_event *)calloc(1, INOTIFY_SIZE);
	FD_ZERO(&fdset);
	if (!inotify_ev)
		return LOG_NOK;

	if (log->notify_fd < 0) {
		ret = LOG_NOK;
		goto out;
	}
	FD_SET(log->notify_fd, &fdset);
	if (log->tv_notify)
		memcpy(&tv, log->tv_notify, sizeof(tv));
check_again:
	ret = select(log->notify_fd + 1, &fdset, NULL, NULL,
		     (log->tv_notify ? &tv : NULL));
	if (ret < 0) {
		if (errno == EINTR)
			goto check_again;
		ret = LOG_NOK;
		goto out;
	} else if (ret == 0) {
		ret = LOG_OK;
		goto out;
	}
	while (read(log->notify_fd, (char *)inotify_ev, INOTIFY_SIZE) < 0 &&
	       errno == EINTR)
		;
	ret = LOG_OK;
	snprintf(tmpname, sizeof(tmpname), "%s", log->path_backing_file);
	filename = basename(tmpname);
	if (inotify_ev->mask & (IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM)) {
		if (!strcmp(inotify_ev->name, filename)) {
			ret = LOG_NOK;
			inotify_rm_watch(log->notify_fd, inotify_ev->wd);
		}
	}
out:
	free(inotify_ev);
	return ret;
}

int log_flush_pv(struct log *log)
{
	int ret = 0;
	struct stat st;
	static char buf[sizeof(log->buff)] = { 0 };
	bool file_deleted = false;

	do {
		/*
		 * We can put timestamps and
		 * application marker.
		 * */
		if (!fstat(fileno(log->backing_file), &st)) {
			off_t current_pos = ftello(log->backing_file);
			if (st.st_size < ftello(log->backing_file)) {
				fseek(log->backing_file, 0, SEEK_SET);
			} else
				fseek(log->backing_file, current_pos, SEEK_SET);
		}

		ret = fread(buf, 1, sizeof(log->buff), log->backing_file);

		if (ret && log->do_flush_log)
			log->do_flush_log(log, buf, ret);
		/*
		 * Can we improve this?
		 * */
		if (log->truncate && !fstat(fileno(log->backing_file), &st)) {
			if (st.st_size >= log->log_limit) {
				truncate(log->path_backing_file, 0);
			}
		}
	} while (ret > 0);

	file_deleted = log_read_inotify(log) == LOG_OK ? false : true;
	; /*Nothing to read from backing store*/
	if (file_deleted)
		return LOG_NOK;

	return ret < 0 ? LOG_NOK : LOG_OK;
}

int log_stop(struct log *log)
{
	int ret = LOG_OK;
	if (!log)
		return LOG_NOK;

	fflush(log->backing_file);
	if (log->do_stop_log) {
		ret = log->do_stop_log(log);
	}
	fclose(log->backing_file);
	if (log->has_tmp_backing_file)
		unlink(log->path_backing_file);

	free(log->path_backing_file);
	close(log->notify_fd);
	log->has_tmp_backing_file = 0;
	return ret;
}
