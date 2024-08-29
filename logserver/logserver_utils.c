/*
 * Copyright (c) 2023 Pantacor Ltd.
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

#include "logserver_utils.h"
#include "logserver_timestamp.h"
#include "config.h"
#include "utils/fs.h"
#include "utils/pvnanoid.h"
#include "log.h"
#include "utils/json.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <glob.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <libgen.h>

static int get_data_line(const struct logserver_data *data,
			 struct logserver_data *line, int sep)
{
	char *end = data->buf + data->len;
	char *buf = !line->buf ? data->buf : line->buf + line->len;
	char *ptr = *buf == sep && buf != end ? buf + 1 : buf;

	while (ptr != end && *ptr != sep)
		++ptr;

	int count = ptr - buf;

	line->len = ptr == end && count == 0 ? 0 : count;
	line->buf = buf;

	return line->len;
}

static void remove_line_feed(char *str)
{
	char *p = NULL;
	while ((p = strchr(str, '\n')) != NULL)
		*p = '\0';
}

static char *format_dmesg_log(const char *str, int len)
{
	const char *buf = str;
	while (*buf == '\n' || *buf == ' ')
		++buf;

	const char *end = str + len;
	const char *txt = buf;

	while (*txt != ';' && txt != end)
		++txt;

	char *formatted = NULL;
	if (txt == end) {
		int log_len = end - buf + 1;
		formatted = calloc(log_len + 1, sizeof(char));
		if (!formatted)
			return NULL;

		memcpy(formatted, buf, log_len);
		formatted[log_len] = '\0';

		remove_line_feed(formatted);
		return formatted;
	}

	txt++;

	int facility;
	int seq;
	int time;

	sscanf(str, "%d,%d,%d,", &facility, &seq, &time);

	int n = asprintf(&formatted, "[%12f] %.*s", time / 1000000.0,
			 (int)(end - txt), txt);

	remove_line_feed(formatted);
	return formatted;
}

static int compress_log(const char *path)
{
	// TODO: this maybe could be configurable
	const int LOGSERVER_MAXFILES = 3;

	char pattern[PATH_MAX] = { 0 };
	snprintf(pattern, PATH_MAX, "%s.*.gz", path);

	glob_t glist;
	int r = glob(pattern, 0, NULL, &glist);
	if (r != 0 && r != GLOB_NOMATCH)
		return -1;

	// looking for the newest file
	size_t max = 0;
	for (size_t i = 0; i < glist.gl_pathc; ++i) {
		char str[PATH_MAX] = { 0 };
		strncpy(str, glist.gl_pathv[i], PATH_MAX - 1);
		str[strlen(str) - 3] = '\0';
		size_t n = strtoumax(strrchr(str, '.') + 1, NULL, 10);
		if (n > max)
			max = n;
	}
	// next file
	++max;

	// only keep maxfile files
	if ((int)glist.gl_pathc >= LOGSERVER_MAXFILES) {
		char delete_path[PATH_MAX] = { 0 };
		snprintf(delete_path, PATH_MAX, "%s.%zd.gz", path,
			 max - LOGSERVER_MAXFILES);
		pv_fs_path_remove(delete_path, false);
	}

	globfree(&glist);

	char path_gz[PATH_MAX] = { 0 };
	snprintf(path_gz, PATH_MAX, "%s.%zd", path, max);
	pv_fs_file_gzip(path, path_gz);

	return 0;
}

int logserver_utils_open_logfile(const char *path)
{
	if (!path)
		return -1;

	int fd = open(path, O_CREAT | O_SYNC | O_RDWR | O_APPEND, 0644);

	struct stat st;
	if (fstat(fd, &st) != 0)
		return fd;

	if (st.st_size < pv_config_get_int(PV_LOG_MAXSIZE))
		return fd;

	if (compress_log(path) == 0) {
		ftruncate(fd, 0);
		lseek(fd, 0, SEEK_SET);
	}

	return fd;
}

static int print_pvfmt_log(int fd, const struct logserver_log *log,
			   const char *src, const char *ts_fmt, bool lf)
{
	const char *util_src = log->src ? log->src : src;

	char ts[256] = { 0 };
	strncpy(ts, "--", 3);

	char *fmt = NULL;
	if (ts_fmt) {
		logserver_timestamp_get_formated(ts, 256, &log->time, ts_fmt);
		fmt = "[%s] [%s] %" PRId64 " %s\t -- [%s]: %.*s%c";
	} else {
		fmt = "[%s] %" PRId64 " %s\t -- [%s]: %.*s%c";
	}

	bool is_dmesg = !strncmp(util_src, "dmesg", strlen("dmesg"));

	char *txt = NULL;
	size_t txt_len = 0;
	int total_len = 0;
	struct logserver_data line = { 0 };

	while (get_data_line(&log->data, &line, '\n') > 0) {
		if (is_dmesg) {
			txt = format_dmesg_log(line.buf, line.len);
			txt_len = strlen(txt);
		} else {
			txt = line.buf;
			txt_len = line.len;
		}

		if (ts_fmt) {
			total_len +=
				dprintf(fd, fmt, ts, log->plat, log->tsec,
					pv_log_level_name(log->lvl), util_src,
					txt_len, txt, lf ? '\n' : '\0');
		} else {
			total_len +=
				dprintf(fd, fmt, log->plat, log->tsec,
					pv_log_level_name(log->lvl), util_src,
					txt_len, txt, lf ? '\n' : '\0');
		}
		if (is_dmesg && txt)
			free(txt);
	}

	return total_len;
}

int logserver_utils_print_raw(int fd, const struct logserver_log *log)
{
	// this is a continuation of the previous message
	if (log->data.len == 2 && !strncmp(log->data.buf, "\r\n", 2))
		return dprintf(fd, "%.*s", log->data.len, log->data.buf);

	char *ts_fmt = pv_config_get_str(PV_LOG_FILETREE_TIMESTAMP_FORMAT);
	if (!ts_fmt)
		return dprintf(fd, "%.*s", log->data.len, log->data.buf);

	char ts[256] = { 0 };
	if (logserver_timestamp_get_formated(ts, 256, &log->time, ts_fmt) != 0)
		strncpy(ts, "--", 3);

	return dprintf(fd, "[%s] %.*s", ts, log->data.len, log->data.buf);
}

int logserver_utils_stdout(const struct logserver_log *log)
{
	return print_pvfmt_log(
		STDOUT_FILENO, log, "unknown",
		pv_config_get_str(PV_LOG_STDOUT_TIMESTAMP_FORMAT), true);
}

int logserver_utils_print_pvfmt(int fd, const struct logserver_log *log,
				const char *src, bool lf)
{
	return print_pvfmt_log(
		fd, log, src,
		pv_config_get_str(PV_LOG_FILETREE_TIMESTAMP_FORMAT), lf);
}

int logserver_utils_print_json_fmt(int fd, const struct logserver_log *log,
				   struct pv_nanoid *nanoid, const char *eol)
{
	struct logserver_log tmp = *log;
	struct logserver_data line = { 0 };

	bool is_dmesg = !strncmp(log->src, "dmesg", strlen("dmesg"));
	int total_len = 0;

	while (get_data_line(&log->data, &line, '\n') > 0) {
		if (is_dmesg) {
			tmp.data.buf = format_dmesg_log(line.buf, line.len);
			tmp.data.len = strlen(tmp.data.buf);
		} else {
			tmp.data.buf = line.buf;
			tmp.data.len = line.len;
		}

		char *json = logserver_utils_jsonify_log(&tmp, nanoid);

		total_len += pv_fs_file_write_nointr(fd, json, strlen(json));
		if (eol)
			total_len += pv_fs_file_write_nointr(fd, eol, 1);

		free(json);

		if (is_dmesg && tmp.data.buf)
			free(tmp.data.buf);
	}

	return total_len;
}

char *logserver_utils_jsonify_log(const struct logserver_log *log,
				  struct pv_nanoid *nanoid)
{
	struct pv_json_ser js;
	pv_json_ser_init(&js, 512);

	log->data.buf[log->data.len] = '\0';

	char ts[256] = { 0 };

	pv_json_ser_object(&js);
	{
		if (nanoid) {
			char *id = pv_nanoid_id(nanoid);
			pv_json_ser_key(&js, "nanoid");
			pv_json_ser_string(&js, id);
			free(id);
		}

		pv_json_ser_key(&js, "tsec");
		pv_json_ser_number(&js, log->tsec);

		pv_json_ser_key(&js, "tnano");
		pv_json_ser_number(&js, 0);

		if (logserver_timestamp_get_formated(
			    ts, 256, &log->time,
			    pv_config_get_str(
				    PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT)) == 0) {
			pv_json_ser_key(&js, "ts");
			pv_json_ser_string(&js, ts);
		}

		pv_json_ser_key(&js, "plat");
		pv_json_ser_string(&js, log->plat);

		pv_json_ser_key(&js, "lvl");
		pv_json_ser_string(&js, pv_log_level_name(log->lvl));

		pv_json_ser_key(&js, "src");
		pv_json_ser_string(&js, log->src);

		pv_json_ser_key(&js, "msg");
		pv_json_ser_string(&js, log->data.buf);

		pv_json_ser_object_pop(&js);
	}
	return pv_json_ser_str(&js);
}

char *logserver_utils_output_to_str(int out_type)
{
	switch (out_type) {
	case LOG_SERVER_OUTPUT_NULL_SINK:
		return "nullsink";
	case LOG_SERVER_OUTPUT_STDOUT:
		return "stdout";
	case LOG_SERVER_OUTPUT_FILE_TREE:
		return "filetree";
	case LOG_SERVER_OUTPUT_SINGLE_FILE:
		return "singlefile";
	case LOG_SERVER_OUTPUT_UPDATE:
		return "update";
	}

	return "unknown";
}

static int write_option(const char *path, const char *op)
{
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return -2;
	int len = write(fd, op, strlen(op));
	close(fd);

	return len < 0 ? len : 0;
}

int logserver_utils_printk_devmsg_on()
{
	return write_option("/proc/sys/kernel/printk_devkmsg", "on\n");
}

int logserver_utils_ignore_loglevel()
{
	return write_option("/sys/module/printk/parameters/ignore_loglevel",
			    "Y");
}