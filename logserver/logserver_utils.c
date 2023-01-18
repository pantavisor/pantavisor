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

#include "logserver_utils.h"
#include "config.h"
#include "utils/fs.h"
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

#define LOGSERVER_JSON_FORMAT                                                  \
	"{\"tsec\":%" PRId64 ", \"tnano\":%" PRId32 ", "                       \
	"\"plat\":\"%s\", \"lvl\":\"%s\", \"src\":\"%s\", "                    \
	"\"msg\": \"%.*s\"}\n"

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

	if (st.st_size < pv_config_get_log_logmax())
		return fd;

	if (compress_log(path) == 0) {
		ftruncate(fd, 0);
		lseek(fd, 0, SEEK_SET);
	}

	return fd;
}

int logserver_utils_print_pvfmt(int fd, const struct logserver_log *log,
				const char *src, bool lf)
{
	const char *util_src = src ? src : log->src;

	char *fmt = NULL;
	if (lf)
		fmt = "[%s] %" PRId64 " %s\t -- [%s]: %.*s\n";
	else
		fmt = "[%s] %" PRId64 " %s\t -- [%s]: %.*s";

	return dprintf(fd, fmt, log->plat, log->tsec,
		       pv_log_level_name(log->lvl), util_src, log->data.len,
		       log->data.buf);
}

char *logserver_utils_jsonify_log(const struct logserver_log *log)
{
	struct logserver_log js = {
		.ver = log->ver,
		.lvl = log->lvl,
		.tsec = log->tsec,
		.plat = pv_json_format(log->plat, strlen(log->plat)),
		.src = pv_json_format(log->src, strlen(log->src)),
		.data.buf = pv_json_format(log->data.buf, log->data.len)
	};

	size_t len = snprintf(NULL, 0, LOGSERVER_JSON_FORMAT, js.tsec, js.tnano,
			      js.plat, pv_log_level_name(js.lvl), js.src,
			      (int)strlen(js.data.buf),
			      js.data.buf) +
		     1; // 0 byte

	char *json = calloc(1, len);
	if (!json)
		return NULL;

	snprintf(json, len, LOGSERVER_JSON_FORMAT, js.tsec, js.tnano, js.plat,
		 pv_log_level_name(js.lvl), js.src, (int)strlen(js.data.buf),
		 js.data.buf);

	free(js.plat);
	free(js.src);
	free(js.data.buf);

	return json;
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
	}

	return "unknown";
}
