/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#include "logserver_phlogger.h"
#include "logserver_utils.h"
#include "config.h"
#include "utils/pvnanoid.h"

#include "utils/fs.h"
#include "paths.h"
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

const char *eol = NULL;

static int create_dir(const struct logserver_log *log, char *path)
{
	if (!log->running_rev) {
		WARN_ONCE(
			"Log with no revision (null) arrives to singlefile output: %s",
			log->data.buf);
		return -1;
	}

	pv_paths_pv_log(path, PATH_MAX, log->running_rev);
	pv_fs_mkdir_p(path, 0755);

	pv_paths_pv_log_plat(path, PATH_MAX, log->running_rev,
			     pv_config_get_str(PH_LOG_TMP_FILE));
	return 0;
}

static int open_socket(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	struct sockaddr_un addr = { 0 };
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
		return fd;

	close(fd);
	return -1;
}

static int get_fd(struct logserver_out *out, const struct logserver_log *log)
{
	char path[PATH_MAX] = { 0 };
	pv_paths_pv_file(path, PATH_MAX, LOGPUSH_FNAME);

	if (pv_fs_path_exist(path)) {
		int fd = open_socket(path);
		if (fd > 0) {
			eol = NULL;
			return fd;
		}
		close(fd);
	}

	memset(path, 0, PATH_MAX);

	if (create_dir(log, path) != 0) {
		WARN_ONCE("error cannot get a valid path");
		return -1;
	}

	eol = "\n";
	int fd = logserver_utils_open_logfile(path);
	if (fd < 0) {
		return -1;
	}

	return fd;
}

static int add_log(struct logserver_out *out, const struct logserver_log *log)
{
	errno = 0;
	int fd = get_fd(out, log);
	if (fd < 0) {
		return 0;
	}

	struct pv_nanoid *nid = (struct pv_nanoid *)out->opaque;
	int written = logserver_utils_print_json_fmt(fd, log, nid, eol);
	close(fd);

	return written;
}

static void free_phlogger_out(struct logserver_out *out)
{
	free((struct pv_nanoid *)out->opaque);
}

struct logserver_out *logserver_phlogger_new()
{
	struct pv_nanoid *nanoid = calloc(1, sizeof(struct pv_nanoid));
	if (!nanoid)
		return NULL;

	return logserver_out_new(LOG_SERVER_OUTPUT_PHLOGGER, "phlogger",
				 add_log, NULL, nanoid);
}