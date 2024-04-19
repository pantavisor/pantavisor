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

#include "logserver_singlefile.h"
#include "logserver_utils.h"
#include "config.h"
#include "paths.h"
#include "utils/fs.h"

#include <string.h>
#include <linux/limits.h>
#include <unistd.h>
#include <libgen.h>
#include <stdio.h>

static char *create_dir(const struct logserver_log *log)
{
	if (!log->running_rev) {
		WARN_ONCE(
			"Log with no revision (null) arrives to singlefile output: %s",
			log->data.buf);
		return NULL;
	}

	char path[PATH_MAX];
	pv_paths_pv_log(path, sizeof(path), log->running_rev);

	if (pv_fs_mkdir_p(path, 0755))
		return NULL;

	pv_paths_pv_log_plat(path, sizeof(path), log->running_rev, "pv.log");

	return strdup(path);
}

static int add_log(struct logserver_out *out, const struct logserver_log *log)
{
	if (log->lvl > pv_config_get_int(CI_LOG_LEVEL))
		return 0;

	char *path = create_dir(log);
	if (!path)
		return -1;

	int fd = logserver_utils_open_logfile(path);
	if (fd < 0) {
		WARN_ONCE("Error opening file %s, errno = %d\n", path, errno);
		free(path);

		return -1;
	}

	char *json = logserver_utils_jsonify_log(log);
	int len = dprintf(fd, "%s\n", json);

	close(fd);
	free(json);
	free(path);

	return len;
}

struct logserver_out *logserver_singlefile_new()
{
	return logserver_out_new(LOG_SERVER_OUTPUT_SINGLE_FILE, "singlefile",
				 add_log, NULL, NULL);
}
