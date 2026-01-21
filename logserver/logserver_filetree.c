/*
 * Copyright (c) 2023-2024 Pantacor Ltd.
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

#include "logserver_filetree.h"
#include "logserver_utils.h"
#include "config.h"
#include "paths.h"
#include "utils/fs.h"

#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <libgen.h>

#define MAIN_PLATFORM "pantavisor"

static int create_dir(const struct logserver_log *log, bool is_pv, char *path)
{
	if (!log->running_rev) {
		WARN_ONCE(
			"Log with no revision (null) arrives to filetree output: %s",
			log->data.buf);
		return -1;
	}

	char tmp_path[PATH_MAX] = { 0 };
	pv_paths_pv_log_file(tmp_path, PATH_MAX, log->running_rev, log->plat,
			     is_pv ? "pantavisor.log" : log->src);

	char dir[PATH_MAX] = { 0 };
	pv_fs_dirname(tmp_path, dir);

	// Create directory for logged item according to platform and source.
	if (pv_fs_mkdir_p(dir, 0755) != 0) {
		return -1;
	}

	memset(path, 0, PATH_MAX);
	memccpy(path, tmp_path, 0, PATH_MAX);

	return 0;
}

static int add_log(struct logserver_out *out, const struct logserver_log *log)
{
	if (log->lvl > pv_config_get_int(PV_LOG_LEVEL))
		return 0;

	bool is_pv = !strncmp(log->plat, MAIN_PLATFORM, strlen(MAIN_PLATFORM));

	if (create_dir(log, is_pv, out->last_log) != 0)
		return -1;

	int fd = logserver_utils_open_logfile(out->last_log);

	if (fd < 0) {
		WARN_ONCE("Error opening file %s/%s, errno = %d\n", platform,
			  source, errno);

		memset(out->last_log, 0, PATH_MAX);
		return -1;
	}

	int len = 0;

	if (is_pv)
		len = logserver_utils_print_pvfmt(fd, log, "pantavisor", true);
	else
		len = logserver_utils_print_raw(fd, log);

	close(fd);

	return len;
}

struct logserver_out *logserver_filetree_new()
{
	return logserver_out_new(LOG_SERVER_OUTPUT_FILE_TREE, "filetree",
				 add_log, NULL, NULL);
}