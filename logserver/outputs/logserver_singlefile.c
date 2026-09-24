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

#include "logserver_singlefile.h"
#include "logserver/utils/logserver_utils.h"
#include "config.h"
#include "paths.h"
#include "utils/fs.h"
#include "log.h"

#include <limits.h>
#include <string.h>
#include <linux/limits.h>
#include <unistd.h>
#include <libgen.h>
#include <stdio.h>

static int pv_ls_singlefile_create_dir(const struct pv_ls_log *log, char *path)
{
	if (!log->running_rev) {
		WARN_ONCE(
			"Log with no revision (null) arrives to singlefile output: %s",
			log->data.buf);
		return -1;
	}

	char tmp_path[PATH_MAX] = { 0 };
	pv_paths_pv_log(tmp_path, PATH_MAX, log->running_rev);

	if (pv_fs_mkdir_p(tmp_path, 0755))
		return -1;

	memset(path, 0, PATH_MAX);
	pv_paths_pv_log_plat(path, PATH_MAX, log->running_rev, "pv.log");

	return 0;
}

static int pv_ls_singlefile_add_log(struct pv_ls_out *out,
				    const struct pv_ls_log *log)
{
	if (log->lvl > pv_config_get_int(PV_LOG_LEVEL))
		return 0;

	if (pv_ls_singlefile_create_dir(log, out->last_log) != 0)
		return -1;

	int fd = pv_ls_utils_open_logfile(out->last_log);
	if (fd < 0) {
		WARN_ONCE("Error opening file %s, errno = %d\n", out->last_log,
			  errno);
		memset(out->last_log, 0, PATH_MAX);
		return -1;
	}

	int len = pv_ls_utils_print_json_fmt(fd, log);

	close(fd);

	return len;
}

struct pv_ls_out *pv_ls_singlefile_new()
{
	return pv_ls_out_new(LOG_SERVER_OUTPUT_SINGLE_FILE, "singlefile",
			     pv_ls_singlefile_add_log, NULL, NULL);
}
