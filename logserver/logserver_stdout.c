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

#include "logserver_stdout.h"
#include "logserver_utils.h"
#include "config.h"

#include <unistd.h>
#include <libgen.h>
#include <stdio.h>

static int add_log(struct logserver_out *out, const struct logserver_log *log)
{
	if (log->lvl > pv_config_get_log_loglevel())
		return 0;

	int len = logserver_utils_print_pvfmt(STDOUT_FILENO, log,
					      basename(log->src), false);
	fflush(stdout);
	return len;
}

struct logserver_out *logserver_stdout_new()
{
	return logserver_out_new(LOG_SERVER_OUTPUT_STDOUT, "stdout", add_log,
				 NULL, NULL);
}
