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

#ifndef LOGSERVER_UTILS_H
#define LOGSERVER_UTILS_H

#include "logserver_out.h"

#include <stdbool.h>

int logserver_utils_open_logfile(const char *path);
int logserver_utils_print_pvfmt(int fd, const struct logserver_log *log,
				const char *src, bool lf);
int logserver_utils_print_json_fmt(int fd, const struct logserver_log *log);
int logserver_utils_print_raw(int fd, const struct logserver_log *log);
char *logserver_utils_jsonify_log(const struct logserver_log *log);
char *logserver_utils_output_to_str(int out_type);
int logserver_utils_stdout(const struct logserver_log *log);
int logserver_utils_printk_devmsg_on(void);
int logserver_utils_ignore_loglevel(void);

#endif
