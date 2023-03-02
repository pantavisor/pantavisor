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

#ifndef __PV_LOGGER_H__
#define __PV_LOGGER_H__

#define LOG_ENTRY_SIZE 512 /*(4096 - 48)*/

#define LOG_NOK (-1)
#define LOG_OK (0)

#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <errno.h>

#ifndef DEBUG
#define DEBUG 0
#else
#undef DEBUG
#define DEBUG 1
#endif

#define LOG_DEFAULT_LIMIT (2 * 1024 * 1024) /*2MiB*/

struct log {
	int (*do_start_log)(struct log *, int init_ret);
	int (*do_stop_log)(struct log *);
	int (*do_flush_log)(struct log *log, char *buf, int buflen);
	off_t log_limit;
	long truncate;
	void *opaque;
	/*
	 * Private stuff.
	 * */
	int notify_fd;
	int has_tmp_backing_file;
	FILE *backing_file;
	char *path_backing_file;
	char buff[LOG_ENTRY_SIZE];
	struct timeval *tv_notify;
};

int log_init(struct log *log, const char *backing_file);
int log_flush_pv(struct log *log);
int log_stop(struct log *log);

#endif /*__PV_LOGGER_H__*/
