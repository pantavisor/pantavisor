/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#ifndef PV_LOG_H
#define PV_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <stdbool.h>

#include "pantavisor.h"
#include "utils.h"

void exit_error(int err, char *msg);

#ifdef DEBUG
#undef DEBUG
#endif

enum log_level {
	FATAL,	// 0
	ERROR,	// 1
	WARN,	// 2
	INFO,	// 3
	DEBUG,	// 4
	ALL	// 5
};

struct log_buffer {
	char *buf;
	int size;
	struct dl_list free_list;
};

struct pv_log {
	pid_t rev_logger;
	pid_t range_logger;
	pid_t push_helper;
};

#define LOG_NAME		"pantavisor.log"
#define ERROR_DIR		"error"

#define __put_buf_back__ 	__cleanup__(__put_log_buff)

#define JSON_FORMAT	"{ \"tsec\": %"PRId64", \"tnano\": %"PRId32", \"lvl\": \"%s\", \"src\": \"%s\", \"msg\": \"%s\" }"

// Example log:		"[pantavisor] WARN [2016-12-01 13:22:26] -- [updater]: Cannot poke cloud"
#define DATE_FORMAT		"2016-12-01 13:22:26"

#define vlog(module, level, ...)	__log(module, level, ## __VA_ARGS__);

#define LOG_CTRL_FNAME 			"pv-ctrl-log"
#define LOG_CTRL_PATH 			"/pv/"LOG_CTRL_FNAME
#define LOG_CTRL_PLATFORM_PATH 		"/pantavisor/"LOG_CTRL_FNAME
#define LOG_MAX_FILE_SIZE 		(2 * 1024 * 1024)

int pv_log_start(struct pantavisor *pv, int rev);

void __log(char *module, int level, const char *fmt, ...);
/*
 * Don't free the return value!
 */
const char *pv_log_level_name(int level);
struct log_buffer* pv_log_get_buffer(bool large);
void pv_log_put_buffer(struct log_buffer*);
static void __put_log_buff(struct log_buffer **log_buf)
{
	if (*log_buf) {
		pv_log_put_buffer(*log_buf);
	}
}
#endif
