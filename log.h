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

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef PV_LOG_H
#define PV_LOG_H

#include "pantavisor.h"

void exit_error(int err, char *msg);

enum log_level {
	FATAL,	// 0
	ERROR,	// 1
	WARN,	// 2
	INFO,	// 3
	DEBUG,	// 4
	ALL	// 5
};

#define LOG_NAME		"pantavisor.log"
#define ERROR_DIR		"error"


#define JSON_FORMAT	"{ \"tsec\": %"PRId64", \"tnano\": %"PRId32", \"lvl\": \"%s\", \"src\": \"%s\", \"msg\": \"%s\" }"

// Example log:		"[pantavisor] WARN [2016-12-01 13:22:26] -- [updater]: Cannot poke cloud"
#define DATE_FORMAT		"2016-12-01 13:22:26"

#define vlog(module, level, ...)	__log(module, level, ## __VA_ARGS__);

#define LOG_MAX_FILE_SIZE 		(2 * 1024 * 1024)

int pv_log_start(struct pantavisor *pv, const char *rev);

void __log(char *module, int level, const char *fmt, ...);
/*
 * Don't free the return value!
 */
const char *pv_log_level_name(int level);
#endif
