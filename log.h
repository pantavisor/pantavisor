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

#include "pantavisor.h"

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

struct level_name {
	int log_level;
	char *name;
};

#define BUF_CHUNK	4096
#define JSON_FORMAT	"{ \"tsec\": %"PRId64", \"tnano\": %"PRId32", \"lvl\": \"%s\", \"src\": \"%s\", \"msg\": \"%s\" }"

// Example log:		"[pantavisor] WARN [2016-12-01 13:22:26] -- [updater]: Cannot poke cloud"
#define DATE_FORMAT		"2016-12-01 13:22:26"

#define vlog(module, level, ...)	__vlog(module, level, ## __VA_ARGS__);

void pv_log_init(struct pantavisor *pv);
void __vlog(char *module, int level, const char *fmt, ...);
void pv_log_flush(struct pantavisor *pv, bool force);
int pv_log_set_level(unsigned int level);
void pv_log_raw(struct pantavisor *pv, char *buf, int len);

#endif
