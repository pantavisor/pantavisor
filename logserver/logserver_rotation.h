/*
 * Copyright (c) 2026 Pantacor Ltd.
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

#ifndef PV_LOGSERVER_ROTATION_H
#define PV_LOGSERVER_ROTATION_H

#include <linux/limits.h>
#include <sys/types.h>

typedef int (*logfn)(int, char *, ...);

struct logserver_rot {
	char path[PATH_MAX];
	off_t total_size;
	off_t rot_size;
	off_t high_wm;
	off_t low_wm;
	off_t cur_size;
};

struct logserver_rot pv_logserver_rot_init(const char *rev, logfn log);
void pv_logserver_rot_update(struct logserver_rot *rot);
int pv_logserver_rot_log_rot(struct logserver_rot *rot, const char *fname);
int pv_logserver_rot_deletion(struct logserver_rot *rot);

#endif
