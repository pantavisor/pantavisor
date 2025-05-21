/*
 * Copyright (c) 2022-2024 Pantacor Ltd.
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

#ifndef LOGSERVER_H
#define LOGSERVER_H

#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include "pantavisor.h"

#define PV_PLATFORM_STR "pantavisor"

void pv_logserver_toggle(struct pantavisor *pv, const char *rev);

int pv_logserver_init(const char *rev);

int pv_logserver_send_log(bool is_platform, char *platform, char *src,
			  int level, const char *msg, ...);
int pv_logserver_send_vlog(bool is_platform, char *platform, char *src,
			   int level, const char *msg, va_list args);

void pv_logserver_transition(const char *rev);
void pv_logserver_stop(void);

void pv_logserver_start_update(const char *rev);
void pv_logserver_stop_update(const char *rev);

int pv_logserver_subscribe_fd(int fd, const char *platform, const char *src,
			      int loglevel);
int pv_logserver_unsubscribe_fd(const char *platform, const char *src);

#endif /* LOGSERVER_H */
