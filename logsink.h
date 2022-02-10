/*
 * Copyright (c) 2022 Pantacor Ltd.
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
#ifndef LOGSINK_H
#define LOGSINK_H

#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include "pantavisor.h"

#define PV_PLATFORM_STR "pantavisor"

void pv_logsink_toggle(struct pantavisor *pv, const char *rev);

int pv_logsink_init(void);

int pv_logsink_send_log(bool is_platform, char *platform, char *src, int level, const char *msg, ...);

int pv_logsink_send_vlog(bool is_platform, char *platform, char *src, int level, const char *msg, va_list args);

void pv_logsink_stop(void);

#endif /* LOGSINK_H */
