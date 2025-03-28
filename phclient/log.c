/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#include <stdio.h>
#include <stdarg.h>

#include "phclient/log.h"

static const char *_level_string(log_level_t level)
{
	switch (level) {
	case FATAL:
		return "FATAL";
	case ERROR:
		return "ERROR";
	case WARN:
		return "WARN";
	case INFO:
		return "INFO";
	case DEBUG:
		return "DEBUG";
	case ALL:
		return "ALL";
	default:
		return "UNKNOWN";
	}
}

void ph_log(log_level_t level, const char *msg, ...)
{
	printf("%s: ", _level_string(level));

	va_list args;
	int ret;
	va_start(args, msg);

	vprintf(msg, args);

	va_end(args);

	printf("\n\r");
}
