/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "phlogger_json_buffer.h"
#include "config.h"

#include <stdlib.h>
#include <string.h>

int pv_phlogger_json_buffer_init(char **buf)
{
	char *tmp = realloc(*buf, 2 * sizeof(char));
	if (!tmp)
		return -1;

	*buf = tmp;
	(*buf)[0] = '[';
	(*buf)[1] = '\0';

	return 0;
}

int pv_phlogger_json_buffer_add(char **buf, const char *data)
{
	size_t len = strlen(data);
	int cur_len = strlen(*buf);

	// +2 bc the bracket and the \0
	char *tmp = realloc(*buf, (cur_len + len + 2) * sizeof(char));
	if (!tmp)
		return -1;

	*buf = tmp;

	if ((*buf)[cur_len - 1] == ']')
		(*buf)[cur_len - 1] = ',';

	char *p = mempcpy(*buf + cur_len, data, len);

	p[0] = ']';
	p[1] = '\0';

	return 0;
}

bool pv_phlogger_json_buffer_need_flush(char *buf, size_t len)
{
	int max_buf_size = pv_config_get_int(PH_INTERNAL_BUFFER_SIZE);
	return strlen(buf) + len >= max_buf_size;
}