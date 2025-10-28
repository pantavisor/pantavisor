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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pvtx_buffer.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int get_buf_size(const char *env, size_t min, size_t max)
{
	char *size_str = getenv(env);
	if (!size_str)
		return min;

	errno = 0;
	int size = strtol(size_str, NULL, 10);
	if (errno != 0 || size < min)
		return min;
	if (size > max)
		return max;

	return size;
}

int pv_pvtx_buffer_realloc(struct pv_pvtx_buffer *buf, size_t new_size)
{
	if (!buf)
		return -1;

	if (!buf->data)
		return -1;

	char *tmp = realloc(buf->data, (new_size + 1) * sizeof(char));

	if (!tmp)
		return -1;

	buf->data = tmp;
	buf->size = new_size;

	return 0;
}

struct pv_pvtx_buffer *pv_pvtx_buffer_new(size_t size)
{
	if (size < 0)
		return NULL;

	struct pv_pvtx_buffer *buf = calloc(1, sizeof(struct pv_pvtx_buffer));
	if (!buf)
		return NULL;

	// the extra block is to be "string compatible"
	buf->data = calloc(size + 1, sizeof(char));
	if (!buf->data) {
		pv_pvtx_buffer_free(buf);
		return NULL;
	}

	buf->size = size;

	return buf;
}

struct pv_pvtx_buffer *pv_pvtx_buffer_from_env(const char *env, size_t min,
					       size_t max, size_t rounding)
{
	size_t size = get_buf_size(env, min, max);

	if (size % rounding)
		size = (size | (rounding - 1)) + 1;

	return pv_pvtx_buffer_new(size);
}

void pv_pvtx_buffer_free(struct pv_pvtx_buffer *buf)
{
	if (!buf)
		return;

	if (buf->data)
		free(buf->data);

	free(buf);
}