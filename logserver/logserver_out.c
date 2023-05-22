/*
 * Copyright (c) 2023 Pantacor Ltd.
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

#include "logserver_out.h"

#include <stdlib.h>
#include <string.h>

struct logserver_out *logserver_out_new(
	int id, const char *name,
	int (*add)(struct logserver_out *out, const struct logserver_log *log),
	void (*free)(struct logserver_out *out), void *opaque)
{
	if (!add)
		return NULL;

	struct logserver_out *out = calloc(1, sizeof(struct logserver_out));
	if (!out)
		return NULL;

	out->name = strdup(name);
	if (!out->name) {
		free(out);
		return NULL;
	}

	out->id = id;
	out->add = add;
	out->free = free;
	out->opaque = opaque;
	dl_list_init(&out->list);

	return out;
}

void logserver_out_free(struct logserver_out *out)
{
	if (!out)
		return;

	if (out->name)
		free(out->name);

	if (out->free)
		out->free(out);

	free(out);
}
