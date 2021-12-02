/*
 * Copyright (c) 2021 Pantacor Ltd.
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


#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include "buffer.h"

#define MODULE_NAME		"buffer"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static int max_items_num = 0;
static int max_item_size = 0;

static DEFINE_DL_LIST(buffer_list);
static DEFINE_DL_LIST(buffer_list_double);

#define __put_buf_back__ 	__cleanup__(__put_buff)

static struct buffer* __pv_buffer_get(struct dl_list *head)
{
       struct buffer *buffer = NULL;

       if (dl_list_empty(head))
               return NULL;
       buffer = dl_list_first(head,
                       struct buffer, free_list);
       dl_list_del(&buffer->free_list);
       dl_list_init(&buffer->free_list);
       return buffer;
}

struct buffer* pv_buffer_get(bool large)
{
	if (large)
		return __pv_buffer_get(&buffer_list_double);
	return __pv_buffer_get(&buffer_list);
}

void pv_buffer_drop(struct buffer *buffer)
{
	if (!buffer)
		return;
	if (!dl_list_empty(&buffer->free_list))
		return;
	if (max_item_size == buffer->size)
		dl_list_add(&buffer_list, &buffer->free_list);
	else
		dl_list_add(&buffer_list_double, &buffer->free_list);

}

static struct buffer* pv_buffer_alloc(int buf_size)
{
	struct buffer *buffer =  NULL;

	if (buf_size <= 0)
		return NULL;
	buffer = (struct buffer*) calloc(1, sizeof(*buffer));
	if (buffer) {
		buffer->buf = (char*)calloc(1, buf_size);
		if (!buffer->buf) {
			free(buffer);
			buffer = NULL;
		} else {
			buffer->size = buf_size;
		}
	}
	return buffer;
}

static int pv_buffer_init_cache(int items, int size, struct dl_list *head)
{
	int allocated = 0;

	if (!dl_list_empty(head)) {
		struct buffer *item, *tmp;
		dl_list_for_each_safe(item, tmp, head,
				struct buffer, free_list) {
			dl_list_del(&item->free_list);
			free(item->buf);
			free(item);
		}
	}
	while (items > 0) {
		struct buffer *buffer =  NULL;

		if (allocated >= max_items_num)
			break;
		buffer = pv_buffer_alloc(size);
		if (buffer) {
			dl_list_add(head, &buffer->free_list);
			allocated++;
		}
		items--;
	}
	return allocated;
}

void pv_buffer_init(int items, int size)
{
	int allocated_cache = 0;
	int allocated_dcache = 0;

	max_items_num = items;
	max_item_size = size;

	allocated_cache = pv_buffer_init_cache(max_items_num, size,
					&buffer_list);

	allocated_dcache = pv_buffer_init_cache(max_items_num, size * 2,
					&buffer_list_double);

	pv_log(DEBUG, "Allocated %d log buffers of size %d bytes",
			allocated_cache, size);
	pv_log(DEBUG, "Allocated %d log buffers of size %d bytes",
			allocated_dcache, size * 2);
}
