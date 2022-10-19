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

#ifndef PV_QUEUE_H
#define PV_QUEUE_H

#include <stdbool.h>

struct pv_queue;

struct pv_queue *pv_queue_new_from_mem(int capacity);
struct pv_queue *pv_queue_new_from_disk(int capacity, const char *fname);
void pv_queue_free(struct pv_queue *q);
int pv_queue_size(const struct pv_queue *q);
int pv_queue_capacity(const struct pv_queue *q);
void pv_queue_push(struct pv_queue *q, char *data, int size);
char *pv_queue_pop(struct pv_queue *q, int *size);
bool pv_queue_has_space(struct pv_queue *q, int size);

#endif
