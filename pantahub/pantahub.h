/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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
#ifndef PV_PANTAHUB_H
#define PV_PANTAHUB_H

#include "pantavisor.h"

#include "pantahub/pantahub_struct.h"

int pv_pantahub_start(void);
int pv_pantahub_stop(void);

void pv_pantahub_evaluate_state(void);

bool pv_pantahub_is_reporting(void);

bool pv_pantahub_is_online(void);
bool pv_pantahub_got_any_failure(void);

bool pv_pantahub_is_device_claimed(void);

bool pv_pantahub_is_progress_queue_empty(void);
void pv_pantahub_queue_progress(const char *rev, const char *progress);

#endif
