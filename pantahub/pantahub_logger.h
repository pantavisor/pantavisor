/*
 * Copyright (c) 2020-2026 Pantacor Ltd.
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
#ifndef PV_PANTAHUB_LOGGER_H
#define PV_PANTAHUB_LOGGER_H

#include "pantahub/pantahub_proto.h"

// pushes the running revision's file tree logs as they are written
void pv_pantahub_logger_start_push(void);
// pushes what is left in older revisions, newest first
void pv_pantahub_logger_start_range(void);
// no new pushes until started again; in-flight ones still complete
void pv_pantahub_logger_pause(void);
// forgets the positions kept in memory
void pv_pantahub_logger_stop(void);

// response to a POST /logs/: HTTP status, or -1 without response
void pv_pantahub_logger_on_posted(pv_logs_req_t which, int status,
				  const char *body);

#endif
