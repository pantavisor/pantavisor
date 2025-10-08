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
#ifndef PV_PANTAHUB_PROTO_H
#define PV_PANTAHUB_PROTO_H

#include <stdbool.h>

void pv_pantahub_proto_init(void);
void pv_pantahub_proto_close(void);

void pv_pantahub_proto_reset_fail(void);
void pv_pantahub_proto_reset_trails_status(void);

bool pv_pantahub_proto_is_online(void);
bool pv_pantahub_proto_got_any_failure(void);

bool pv_pantahub_proto_is_any_progress_request_pending(void);

bool pv_pantahub_proto_is_trails_unknown(void);
bool pv_pantahub_proto_is_trails_unsynced(void);

void pv_pantahub_proto_open_session(void);
bool pv_pantahub_proto_is_session_open(void);
void pv_pantahub_proto_close_session(void);

void pv_pantahub_proto_get_trails_status(void);

void pv_pantahub_proto_get_usrmeta(void);
void pv_pantahub_proto_set_devmeta(void);
void pv_pantahub_proto_get_pending_steps(void);

void pv_pantahub_proto_init_object_transfer(void);
int pv_pantahub_proto_get_objects_metadata(void);
int pv_pantahub_proto_get_objects(void);

void pv_pantahub_proto_put_progress(const char *rev, const char *progress);

#endif
