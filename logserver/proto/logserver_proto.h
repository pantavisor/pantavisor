/*
 * Copyright (c) 2026 Pantacor Ltd.
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

#ifndef LOGSERVER_PROTO_H
#define LOGSERVER_PROTO_H

#include "logserver/logserver_out.h"

typedef enum {
	LOG_PROTOCOL_LEGACY = 0,
	LOG_PROTOCOL_UNKNOWN,
	LOG_PROTOCOL_RFC5424,
	LOG_PROTOCOL_RFC3164,
	LOG_PROTOCOL_JSON,
	LOG_PROTOCOL_CMD = 256
} log_protocol_code_t;

struct logserver_log_data {
	char *rev;
	char *upd;
	char *cgroup;
	char *buf;
};

log_protocol_code_t logserver_proto_get(const char *buf);
int logserver_proto_to_log(struct logserver_log_data *data,
			   struct logserver_log *log);
int logserver_proto_set_platform_name(const char *cgroup, char *name);

#endif
