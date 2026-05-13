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

#ifndef LOGSERVER_RFC_H
#define LOGSERVER_RFC_H

#include "logserver/logserver_out.h"

#include <time.h>
#include <stdbool.h>

struct logserver_rfc {
	int prival;
	time_t time;
	char *host;
	char *app;
	char *msg;
};

int logserver_rfc_level_to_pv(int prival);
char *logserver_rfc_get_facility(int prival);
int logserver_rfc_get_prival(const char *buf);
int logserver_rfc_create_socket(const char *cur_sock);
log_protocol_code_t logserver_rfc_get_type(const char *buf);
int logserver_rfc_to_log(struct logserver_rfc *rfc, log_protocol_code_t code,
			 const char *rev, const char *upd_rev,
			 struct logserver_log *log);
int logserver_rfc5424_to_log(char *buf, const char *rev, const char *upd_rev,
			     struct logserver_log *log);
int logserver_rfc3164_to_log(char *buf, const char *rev, const char *upd_rev,
			     struct logserver_log *log);

#endif
