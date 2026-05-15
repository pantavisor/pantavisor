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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "logserver_rfc.h"

#include <time.h>
#include <string.h>

static char *logserver_rfc3164_get_timestamp(char *buf, time_t *tst)
{
	if (!buf || *buf == '\0')
		return NULL;

	struct tm tm = { 0 };
	char *ptr = strptime(buf, "%b %d %H:%M:%S", &tm);
	if (!ptr)
		return NULL;

	*tst = mktime(&tm);
	if (*tst == (time_t)-1)
		return NULL;

	return ptr;
}

static int logserver_rfc3164_parse(char *buf, struct logserver_rfc *rfc)
{
	rfc->prival = logserver_rfc_get_prival(buf);
	if (rfc->prival < 0)
		return -1;

	char *ptr = strchr(buf, '>');
	if (!ptr)
		return -1;
	ptr++;
	ptr = logserver_rfc3164_get_timestamp(ptr, &rfc->time);

	if (!ptr)
		return -1;

	ptr++;
	char *header_end = strchr(ptr, ':');
	if (!header_end) {
		rfc->host = "unknown-host";
		rfc->app = "unknown-app";
		rfc->msg = ptr;
		return 0;
	}

	// null-terminate at ':' and advance past ': '
	*header_end = '\0';
	rfc->msg = header_end + 1;
	if (*rfc->msg == ' ')
		rfc->msg++;

	char *host_end = strchr(ptr, ' ');

	if (!host_end) {
		rfc->host = "unknown-host";
	} else {
		rfc->host = ptr;
		*host_end = '\0';
		ptr = host_end + 1;
	}

	char *tag_end = strchr(ptr, '[');
	if (tag_end)
		*tag_end = '\0';
	rfc->app = ptr;

	return 0;
}

int logserver_rfc3164_to_log(char *buf, const char *rev, const char *upd_rev,
			     struct logserver_log *log)
{
	struct logserver_rfc rfc = { 0 };
	if (logserver_rfc3164_parse(buf, &rfc) != 0)
		return -1;

	return logserver_rfc_to_log(&rfc, logserver_rfc_get_type(buf), rev,
				    upd_rev, log);
}
