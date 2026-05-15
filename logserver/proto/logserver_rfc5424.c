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

#include <string.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>

#define LOGSERVER_RFC5424_NILVALUE '-'
#define LOGSERVER_RFC5424_PARTS (8)

static bool logserver_rfc5424_is_nil(const char *buf)
{
	return (*buf == LOGSERVER_RFC5424_NILVALUE &&
		(*(buf - 1) == ' ' && *(buf + 1) == ' '));
}

static int logserver_rfc5424_get_timestamp(const char *buf, time_t *tst)
{
	if (logserver_rfc5424_is_nil(buf)) {
		*tst = time(NULL);
		return 0;
	}

	struct tm tm = { 0 };
	char *ptr = strptime(buf, "%Y-%m-%dT%H:%M:%S", &tm);
	if (!ptr)
		return -1;

	*tst = mktime(&tm);

	return 0;
}

static int logserver_rfc5424_get_str(char *beg, char *end, char **str)
{
	if (logserver_rfc5424_is_nil(beg)) {
		*str = NULL;
		return 0;
	}

	*str = beg;
	if (end)
		*end = '\0';

	return 0;
}

static int logserver_rfc5424_parse(char *buf, struct logserver_rfc *rfc)
{
	char *parts[LOGSERVER_RFC5424_PARTS] = { 0 };
	char *ptr = buf;
	int i = 0;

	do {
		// bad format
		if (!ptr || *ptr == '\0')
			return -1;

		parts[i] = ptr;
		i++;

		char *tmp = strchr(ptr, ' ');
		if (!tmp)
			break;
		ptr = tmp + 1;
	} while (i < LOGSERVER_RFC5424_PARTS);

	if (i < LOGSERVER_RFC5424_PARTS)
		return -1;

	rfc->prival = logserver_rfc_get_prival(parts[0]);
	if (rfc->prival < 0)
		return -1;

	if (logserver_rfc5424_get_timestamp(parts[1], &rfc->time) != 0)
		return -1;

	logserver_rfc5424_get_str(parts[2], parts[3] - 1, &rfc->host);

	if (!rfc->host)
		rfc->host = "unknown-host";

	logserver_rfc5424_get_str(parts[3], parts[4] - 1, &rfc->app);

	if (!rfc->app)
		rfc->app = "unknown-app";

	// ignoring PROCID, MSGID and STRUCTURED-DATA
	// parts 4, 5 and 6

	logserver_rfc5424_get_str(parts[7], NULL, &rfc->msg);
	if (!rfc->msg)
		rfc->msg = " ";

	return 0;
}

int logserver_rfc5424_to_log(char *buf, const char *rev, const char *upd_rev,
			     struct logserver_log *log)
{
	struct logserver_rfc rfc = { 0 };
	if (logserver_rfc5424_parse(buf, &rfc) != 0)
		return -1;

	return logserver_rfc_to_log(&rfc, logserver_rfc_get_type(buf), rev,
				    upd_rev, log);
}
