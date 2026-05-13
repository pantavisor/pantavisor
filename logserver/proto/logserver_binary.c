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

#include "logserver_binary.h"

#include "utils/timer.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

int logserver_bin_parse_msg(struct logserver_msg *msg,
			    struct logserver_log *log)
{
	const char *end = msg->buf + msg->len;
	int bytes_read = 0;

	size_t lvl_len = strnlen(msg->buf, msg->len);
	if (lvl_len >= (size_t)msg->len)
		return -1;

	sscanf(msg->buf, "%d", &log->lvl);
	bytes_read += lvl_len + 1;

	char *plat_pos = msg->buf + bytes_read;
	if (plat_pos >= end)
		return -1;

	memccpy(log->plat, plat_pos, 0, LOGSERVER_PLAT_MAX_LEN);
	log->plat[LOGSERVER_PLAT_MAX_LEN - 1] = '\0';

	size_t plat_len = strnlen(plat_pos, end - plat_pos);
	if (plat_pos + plat_len >= end)
		return -1;

	bytes_read += plat_len + 1;

	log->src = msg->buf + bytes_read;
	if (log->src >= end)
		return -1;

	size_t src_len = strnlen(log->src, end - log->src);
	if (log->src + src_len >= end)
		return -1;

	bytes_read += src_len + 1;

	log->data.buf = msg->buf + bytes_read;
	log->data.len = msg->len - bytes_read;
	if (log->data.len < 0)
		return -1;

	log->tsec = timer_get_current_time_sec(RELATIV_TIMER);
	log->tnano = 0;
	log->time = time(NULL);

	return 0;
}

int logserver_bin_to_log(const char *buf, const char *rev, const char *upd_rev,
			 struct logserver_log *log)
{
	struct logserver_msg *msg = (struct logserver_msg *)buf;

	log->code = msg->code;
	log->running_rev = (char *)rev;
	log->updated_rev = (char *)upd_rev;

	int ret = 0;

	if (log->code == LOG_PROTOCOL_LEGACY) {
		ret = logserver_bin_parse_msg(msg, log);
	} else if (log->code == LOG_PROTOCOL_CMD) {
		log->data.buf = msg->buf;
		log->data.len = msg->len;
	} else {
		return log->code;
	}

	return ret;
}
