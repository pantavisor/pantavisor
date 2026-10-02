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
#include "logserver/utils/logserver_timestamp.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static int pv_ls_bin_parse_msg(struct pv_ls_msg *msg, struct pv_ls_log *log)
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

	memccpy(log->plat, plat_pos, 0, PV_LS_PLATFORM_MAX);
	log->plat[PV_LS_PLATFORM_MAX - 1] = '\0';

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

	log->tnano = 0;
	log->time = time(NULL);
	log->tsec = pv_ls_timestamp_get_tsec(log->time);

	return 0;
}

pv_ls_proto_code_t pv_ls_bin_check_type(const char *buf)
{
	struct pv_ls_msg *msg = (struct pv_ls_msg *)buf;

	if (msg->code == LOG_PROTOCOL_LEGACY || msg->code == LOG_PROTOCOL_CMD)
		return msg->code;

	return LOG_PROTOCOL_UNKNOWN;
}

int pv_ls_bin_to_log(struct pv_ls_log_data *data, struct pv_ls_log *log)
{
	struct pv_ls_msg *msg = (struct pv_ls_msg *)data->buf;

	log->code = msg->code;
	log->running_rev = data->rev;
	log->updated_rev = data->upd;

	int ret = 0;

	if (log->code == LOG_PROTOCOL_LEGACY) {
		ret = pv_ls_bin_parse_msg(msg, log);
	} else if (log->code == LOG_PROTOCOL_CMD) {
		log->data.buf = msg->buf;
		log->data.len = msg->len;
	} else {
		return log->code;
	}

	return ret;
}
