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

#include "logserver_json.h"
#include "utils/json.h"
#include "log.h"
#include "logserver/logserver_timestamp.h"

#include <string.h>
#include <ctype.h>

#define LOGSERVER_JSON_VER "0"

#define LOGSERVER_JSON_FLD_VER "version"
#define LOGSERVER_JSON_FLD_LVL "level"
#define LOGSERVER_JSON_FLD_SRC "src"
#define LOGSERVER_JSON_FLD_MSG "message"

log_protocol_code_t logserver_json_check_type(const char *buf)
{
	if (!pv_json_is_valid(buf))
		return LOG_PROTOCOL_UNKNOWN;
	return LOG_PROTOCOL_JSON;
}

static bool logserver_json_version_ok(const char *buf, jsmntok_t *tokv,
				      int tokc)
{
	char *ver = pv_json_get_value(buf, LOGSERVER_JSON_FLD_VER, tokv, tokc);
	if (!ver)
		return false;

	bool ret =
		!strncmp(ver, LOGSERVER_JSON_VER, strlen(LOGSERVER_JSON_VER));
	free(ver);

	return ret;
}

static int logserver_json_get_level(const char *buf, jsmntok_t *tokv, int tokc)
{
	char *name = pv_json_get_value(buf, LOGSERVER_JSON_FLD_LVL, tokv, tokc);
	if (!name)
		return -1;

	for (size_t i = 0; i < strlen(name); i++)
		name[i] = toupper(name[i]);

	int lvl = pv_log_level_value(name);
	free(name);

	return lvl;
}

int logserver_json_to_log(struct logserver_log_data *data,
			  struct logserver_log *log)
{
	int ret = -1;
	int tokc = 0;
	jsmntok_t *tokv = NULL;

	if (jsmnutil_parse_json(data->buf, &tokv, &tokc) < 0)
		goto out;

	if (!logserver_json_version_ok(data->buf, tokv, tokc))
		goto out;

	log->lvl = logserver_json_get_level(data->buf, tokv, tokc);
	if (log->lvl == -1)
		goto out;

	if (logserver_proto_set_platform_name(data->cgroup, log->plat) != 0)
		goto out;

	int src_len = 0;
	log->src = (char *)pv_json_get_value_ref(
		data->buf, LOGSERVER_JSON_FLD_SRC, tokv, tokc, &src_len);
	if (!log->src)
		goto out;

	log->data.buf = (char *)pv_json_get_value_ref(
		data->buf, LOGSERVER_JSON_FLD_MSG, tokv, tokc, &log->data.len);

	if (!log->data.buf)
		goto out;

	log->code = LOG_PROTOCOL_JSON;
	log->tnano = 0;
	log->time = time(NULL);
	log->tsec = logserver_timestamp_get_tsec(log->time);
	log->running_rev = data->rev;
	log->updated_rev = data->upd;

	// Add null terminators after processing the buffer
	log->src[src_len] = '\0';
	log->data.buf[log->data.len] = '\0';

	ret = 0;
out:
	if (tokv)
		free(tokv);

	return ret;
}
