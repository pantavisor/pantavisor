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

#include "logserver_kv.h"
#include "logserver/logserver_timestamp.h"
#include "log.h"

#include <ctype.h>
#include <string.h>

#define LOGSERVER_KV_KEY_LVL "level"
#define LOGSERVER_KV_KEY_SRC "src"
#define LOGSERVER_KV_KEY_MSG "message"

#define LOGSERVER_KV_FLAG_LVL (1 << 0)
#define LOGSERVER_KV_FLAG_SRC (1 << 1)
#define LOGSERVER_KV_FLAG_MSG (1 << 2)
#define LOGSERVER_KV_FLAG_ALL                                                  \
	(LOGSERVER_KV_FLAG_LVL | LOGSERVER_KV_FLAG_SRC | LOGSERVER_KV_FLAG_MSG)

static void logserver_kv_skip_space(char **ptr)
{
	char *p = *ptr;
	while (*p && isspace((unsigned char)*p))
		p++;
	*ptr = p;
}

static bool logserver_kv_key_comp(const char *start, size_t len,
				  const char *key)
{
	return len == strlen(key) && !strncmp(start, key, strlen(key));
}

static int logserver_kv_check_key(char **buf)
{
	char *ptr = *buf;

	logserver_kv_skip_space(&ptr);
	if (*ptr == '\0')
		return 0;

	const char *start = (const char *)ptr;
	while (*ptr && *ptr != '=' && !isspace((unsigned char)*ptr))
		ptr++;

	if (*ptr == '\0')
		return 0;

	int len = ptr - start;
	if (len == 0)
		return 0;

	*buf = ptr;

	if (logserver_kv_key_comp(start, len, LOGSERVER_KV_KEY_LVL))
		return LOGSERVER_KV_FLAG_LVL;
	else if (logserver_kv_key_comp(start, len, LOGSERVER_KV_KEY_SRC))
		return LOGSERVER_KV_FLAG_SRC;
	else if (logserver_kv_key_comp(start, len, LOGSERVER_KV_KEY_MSG))
		return LOGSERVER_KV_FLAG_MSG;

	return 0;
}

bool debug = false;

static bool logserver_kv_check_val(char **buf, char **val, int *vlen)
{
	char *ptr = *buf;

	logserver_kv_skip_space(&ptr);
	if (*ptr != '=')
		return false;

	ptr++;

	logserver_kv_skip_space(&ptr);
	if (*ptr == '\0')
		return false;

	if (*ptr != '"') {
		const char *start = ptr;
		while (*ptr && !isspace((unsigned char)*ptr))
			++ptr;

		if (val)
			*val = (char *)start;
		if (vlen)
			*vlen = ptr - start;

		*buf = ptr;

		return ptr != start;
	}

	ptr++;

	if (val)
		*val = ptr;

	bool closed = false;
	while (*ptr) {
		// scaped quote
		if (*ptr == '\\' && *(ptr + 1) == '"') {
			ptr += 2;
			continue;
		}

		if (*ptr == '"') {
			if (vlen)
				*vlen = ptr - *val;
			ptr++;
			closed = true;
			break;
		}

		ptr++;
	}

	*buf = ptr;

	return closed;
}

static char *logserver_kv_check_kv(char *ptr, int *found)
{
	int f = logserver_kv_check_key(&ptr);
	if (f == 0)
		return NULL;

	*found |= f;

	if (f > 0)
		debug = true;

	bool x = logserver_kv_check_val(&ptr, NULL, NULL);

	if (debug)
		debug = false;

	if (!x)
		return NULL;

	return ptr;
}

log_protocol_code_t logserver_kv_check_type(const char *buf)
{
	int found = 0;
	char *ptr = (char *)buf;

	while ((ptr = logserver_kv_check_kv(ptr, &found)))
		;

	if (found != LOGSERVER_KV_FLAG_ALL)
		return LOG_PROTOCOL_UNKNOWN;

	return LOG_PROTOCOL_KEY_VAL;
}

int logserver_kv_to_log(struct logserver_log_data *data,
			struct logserver_log *log)
{
	char *ptr = data->buf;
	char *val = NULL;
	int vlen = 0;
	int key = 0;

	char *end = &data->buf[strlen(data->buf)];

	while ((key = logserver_kv_check_key(&ptr)) > 0) {
		if (!logserver_kv_check_val(&ptr, &val, &vlen))
			return -1;

		if (!val || vlen == 0)
			return -1;

		if (key & LOGSERVER_KV_FLAG_LVL) {
			char *lvl = calloc(vlen + 1, sizeof(char));
			if (!lvl)
				return -1;
			memcpy(lvl, val, vlen);

			for (size_t i = 0; i < strlen(lvl); i++)
				lvl[i] = toupper((unsigned char)lvl[i]);

			log->lvl = pv_log_level_value(lvl);
			free(lvl);
			if (log->lvl == -1)
				return -1;

		} else if (key & LOGSERVER_KV_FLAG_MSG) {
			log->data.len = vlen;
			log->data.buf = val;
			ptr = val + vlen;
			if (*ptr && ptr < end) {
				*ptr = '\0';
				ptr++;
			}
		} else if (key & LOGSERVER_KV_FLAG_SRC) {
			log->src = val;
			ptr = val + vlen;
			if (*ptr && ptr < end) {
				*ptr = '\0';
				ptr++;
			}
		}
	}

	if (logserver_proto_set_platform_name(data->cgroup, log->plat) != 0)
		return -1;

	log->code = LOG_PROTOCOL_KEY_VAL;
	log->tnano = 0;
	log->time = time(NULL);
	log->tsec = logserver_timestamp_get_tsec(log->time);
	log->running_rev = data->rev;
	log->updated_rev = data->upd;

	return 0;
}
