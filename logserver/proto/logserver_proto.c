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

#include "logserver_proto.h"
#include "logserver_rfc.h"
#include "logserver_binary.h"
#include "logserver_json.h"
#include "logserver_kv.h"

#include <stdbool.h>
#include <string.h>

#define LOGSERVER_PROTO_PV "_pv_"
#define LOGSERVER_PROTO_MAIN_PLAT "pantavisor"
#define LOGSERVER_PROTO_UNK_PLAT "unknown-platform"

typedef log_protocol_code_t (*check_proto_fn)(const char *buf);
typedef int (*to_log_fn)(struct logserver_log_data *data,
			 struct logserver_log *log);

struct logserver_proto {
	log_protocol_code_t type;
	to_log_fn to_log;
};

static check_proto_fn proto_type[] = {
	logserver_rfc_check_type,
	logserver_json_check_type,
	logserver_kv_check_type,
	logserver_bin_check_type,
};

static struct logserver_proto proto[] = {
	{ LOG_PROTOCOL_LEGACY, logserver_bin_to_log },
	{ LOG_PROTOCOL_CMD, logserver_bin_to_log },
	{ LOG_PROTOCOL_RFC3164, logserver_rfc3164_to_log },
	{ LOG_PROTOCOL_RFC5424, logserver_rfc5424_to_log },
	{ LOG_PROTOCOL_JSON, logserver_json_to_log },
	{ LOG_PROTOCOL_KEY_VAL, logserver_kv_to_log },
	{ LOG_PROTOCOL_UNKNOWN, NULL }
};

log_protocol_code_t logserver_proto_get(const char *buf)
{
	size_t size = sizeof(proto_type) / sizeof(proto_type[0]);
	for (size_t i = 0; i < size; i++) {
		if (!proto_type[i])
			continue;

		log_protocol_code_t code = proto_type[i](buf);
		if (code != LOG_PROTOCOL_UNKNOWN)
			return code;
	}
	return LOG_PROTOCOL_UNKNOWN;
}

int logserver_proto_to_log(struct logserver_log_data *data,
			   struct logserver_log *log)
{
	log_protocol_code_t code = logserver_proto_get(data->buf);

	if (code == LOG_PROTOCOL_UNKNOWN) {
		log->code = code;
		return 0;
	}

	int ret = -1;

	size_t size = sizeof(proto) / sizeof(proto[0]);
	for (size_t i = 0; i < size; i++) {
		if (proto[i].type != code || !proto[i].to_log)
			continue;

		ret = proto[i].to_log(data, log);
		break;
	}

	return ret;
}

int logserver_proto_set_platform_name(const char *cgroup, char *name)
{
	if (!name)
		return -1;

	memset(name, 0, LOGSERVER_PLAT_MAX_LEN);

	if (!cgroup) {
		memcpy(name, LOGSERVER_PROTO_UNK_PLAT,
		       strlen(LOGSERVER_PROTO_UNK_PLAT));
		return 0;
	}

	if (!strcmp(cgroup, LOGSERVER_PROTO_PV)) {
		memcpy(name, LOGSERVER_PROTO_MAIN_PLAT,
		       strlen(LOGSERVER_PROTO_MAIN_PLAT));
		return 0;
	}

	memccpy(name, cgroup, 0, LOGSERVER_PLAT_MAX_LEN - 1);

	return 0;
}
