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

#define PV_LS_PROTO_PV "_pv_"
#define PV_LS_PROTO_MAIN_PLAT "pantavisor"
#define PV_LS_PROTO_UNK_PLAT "unknown-platform"

typedef pv_ls_proto_code_t (*check_proto_fn)(const char *buf);
typedef int (*to_log_fn)(struct pv_ls_log_data *data, struct pv_ls_log *log);

struct pv_ls_proto {
	pv_ls_proto_code_t type;
	to_log_fn to_log;
};

static check_proto_fn proto_type[] = {
	pv_ls_rfc_check_type,
	pv_ls_json_check_type,
	pv_ls_kv_check_type,
	pv_ls_bin_check_type,
};

static struct pv_ls_proto proto[] = {
	{ LOG_PROTOCOL_LEGACY, pv_ls_bin_to_log },
	{ LOG_PROTOCOL_CMD, pv_ls_bin_to_log },
	{ LOG_PROTOCOL_RFC3164, pv_ls_rfc3164_to_log },
	{ LOG_PROTOCOL_RFC5424, pv_ls_rfc5424_to_log },
	{ LOG_PROTOCOL_JSON, pv_ls_json_to_log },
	{ LOG_PROTOCOL_KEY_VAL, pv_ls_kv_to_log },
	{ LOG_PROTOCOL_UNKNOWN, NULL }
};

pv_ls_proto_code_t pv_ls_proto_get(const char *buf)
{
	size_t size = sizeof(proto_type) / sizeof(proto_type[0]);
	for (size_t i = 0; i < size; i++) {
		if (!proto_type[i])
			continue;

		pv_ls_proto_code_t code = proto_type[i](buf);
		if (code != LOG_PROTOCOL_UNKNOWN)
			return code;
	}
	return LOG_PROTOCOL_UNKNOWN;
}

int pv_ls_proto_to_log(struct pv_ls_log_data *data, struct pv_ls_log *log)
{
	pv_ls_proto_code_t code = pv_ls_proto_get(data->buf);

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

int pv_ls_proto_set_platform_name(const char *cgroup, char *name)
{
	if (!name)
		return -1;

	memset(name, 0, PV_LS_PLATFORM_MAX);

	if (!cgroup) {
		memcpy(name, PV_LS_PROTO_UNK_PLAT,
		       strlen(PV_LS_PROTO_UNK_PLAT));
		return 0;
	}

	if (!strcmp(cgroup, PV_LS_PROTO_PV)) {
		memcpy(name, PV_LS_PROTO_MAIN_PLAT,
		       strlen(PV_LS_PROTO_MAIN_PLAT));
		return 0;
	}

	memccpy(name, cgroup, 0, PV_LS_PLATFORM_MAX - 1);

	return 0;
}
