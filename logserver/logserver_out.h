/*
 * Copyright (c) 2023 Pantacor Ltd.
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

#ifndef LOGSERVER_OUT_H
#define LOGSERVER_OUT_H

#include "utils/list.h"

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef DEBUG
#define WARN_ONCE(msg, args...)                                                \
	do {                                                                   \
		static bool __warned = false;                                  \
		if (!__warned) {                                               \
			pv_log(WARN, msg, ##args);                             \
			__warned = true;                                       \
		}                                                              \
	} while (0)
#else
#define WARN_ONCE(msg, args...)
#endif

struct logserver_data {
	char *buf;
	int len;
};

typedef enum {
	LOG_PROTOCOL_LEGACY = 0,
	LOG_PROTOCOL_BINARY_V2 = 1,
	LOG_PROTOCOL_UNKNOWN = 255,
	LOG_PROTOCOL_CMD = 256
} log_protocol_code_t;

// alias to match the new protocols names
#define LOG_PROTOCOL_BINARY_V1 (0)

static unsigned char proto_bin_v2_header[] = {
	//0pvlogv2 0xab 0xc8
	0x00, 0x50, 0x76, 0x6c, 0x6f, 0x67, 0x76, 0x32, 0xab, 0xc8
};

struct logserver_log {
	log_protocol_code_t code;
	int lvl;
	uint64_t tsec;
	uint32_t tnano;
	time_t time;
	char *plat;
	char *src;
	char *running_rev;
	char *updated_rev;
	struct logserver_data data;
};

struct logserver_out {
	int id;
	char *name;
	int (*add)(struct logserver_out *out, const struct logserver_log *log);
	void (*free)(struct logserver_out *out);
	void *opaque;
	struct dl_list list;
};

struct logserver_out *logserver_out_new(
	int id, const char *name,
	int (*add)(struct logserver_out *out, const struct logserver_log *log),
	void (*free)(struct logserver_out *out), void *opaque);

void logserver_out_free(struct logserver_out *out);

#endif
