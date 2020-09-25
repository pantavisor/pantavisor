/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#ifndef PV_CMD_H
#define PV_CMD_H
#include "pantavisor.h"

// legacy commands, use cmd_json_operation_t for new commands
enum cmd_t {
	CMD_TRY_ONCE = 1,
	CMD_LOG,
	CMD_JSON
};

enum cmd_json_operation_t {
	CMD_JSON_UPDATE_METADATA = 1,
	// add new commands here
	CMD_JSON_LOG,
	MAX_CMD_JSON_OP
};

struct pv_cmd_req {
	char cmd;
	enum cmd_json_operation_t json_operation ;
	uint32_t len;
	char *data;
	char *platform;
};

int pv_cmd_socket_open(struct pantavisor *pv, char *path);
struct pv_cmd_req *pv_cmd_socket_wait(struct pantavisor *pv, int timeout);
void pv_cmd_finish(struct pantavisor *pv);

static inline const char *string_cmd_operation(const enum cmd_json_operation_t op)
{
	static const char *strings[] = {NULL, "UPDATE_METADATA","JSON_LOG" };
	return strings[op];
}

static inline enum cmd_json_operation_t int_cmd_operation(const char *op_string, const uint8_t op_string_size)
{
	for (enum cmd_json_operation_t op_index = 1; op_index < MAX_CMD_JSON_OP; ++op_index) {
		if (!strncmp(op_string, string_cmd_operation(op_index), op_string_size))
			return op_index;
    }

    return 0;
}

#endif // PV_CMD_H
