/*
 * Copyright (c) 2017-2023 Pantacor Ltd.
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

#ifndef PV_CTRL_H
#define PV_CTRL_H

#include <stdint.h>
#include <string.h>

typedef enum {
	CMD_UPDATE_METADATA = 1,
	CMD_REBOOT_DEVICE = 2,
	CMD_POWEROFF_DEVICE = 3,
	CMD_TRY_ONCE = 4,
	CMD_LOCAL_RUN = 5,
	CMD_MAKE_FACTORY = 6,
	CMD_RUN_GC = 7,
	CMD_ENABLE_SSH = 8,
	CMD_DISABLE_SSH = 9,
	CMD_GO_REMOTE = 10,
	CMD_DEFER_REBOOT = 11,
	CMD_LOCAL_RUN_COMMIT = 12,
	MAX_CMD_OP
} pv_cmd_operation_t;

struct pv_cmd {
	pv_cmd_operation_t op;
	char *payload;
};

void pv_ctrl_socket_read(int fd, short event, void *arg);
void pv_ctrl_free_cmd(struct pv_cmd *cmd);

void pv_ctrl_socket_close(int ctrl_fd);

static inline const char *
pv_ctrl_string_cmd_operation(const pv_cmd_operation_t op)
{
	static const char *strings[] = { NULL,
					 "UPDATE_METADATA",
					 "REBOOT_DEVICE",
					 "POWEROFF_DEVICE",
					 "TRY_ONCE",
					 "LOCAL_RUN",
					 "LOCAL_APPLY",
					 "MAKE_FACTORY",
					 "RUN_GC",
					 "ENABLE_SSH",
					 "DISABLE_SSH",
					 "GO_REMOTE",
					 "DEFER_REBOOT",
					 "LOCAL_RUN_COMMIT" };
	return strings[op];
}

static inline pv_cmd_operation_t
pv_ctrl_int_cmd_operation(const char *op_string, const int op_string_size)
{
	for (pv_cmd_operation_t op_index = 1; op_index < MAX_CMD_OP;
	     ++op_index) {
		if (!strncmp(op_string, pv_ctrl_string_cmd_operation(op_index),
			     op_string_size))
			return op_index;
	}

	return 0;
}

#endif // PV_CTRL_H
