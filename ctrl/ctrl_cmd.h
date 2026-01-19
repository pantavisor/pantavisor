/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#ifndef PV_CTRL_CMD_H
#define PV_CTRL_CMD_H

#include <stddef.h>
#include <string.h>

#define PV_CTRL_CMD_MAX_SIZE (4096)

enum pv_ctrl_cmd_op {
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
};

struct pv_ctrl_cmd {
	enum pv_ctrl_cmd_op op;
	char *payload;
};

static inline const char *pv_ctrl_cmd_op_to_str(const enum pv_ctrl_cmd_op op)
{
	static const char *strings[] = {
		NULL,
		"UPDATE_METADATA",
		"REBOOT_DEVICE",
		"POWEROFF_DEVICE",
		"TRY_ONCE",
		"LOCAL_RUN",
		"MAKE_FACTORY",
		"RUN_GC",
		"ENABLE_SSH",
		"DISABLE_SSH",
		"GO_REMOTE",
		"DEFER_REBOOT",
		"LOCAL_RUN_COMMIT",
	};
	return strings[op];
}

static inline enum pv_ctrl_cmd_op
pv_ctrl_cmd_op_from_str(const char *op_str, const size_t op_str_size)
{
	for (enum pv_ctrl_cmd_op index = 1; index < MAX_CMD_OP; ++index) {
		const char *index_str = pv_ctrl_cmd_op_to_str(index);
		if (!strncmp(op_str, index_str, op_str_size))
			return index;
	}

	return 0;
}

struct pv_ctrl_cmd *pv_ctrl_cmd_parse(const char *buf);
int pv_ctrl_cmd_add(struct pv_ctrl_cmd *cmd, char **err);
void pv_ctrl_cmd_free(struct pv_ctrl_cmd *cmd);

#endif
