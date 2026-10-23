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

#ifndef PV_CTRL_ENDPOINTS_H
#define PV_CTRL_ENDPOINTS_H

int pv_ctrl_endpoints_containers_init(void);
int pv_ctrl_endpoints_groups_init(void);
int pv_ctrl_endpoints_signal_init(void);
int pv_ctrl_endpoints_objects_init(void);
int pv_ctrl_endpoints_steps_init(void);
int pv_ctrl_endpoints_usrmeta_init(void);
int pv_ctrl_endpoints_devmeta_init(void);
int pv_ctrl_endpoints_buildinfo_init(void);
int pv_ctrl_endpoints_drivers_init(void);
int pv_ctrl_endpoints_commands_init(void);
int pv_ctrl_endpoints_config_init(void);
int pv_ctrl_endpoints_xconnect_graph_init(void);
int pv_ctrl_endpoints_daemons_init(void);
int pv_ctrl_endpoints_storage_init(void);
int pv_ctrl_endpoints_wakelock_init(void);
int pv_ctrl_endpoints_devmode_init(void);
int pv_ctrl_endpoints_exec_init(void);

// 0 while a devmode revision runs and devmode is allowed, else an HTTP code and a message
int pv_ctrl_devmode_check(const char **msg);
int pv_ctrl_endpoints_devmode_files_init(void);
#include <stddef.h>

struct pv_state;
struct pv_platform;
void pv_ctrl_devmode_inlay_path(struct pv_state *s, struct pv_platform *p,
				char *buf, size_t size);

#endif
