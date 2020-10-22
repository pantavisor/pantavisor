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
#ifndef PV_PLATFORMS_H
#define PV_PLATFORMS_H

#include <stdbool.h>

#include "pantavisor.h"

#define MAX_RUNLEVEL 1

typedef enum {
	PLAT_NONE,
	PLAT_INSTALLED,
	PLAT_STARTED,
	PLAT_STOPPED
} plat_status_t;

struct pv_platform {
	char *name;
	char *type;
	char **configs;
	char *exec;
	unsigned long ns_share;
	void *data;
	char *json;
	pid_t init_pid;
	plat_status_t status;
	int runlevel;
	struct dl_list list; // pv_platform
	struct dl_list logger_list; // pv_log_info
	/*
	 * To be freed once logger_list is setup.
	 * */
	struct dl_list logger_configs; // pv_logger_config
};

void pv_platform_free(struct pv_platform *p);

int pv_platforms_init_ctrl(struct pantavisor *pv);

struct pv_platform* pv_platform_add(struct pv_state *s, char *name);
struct pv_platform* pv_platform_get_by_name(struct pv_state *s, char *name);

void pv_platforms_remove_not_installed(struct pv_state *s);
void pv_platforms_default_runlevel(struct pv_state *s);

int pv_platforms_start(struct pantavisor *pv, int runlevel);
int pv_platforms_check_exited(struct pantavisor *pv, int runlevel);
int pv_platforms_stop(struct pantavisor *pv, int runlevel);
void pv_platforms_empty(struct pv_state *s);

#endif
