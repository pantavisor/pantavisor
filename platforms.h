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

#include <sys/types.h>

#include "pantavisor.h"
#include "condition.h"
#include "utils/list.h"

typedef enum {
	PLAT_NONE,
	PLAT_READY,
	PLAT_MOUNTED,
	PLAT_BLOCKED,
	PLAT_STARTING,
	PLAT_STARTED,
	PLAT_STOPPING,
	PLAT_STOPPED
} plat_status_t;

typedef enum {
	DRIVER_REQUIRED = (1 << 0),
	DRIVER_OPTIONAL = (1 << 1),
	DRIVER_MANUAL   = (1 << 2)
} plat_driver_t;

struct pv_platform_driver {
	plat_driver_t type;
	bool loaded;
	char *match;
	struct dl_list list;
};

typedef enum {
	PLAT_ROLE_MGMT = 1 << 0,
	PLAT_ROLE_SIZE
} roles_mask_t;

struct pv_platform {
	char *name;
	char *type;
	char **configs;
	char *exec;
	unsigned long ns_share;
	void *data;
	pid_t init_pid;
	plat_status_t status;
	struct pv_group *group;
	struct pv_state *state;
	int roles;
	bool updated;
	struct dl_list drivers;
	struct dl_list condition_refs; // pv_condition_ref
	struct dl_list list; // pv_platform
	struct dl_list logger_list; // pv_log_info
	/*
	 * To be freed once logger_list is setup.
	 * */
	struct dl_list logger_configs; // pv_logger_config
};

void pv_platform_free(struct pv_platform *p);

void pv_platform_add_driver(struct pv_platform *g, plat_driver_t type, char *value);
void pv_platform_add_condition(struct pv_platform *g, struct pv_condition *c);

int pv_platform_load_drivers(struct pv_platform *p, char *namematch, plat_driver_t typematch);
void pv_platform_unload_drivers(struct pv_platform *p, char *namematch, plat_driver_t typematch);

int pv_platform_start(struct pv_platform *p);
int pv_platform_stop(struct pv_platform *p);
void pv_platform_force_stop(struct pv_platform *p);

int pv_platform_check_running(struct pv_platform *p);
bool pv_platform_check_conditions(struct pv_platform *p);

void pv_platform_set_ready(struct pv_platform *p);
void pv_platform_set_mounted(struct pv_platform *p);
void pv_platform_set_blocked(struct pv_platform *p);
void pv_platform_set_updated(struct pv_platform *p);

bool pv_platform_is_ready(struct pv_platform *p);
bool pv_platform_is_blocked(struct pv_platform *p);
bool pv_platform_is_starting(struct pv_platform *p);
bool pv_platform_is_started(struct pv_platform *p);
bool pv_platform_is_stopping(struct pv_platform *p);
bool pv_platform_is_stopped(struct pv_platform *p);
bool pv_platform_is_updated(struct pv_platform *p);

void pv_platform_set_role(struct pv_platform *p, roles_mask_t role);
void pv_platform_unset_role(struct pv_platform *p, roles_mask_t role);
bool pv_platform_has_role(struct pv_platform *p, roles_mask_t role);

char* pv_platform_get_json(struct pv_platform *p);

int pv_platforms_init_ctrl(struct pantavisor *pv);

struct pv_platform* pv_platform_add(struct pv_state *s, char *name);

void pv_platforms_remove_not_installed(struct pv_state *s);
void pv_platforms_add_all_loggers(struct pv_state *s);

void pv_platforms_empty(struct pv_state *s);

#endif
