/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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

#include "utils/list.h"
#include "utils/json.h"
#include "utils/timer.h"

#include "event/event_socket.h"

typedef enum {
	PLAT_NONE,
	PLAT_INSTALLED,
	PLAT_MOUNTED,
	PLAT_BLOCKED,
	PLAT_STARTING,
	PLAT_STARTED,
	PLAT_READY,
	PLAT_STOPPING,
	PLAT_STOPPED
} plat_status_t;

typedef enum {
	PLAT_GOAL_NONE,
	PLAT_GOAL_ACHIEVED,
	PLAT_GOAL_UNACHIEVED,
	PLAT_GOAL_TIMEDOUT,
} plat_goal_state_t;

typedef enum {
	DRIVER_REQUIRED = (1 << 0),
	DRIVER_OPTIONAL = (1 << 1),
	DRIVER_MANUAL = (1 << 2)
} plat_driver_t;

typedef enum {
	SVC_TYPE_UNKNOWN,
	SVC_TYPE_REST,
	SVC_TYPE_DBUS,
	SVC_TYPE_UNIX,
	SVC_TYPE_DRM,
	SVC_TYPE_WAYLAND,
	SVC_TYPE_INPUT
} service_type_t;

typedef enum {
	SERVICE_REQUIRED = (1 << 0),
	SERVICE_OPTIONAL = (1 << 1),
	SERVICE_MANUAL = (1 << 2)
} plat_service_t;

struct pv_platform_service {
	plat_service_t type;
	service_type_t svc_type;
	char *name;
	char *role;
	char *interface;
	struct dl_list list;
};

struct pv_platform_service_export {
	service_type_t svc_type;
	char *name;
	char *socket;
	struct dl_list list;
};
typedef enum {
	RESTART_NONE,
	RESTART_SYSTEM,
	RESTART_CONTAINER
} restart_policy_t;

struct pv_platform_driver {
	plat_driver_t type;
	char *match;
	struct dl_list list;
};

typedef enum { PLAT_ROLE_MGMT = 1 << 0, PLAT_ROLE_SIZE } roles_mask_t;

struct pv_status {
	plat_status_t current;
	plat_status_t goal;
};

struct pv_platform_log {
	int console_tty;
	int console_pt;
	int lxc_pipe[2];
};

struct pv_platform {
	char *name;
	char *type;
	char **configs;
	char *exec;
	unsigned long ns_share;
	pid_t init_pid;
	struct pv_platform_log log;
	struct pv_status status;
	struct pv_group *group;
	struct pv_state *state;
	int roles;
	restart_policy_t restart_policy;
	bool updated;
	bool automodfw; // auto mount modfw
	bool export;
	int pipefd[2];
	struct pv_event_socket pipefd_listener;
	struct timer timer_status_goal;
	struct dl_list drivers; // pv_platform_driver
	struct dl_list services; // pv_platform_service
	struct dl_list service_exports; // pv_platform_service_export
	struct dl_list list; // pv_platform
	struct dl_list logger_list; // pv_log_info
	/*
	         * To be freed once logger_list is setup.
	         * */
	struct dl_list logger_configs; // pv_logger_config
};
void pv_platform_free(struct pv_platform *p);

void pv_platform_add_driver(struct pv_platform *p, plat_driver_t type,
			    char *value);
void pv_platform_add_service(struct pv_platform *p, plat_service_t type,
			     service_type_t svc_type, char *name, char *role,
			     char *interface);
void pv_platform_add_service_export(struct pv_platform *p,
				    service_type_t svc_type, char *name,
				    char *socket);
int pv_platform_load_drivers(struct pv_platform *p, char *namematch,
			     plat_driver_t typematch);
void pv_platform_unload_drivers(struct pv_platform *p, char *namematch,
				plat_driver_t typematch);

int pv_platform_start(struct pv_platform *p);
int pv_platform_stop(struct pv_platform *p);
void pv_platform_force_stop(struct pv_platform *p);

bool pv_platform_check_running(struct pv_platform *p);

void pv_platform_set_installed(struct pv_platform *p);
void pv_platform_set_mounted(struct pv_platform *p);
void pv_platform_set_blocked(struct pv_platform *p);
void pv_platform_set_updated(struct pv_platform *p);

int pv_platform_set_ready(struct pv_platform *p);

bool pv_platform_is_installed(struct pv_platform *p);
bool pv_platform_is_blocked(struct pv_platform *p);
bool pv_platform_is_starting(struct pv_platform *p);
bool pv_platform_is_started(struct pv_platform *p);
bool pv_platform_is_ready(struct pv_platform *p);
bool pv_platform_is_stopping(struct pv_platform *p);
bool pv_platform_is_stopped(struct pv_platform *p);
bool pv_platform_is_updated(struct pv_platform *p);

void pv_platform_set_status_goal(struct pv_platform *p, plat_status_t goal);
plat_goal_state_t pv_platform_check_goal(struct pv_platform *p);

void pv_platform_set_restart_policy(struct pv_platform *p,
				    restart_policy_t policy);

void pv_platform_set_role(struct pv_platform *p, roles_mask_t role);
void pv_platform_unset_role(struct pv_platform *p, roles_mask_t role);
bool pv_platform_has_role(struct pv_platform *p, roles_mask_t role);

const char *pv_platform_status_string(plat_status_t status);
const char *pv_platforms_restart_policy_str(restart_policy_t policy);

void pv_platform_add_json(struct pv_json_ser *js, struct pv_platform *p);

int pv_platforms_init_ctrl(void);

struct pv_platform *pv_platform_add(struct pv_state *s, char *name);

void pv_platforms_remove_not_installed(struct pv_state *s);
void pv_platforms_add_all_loggers(struct pv_state *s);

void pv_platforms_empty(struct pv_state *s);

struct pv_platform_ref {
	struct pv_platform *ref;
	struct dl_list list; // pv_platform_ref
};

struct pv_platform_ref *pv_platform_ref_new(struct pv_platform *p);
void pv_platform_ref_free(struct pv_platform_ref *pr);

#endif
