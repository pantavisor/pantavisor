/*
 * Copyright (c) 2022 Pantacor Ltd.
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
#ifndef PV_GROUP_H
#define PV_GROUP_H

#include "platforms.h"

#include "utils/list.h"
#include "utils/json.h"
#include "utils/timer.h"

typedef enum {
	STATUS_GOAL_UNKNOWN,
	STATUS_GOAL_REACHED,
	STATUS_GOAL_WAITING,
	STATUS_GOAL_FAILED
} groups_goals_state_t;

struct pv_group {
	char *name;
	int timeout;
	plat_status_t default_status_goal;
	restart_policy_t default_restart_policy;
	struct timer timer_goal;
	struct dl_list platform_refs; // pv_platform_ref
	struct dl_list list; // pv_group
};

struct pv_group *pv_group_new(char *name, int timeout, plat_status_t status,
			      restart_policy_t restart);
void pv_group_empty_platform_refs(struct pv_group *g);
void pv_group_free(struct pv_group *g);

void pv_group_add_platform(struct pv_group *g, struct pv_platform *p);

groups_goals_state_t pv_group_check_goals(struct pv_group *g);
void pv_group_add_json(struct pv_json_ser *js, struct pv_group *g);
void pv_group_start_timer(struct pv_group *g);

#endif // PV_GROUP_H
