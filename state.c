/*
 * Copyright (c) 2020-2022 Pantacor Ltd.
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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>

#include "state.h"
#include "drivers.h"
#include "paths.h"
#include "volumes.h"
#include "disk/disk.h"
#include "platforms.h"
#include "objects.h"
#include "jsons.h"
#include "addons.h"
#include "pantavisor.h"
#include "storage.h"
#include "metadata.h"
#include "utils/tsh.h"
#include "utils/math.h"
#include "utils/str.h"
#include "utils/json.h"
#include "utils/timer.h"

#define MODULE_NAME "state"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pv_state *pv_state_new(const char *rev, state_spec_t spec)
{
	int len = strlen(rev) + 1;
	struct pv_state *s;

	s = calloc(1, sizeof(struct pv_state));
	if (s) {
		s->rev = calloc(len, sizeof(char));
		SNPRINTF_WTRUNC(s->rev, len, "%s", rev);
		s->status = PLAT_NONE;
		s->spec = spec;
		dl_list_init(&s->platforms);
		dl_list_init(&s->volumes);
		dl_list_init(&s->disks);
		dl_list_init(&s->addons);
		dl_list_init(&s->objects);
		dl_list_init(&s->jsons);
		dl_list_init(&s->groups);
		dl_list_init(&s->bsp.drivers);
		s->using_runlevels = false;
		s->done = false;
	}

	return s;
}

static void pv_state_empty_groups(struct pv_state *s)
{
	int num_groups = 0;
	struct pv_group *g, *tmp;
	struct dl_list *groups = &s->groups;

	// Iterate over all groups from state
	dl_list_for_each_safe(g, tmp, groups, struct pv_group, list)
	{
		dl_list_del(&g->list);
		pv_group_free(g);
		num_groups++;
	}

	pv_log(INFO, "removed %d groups", num_groups);
}

void pv_state_free(struct pv_state *s)
{
	if (!s)
		return;

	pv_log(INFO, "removing state with revision %s", s->rev);

	if (s->rev)
		free(s->rev);
	if (s->bsp.config)
		free(s->bsp.config);
	if (s->bsp.img.ut.fit) {
		free(s->bsp.img.ut.fit);
	} else if (s->bsp.img.rpiab.bootimg) {
		free(s->bsp.img.rpiab.bootimg);
	} else {
		if (s->bsp.img.std.kernel)
			free(s->bsp.img.std.kernel);
		if (s->bsp.img.std.fdt)
			free(s->bsp.img.std.fdt);
		if (s->bsp.img.std.initrd)
			free(s->bsp.img.std.initrd);
	}
	if (s->bsp.firmware)
		free(s->bsp.firmware);
	if (s->bsp.modules)
		free(s->bsp.modules);

	pv_drivers_empty(s);
	pv_platforms_empty(s);
	pv_volumes_empty(s);
	pv_disk_empty(&s->disks);
	pv_addons_empty(s);
	pv_objects_empty(s);
	pv_jsons_empty(s);
	pv_state_empty_groups(s);

	free(s);
}

void pv_state_add_group(struct pv_state *s, struct pv_group *g)
{
	pv_log(DEBUG,
	       "adding group '%s' with status goal '%s' and restart policy '%s' to state",
	       g->name, pv_platform_status_string(g->default_status_goal),
	       pv_platforms_restart_policy_str(g->default_restart_policy));

	dl_list_init(&g->list);
	dl_list_add_tail(&s->groups, &g->list);
}

struct pv_group *pv_state_fetch_group(struct pv_state *s, const char *name)
{
	struct pv_group *g, *tmp;

	if (!name)
		return NULL;

	// Iterate over all groups from state
	dl_list_for_each_safe(g, tmp, &s->groups, struct pv_group, list)
	{
		if (pv_str_matches(g->name, strlen(g->name), name,
				   strlen(name)))
			return g;
	}

	return NULL;
}

struct pv_platform *pv_state_fetch_platform(struct pv_state *s,
					    const char *name)
{
	struct pv_platform *p, *tmp;

	if (!name)
		return NULL;

	// Iterate over all platforms from state
	dl_list_for_each_safe(p, tmp, &s->platforms, struct pv_platform, list)
	{
		if (pv_str_matches(p->name, strlen(p->name), name,
				   strlen(name)))
			return p;
	}

	return NULL;
}

struct pv_object *pv_state_fetch_object(struct pv_state *s, const char *name)
{
	struct pv_object *o, *tmp;

	if (!name)
		return NULL;

	// Iterate over all objects from state
	dl_list_for_each_safe(o, tmp, &s->objects, struct pv_object, list)
	{
		if (pv_str_matches(o->name, strlen(o->name), name,
				   strlen(name)))
			return o;
	}

	return NULL;
}

struct pv_json *pv_state_fetch_json(struct pv_state *s, const char *name)
{
	struct pv_json *j, *tmp;

	if (!name)
		return NULL;

	// Iterate over all groups from state
	dl_list_for_each_safe(j, tmp, &s->jsons, struct pv_json, list)
	{
		if (pv_str_matches(j->name, strlen(j->name), name,
				   strlen(name)))
			return j;
	}

	return NULL;
}

static struct pv_disk *pv_state_fetch_disk(struct pv_state *s, const char *name)
{
	struct pv_disk *d, *tmp;

	if (!name)
		return NULL;

	// Iterate over all disks from state
	dl_list_for_each_safe(d, tmp, &s->disks, struct pv_disk, list)
	{
		if (pv_str_matches(d->name, strlen(d->name), name,
				   strlen(name)))
			return d;
	}

	return NULL;
}

void pv_state_print(struct pv_state *s)
{
	if (!s)
		return;

	pv_log(DEBUG, "state %s:", s->rev);
	pv_log(DEBUG, " kernel: '%s'", s->bsp.img.std.kernel);
	pv_log(DEBUG, " initrd: '%s'", s->bsp.img.std.initrd);
	struct pv_group *g, *tmp_g;
	struct dl_list *groups = &s->groups;
	dl_list_for_each_safe(g, tmp_g, groups, struct pv_group, list)
	{
		pv_log(DEBUG, " group: '%s'", g->name);
	}
	struct pv_platform *p, *tmp_p;
	struct dl_list *platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp_p, platforms, struct pv_platform, list)
	{
		pv_log(DEBUG, " platform: '%s'", p->name);
		pv_log(DEBUG, "  type: '%s'", p->type);
		if (p->group)
			pv_log(DEBUG, "  group: '%s'", p->group->name);
		pv_log(DEBUG, "  configs:");
		char **config = p->configs;
		while (config && *config) {
			pv_log(DEBUG, "   '%s'", *config);
			config++;
		}
	}
	struct pv_volume *v, *tmp_v;
	struct dl_list *volumes = &s->volumes;
	dl_list_for_each_safe(v, tmp_v, volumes, struct pv_volume, list)
	{
		pv_log(DEBUG, " volume: '%s'", v->name);
		pv_log(DEBUG, "  type: %d", v->type);
		if (v->plat)
			pv_log(DEBUG, "  platform: '%s'", v->plat->name);
		if (v->disk)
			pv_log(DEBUG, "  disk: '%s'", v->disk->name);
	}
	struct pv_disk *d, *tmp_d;
	struct dl_list *disks = &s->disks;
	dl_list_for_each_safe(d, tmp_d, disks, struct pv_disk, list)
	{
		pv_log(DEBUG, " disk: '%s'", d->name);
		pv_log(DEBUG, "  default: %d", d->def);
		pv_log(DEBUG, "  type: %d", d->type);
	}
	struct pv_addon *a, *tmp_a;
	struct dl_list *addons = &s->addons;
	dl_list_for_each_safe(a, tmp_a, addons, struct pv_addon, list)
	{
		pv_log(DEBUG, " addon: '%s'", a->name);
	}
	struct pv_object *curr;
	pv_objects_iter_begin(s, curr)
	{
		pv_log(DEBUG, " object: '%s'", curr->name);
		pv_log(DEBUG, "  id: '%s'", curr->id);
		if (curr->plat)
			pv_log(DEBUG, "  platform: '%s'", curr->plat->name);
	}
	pv_objects_iter_end;
	struct pv_json *j, *tmp_j;
	struct dl_list *jsons = &s->jsons;
	dl_list_for_each_safe(j, tmp_j, jsons, struct pv_json, list)
	{
		pv_log(DEBUG, " json: '%s'", j->name);
		if (j->plat)
			pv_log(DEBUG, "  platform: '%s'", j->plat->name);
	}
	pv_log(DEBUG, "done=%d", s->done);
}

static int pv_state_set_default_groups(struct pv_state *s)
{
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = &s->platforms;
	struct pv_group *d;

	// default group is the last group added from groups.json
	d = dl_list_last(&s->groups, struct pv_group, list);
	dl_list_for_each_safe(p, tmp, platforms, struct pv_platform, list)
	{
		if (!p->group) {
			pv_log(WARN,
			       "platform '%s' does not belong to any group. Setting default...",
			       p->name);
			pv_group_add_platform(d, p);
		}
	}

	return 0;
}

static int pv_state_set_default_runlevels(struct pv_state *s)
{
	bool root_configured = false;
	struct pv_platform *p, *tmp, *first_p = NULL;
	struct dl_list *platforms = &s->platforms;
	struct pv_group *r, *d;

	r = pv_state_fetch_group(s, "root");
	d = pv_state_fetch_group(s, "platform");
	if (!r || !d) {
		pv_log(ERROR, "could not find group root or platform");
		return -1;
	}

	dl_list_for_each_safe(p, tmp, platforms, struct pv_platform, list)
	{
		// check if any platform has been configured in group root
		if (p->group == r)
			root_configured = true;
		// get first unconfigured platform
		if (!first_p && (p->group == NULL))
			first_p = p;
	}

	// if not, set first platform in group root
	if (!root_configured && first_p) {
		pv_log(WARN,
		       "no platform was found in 'root' group, "
		       "so the first unconfigured one in alphabetical order will be set");
		pv_group_add_platform(r, first_p);
	}

	// set rest of the non configured platforms in group platform
	platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp, platforms, struct pv_platform, list)
	{
		if (p->group == NULL) {
			pv_group_add_platform(d, p);
		}
	}

	return 0;
}

static int pv_state_set_runlevel_groups(struct pv_state *s)
{
	if (dl_list_empty(&s->platforms))
		return 0;

	if (s->using_runlevels)
		return pv_state_set_default_runlevels(s);

	return pv_state_set_default_groups(s);
}

static void pv_state_set_default_status_goals(struct pv_state *s)
{
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp, platforms, struct pv_platform, list)
	{
		if (p->status.goal != PLAT_NONE)
			continue;

		pv_log(INFO,
		       "platform '%s' in group '%s' has no explicit status goal. "
		       "It will be set by default to the group's '%s'",
		       p->name, p->group->name,
		       pv_platform_status_string(
			       p->group->default_status_goal));
		pv_platform_set_status_goal(p, p->group->default_status_goal);
	}
}

static void pv_state_set_default_restart_policies(struct pv_state *s)
{
	struct pv_platform *p, *tmp;
	struct dl_list *platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp, platforms, struct pv_platform, list)
	{
		if (p->restart_policy != RESTART_NONE)
			continue;

		pv_log(INFO,
		       "platform '%s' in group '%s' has no explicit restart_policy. "
		       "It will be set by default to the group's '%s'",
		       p->name, p->group->name,
		       pv_platforms_restart_policy_str(
			       p->group->default_restart_policy));
		pv_platform_set_restart_policy(
			p, p->group->default_restart_policy);
	}
}

int pv_state_validate(struct pv_state *s)
{
	// remove platforms that have no loaded data
	pv_platforms_remove_not_installed(s);
	// add loggers for all platforms
	pv_platforms_add_all_loggers(s);
	// set groups for all undefined platforms
	if (pv_state_set_runlevel_groups(s))
		return -1;
	// set default status goal
	pv_state_set_default_status_goals(s);
	// set default restart policies
	pv_state_set_default_restart_policies(s);

	return 0;
}

static int pv_state_mount_bsp_volumes(struct pv_state *s)
{
	if (pv_disk_mount_swap(&s->disks) != 0)
		return -1;

	struct pv_volume *v, *tmp;

	dl_list_for_each_safe(v, tmp, &s->volumes, struct pv_volume, list)
	{
		if (!v->plat)
			if (pv_volume_mount(v)) {
				pv_log(ERROR, "bsp volume %s mount failed",
				       v->name);
				return -1;
			}
	}

	return pv_volumes_mount_firmware_modules();
}

int pv_state_start(struct pv_state *s)
{
	return pv_state_mount_bsp_volumes(s);
}

static void pv_state_set_status(struct pv_state *s, plat_status_t status)
{
	if (s->status == status)
		return;

	s->status = status;
	pv_log(INFO, "state revision '%s' status is now %s", s->rev,
	       pv_platform_status_string(status));

	pv_metadata_add_devmeta("pantavisor.status",
				pv_platform_status_string(status));
}

void pv_state_eval_status(struct pv_state *s)
{
	if (!s)
		return;

	plat_status_t state_status = PLAT_READY;

	struct pv_group *g, *tmp;
	dl_list_for_each_safe(g, tmp, &s->groups, struct pv_group, list)
	{
		if (g->status < state_status)
			state_status = g->status;
	}

	pv_state_set_status(s, state_status);
}

plat_goal_state_t pv_state_check_goals(struct pv_state *s)
{
	if (!s)
		return PLAT_GOAL_NONE;

	plat_goal_state_t s_goal_state = PLAT_GOAL_ACHIEVED;
	plat_goal_state_t g_goal_state;

	struct pv_group *g, *tmp;
	dl_list_for_each_safe(g, tmp, &s->groups, struct pv_group, list)
	{
		// we are only interested in the highest goal state here. This will be
		// ACHIEVED unless there is any group that is still UNACHIEVED, which
		// will be also overwriten by any group that has TIMEDOUT
		g_goal_state = pv_group_check_goals(g);
		if (g_goal_state > s_goal_state)
			s_goal_state = g_goal_state;
	}

	return s_goal_state;
}

static plat_goal_state_t pv_state_check_goal_prev_group(struct pv_state *s,
							struct pv_group *group)
{
	if (!s || !group)
		return PLAT_GOAL_NONE;

	plat_goal_state_t g_goal_state = PLAT_GOAL_ACHIEVED;

	struct pv_group *g, *tmp;
	dl_list_for_each_safe(g, tmp, &s->groups, struct pv_group, list)
	{
		// we iterate over all previous groups to the one we are checking
		if (group == g)
			break;

		// each group that we iterate over will overwrite the return state,
		// so we will always get the one inmediately previous to the one we
		// are checking, unsless we find any group with UNACHIEVED state. In
		// that case, we return UNACHIEVED, as further ACHIEVED groups means
		// they have no platforms
		g_goal_state = pv_group_check_goals(g);
		if (g_goal_state == PLAT_GOAL_UNACHIEVED)
			break;
	}

	return g_goal_state;
}

static int pv_state_start_platform(struct pv_state *s, struct pv_platform *p)
{
	struct pv_volume *v, *tmp;

	dl_list_for_each_safe(v, tmp, &s->volumes, struct pv_volume, list)
	{
		if (v->plat == p)
			if (pv_volume_mount(v)) {
				pv_log(ERROR, "volume %s could not be mounted",
				       v->name);
				return -1;
			}
	}

	pv_platform_set_mounted(p);

	if (p->status.goal == PLAT_MOUNTED)
		return 0;

	if (pv_platform_load_drivers(p, NULL,
				     DRIVER_REQUIRED | DRIVER_OPTIONAL) < 0) {
		pv_log(ERROR, "failed to load drivers");
		return -1;
	}

	if (pv_platform_start(p)) {
		pv_log(ERROR, "platform %s could not be started", p->name);
		return -1;
	}

	return 0;
}

int pv_state_run(struct pv_state *s)
{
	int ret = 0;
	struct pv_platform *p, *tmp_p;

	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		if (pv_platform_is_installed(p) || pv_platform_is_blocked(p)) {
			plat_goal_state_t status_goal =
				pv_state_check_goal_prev_group(s, p->group);

			switch (status_goal) {
			case PLAT_GOAL_UNACHIEVED:
				pv_platform_set_blocked(p);
				break;
			case PLAT_GOAL_ACHIEVED:
			case PLAT_GOAL_TIMEDOUT:
				pv_log(DEBUG,
				       "platform '%s' from group '%s' can be started now",
				       p->name, p->group->name);
				ret = pv_state_start_platform(s, p);
				break;
			default:
				pv_log(WARN, "could not check groups goals");
			}
		} else if (pv_platform_is_starting(p)) {
			if (!pv_platform_check_running(p))
				pv_log(DEBUG,
				       "platform %s still not running   ",
				       p->name);
		} else if (pv_platform_is_started(p) ||
			   pv_platform_is_ready(p)) {
			if (!pv_platform_check_running(p)) {
				pv_log(ERROR, "platform %s suddenly stopped",
				       p->name);
				ret = -1;
			}
		}

		if (ret)
			goto out;
	}

out:
	return ret;
}

static bool pv_state_check_all_stopped(struct pv_state *s)
{
	bool try_again = false, ret = true;
	struct pv_platform *p, *tmp_p;

	for (int i = 0; i < 5; i++) {
		ret = true;
		dl_list_for_each_safe(p, tmp_p, &s->platforms,
				      struct pv_platform, list)
		{
			if (pv_platform_is_stopping(p)) {
				if (pv_platform_check_running(p)) {
					pv_log(DEBUG,
					       "platform %s still running",
					       p->name);
					try_again = true;
					ret = false;
				}
			}
		}

		if (!try_again)
			break;

		pv_log(DEBUG,
		       "some platforms are still running. Trying again in 1 second...");

		sleep(1);
		try_again = false;
	}

	return ret;
}

static void pv_state_lenient_stop(struct pv_state *s)
{
	struct pv_platform *p, *tmp_p;

	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		if (pv_platform_is_starting(p) || pv_platform_is_started(p) ||
		    pv_platform_is_ready(p))
			pv_platform_stop(p);
	}
}

static void pv_state_force_stop(struct pv_state *s)
{
	struct pv_platform *p, *tmp_p;

	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		if (pv_platform_is_stopping(p))
			pv_platform_force_stop(p);
	}
}

static int pv_state_unmount_platform_volumes(struct pv_state *s,
					     struct pv_platform *p)
{
	int ret = 0;
	struct pv_volume *v, *tmp_v;

	dl_list_for_each_safe(v, tmp_v, &s->volumes, struct pv_volume, list)
	{
		if (v->plat == p) {
			if (pv_volume_unmount(v))
				ret = -1;
		}
	}

	return ret;
}

static int pv_state_unmount_platforms_volumes(struct pv_state *s)
{
	int ret = 0;
	struct pv_platform *p, *tmp_p;

	// unmount platform volumes
	dl_list_for_each_safe(p, tmp_p, &s->platforms, struct pv_platform, list)
	{
		if (!(pv_platform_is_stopping(p) ||
		      pv_platform_is_starting(p) || pv_platform_is_started(p) ||
		      pv_platform_is_ready(p))) {
			if (pv_state_unmount_platform_volumes(s, p))
				ret = -1;
		}
	}

	return ret;
}

void pv_state_stop_lenient(struct pv_state *s)
{
	if (!s)
		return;

	pv_log(DEBUG, "leniently stopping state %s", s->rev);

	pv_state_lenient_stop(s);
}

int pv_state_stop_force(struct pv_state *s)
{
	int ret = 0;

	if (!s)
		return -1;

	if (!pv_state_check_all_stopped(s)) {
		pv_state_force_stop(s);
		ret |= -2;
	}

	// unmount all platform related volumes
	if (pv_state_unmount_platforms_volumes(s))
		ret |= -4;

	// unmount bsp volumes
	if (pv_state_unmount_platform_volumes(s, NULL))
		ret |= -8;

	return ret;
}

static bool pv_state_platform_requires_reboot(struct pv_platform *p)
{
	if (p->restart_policy == RESTART_SYSTEM) {
		pv_log(DEBUG,
		       "it belongs to platform '%s', which has a 'system' restart policy. "
		       "Rebooting...",
		       p->name);
		return true;
	} else if (p->restart_policy == RESTART_CONTAINER) {
		pv_log(DEBUG,
		       "it belongs to platform '%s', which has a 'container' restart policy. "
		       "Reseting container only...",
		       p->name);
	} else {
		pv_log(WARN,
		       "it belongs to platform '%s', which has a an unknown restart policy. "
		       "Rebooting...");
		return true;
	}

	return false;
}

static bool pv_state_compare_objects(struct pv_state *current,
				     struct pv_state *pending)
{
	struct pv_object *o, *tmp, *pend_o, *curr_o;
	struct pv_platform *p;

	if (!current || !pending)
		return true;

	// search for modified or deleted objects
	dl_list_for_each_safe(o, tmp, &current->objects, struct pv_object, list)
	{
		pend_o = pv_state_fetch_object(pending, o->name);
		if (!pend_o || strcmp(o->id, pend_o->id)) {
			pv_log(DEBUG,
			       "object %s has been modified or deleted in the pending update",
			       o->name);
			// changes in objects belonging to bsp require reboot
			if (!o->plat) {
				pv_log(DEBUG, "object belongs to bsp");
				return true;
			}
			// changes in objects belonging to platforms in certain groups require reboot
			if (pv_state_platform_requires_reboot(o->plat))
				return true;
			// lenient stop of platform and continue
			if (pv_platform_is_starting(o->plat) ||
			    pv_platform_is_started(o->plat) ||
			    pv_platform_is_ready(o->plat))
				pv_platform_stop(o->plat);
			// set to updated so we can remove it later
			pv_platform_set_updated(o->plat);
		}
	}

	// search for new objects
	dl_list_for_each_safe(o, tmp, &pending->objects, struct pv_object, list)
	{
		curr_o = pv_state_fetch_object(current, o->name);
		if (!curr_o) {
			pv_log(DEBUG,
			       "object %s has been added in the pending update",
			       o->name);
			// new objects belonging to bsp require reboot
			if (!o->plat) {
				pv_log(DEBUG, "object belongs to bsp");
				return true;
			}
			// new objects belonging to platforms in certain groups require reboot
			if (pv_state_platform_requires_reboot(o->plat))
				return true;
			// lenient stop of platform and continue
			p = pv_state_fetch_platform(current, o->plat->name);
			if (!p)
				continue;
			if (pv_platform_is_starting(p) ||
			    pv_platform_is_started(p) ||
			    pv_platform_is_ready(p))
				pv_platform_stop(p);
			// set to updated so we can remove it later
			pv_platform_set_updated(p);
		}
	}

	return false;
}

static bool pv_state_compare_jsons(struct pv_state *current,
				   struct pv_state *pending)
{
	struct pv_json *j, *tmp, *pend_j, *curr_j;
	struct pv_platform *p;

	if (!current || !pending)
		return true;

	// search for modified or deleted jsons
	dl_list_for_each_safe(j, tmp, &current->jsons, struct pv_json, list)
	{
		pend_j = pv_state_fetch_json(pending, j->name);
		if (!pend_j || strcmp(j->value, pend_j->value)) {
			pv_log(DEBUG,
			       "json %s has been modified or deleted in the pending update",
			       j->name);
			// changes in jsons belonging to bsp require reboot
			if (!j->plat) {
				pv_log(DEBUG, "json belongs to bsp");
				return true;
			}
			// changes in jsons belonging to platforms in certain groups require reboot
			if (pv_state_platform_requires_reboot(j->plat))
				return true;
			// lenient stop of platform and continue
			if (pv_platform_is_starting(j->plat) ||
			    pv_platform_is_started(j->plat) ||
			    pv_platform_is_ready(j->plat))
				pv_platform_stop(j->plat);
			// set to updated so we can remove it later
			pv_platform_set_updated(j->plat);
		}
	}

	// search for new jsons
	dl_list_for_each_safe(j, tmp, &pending->jsons, struct pv_json, list)
	{
		curr_j = pv_state_fetch_json(current, j->name);
		if (!curr_j) {
			pv_log(DEBUG,
			       "json %s has been added in the pending update",
			       j->name);
			// new jsons belonging to bsp require reboot
			if (!j->plat) {
				pv_log(DEBUG, "json belongs to bsp");
				return true;
			}
			// new jsons belonging to platforms in certain groups require reboot
			if (pv_state_platform_requires_reboot(j->plat))
				return true;
			// lenient stop of platform and continue
			p = pv_state_fetch_platform(current, j->plat->name);
			if (!p)
				continue;
			if (pv_platform_is_starting(p) ||
			    pv_platform_is_started(p) ||
			    pv_platform_is_ready(p))
				pv_platform_stop(p);
			// set to updated so we can remove it later
			pv_platform_set_updated(p);
		}
	}

	return false;
}

// returns: 1 in case a reboot is required because something outside of plat changed
// returns: 0 if all good and no reboot is required
// returns: -1 if there was an error and reboot is mandatory
int pv_state_stop_platforms(struct pv_state *current, struct pv_state *pending)
{
	if (pv_state_compare_jsons(current, pending) ||
	    pv_state_compare_objects(current, pending)) {
		pv_log(INFO,
		       "could not just stop individual platforms for update");
		return 1;
	}

	if (!pv_state_check_all_stopped(current))
		pv_state_force_stop(current);

	if (pv_state_unmount_platforms_volumes(current)) {
		pv_log(ERROR, "could not unmount volumes");
		return -1;
	}

	return 0;
}

static void pv_state_remove_updated_platforms(struct pv_state *s)
{
	struct pv_json *j, *j_tmp;
	struct pv_object *o, *o_tmp;
	struct pv_volume *v, *v_tmp;
	struct pv_platform *p, *p_tmp;

	pv_log(DEBUG,
	       "removing artifacts that belong to stopped platforms from rev %s",
	       s->rev);

	// remove jsons belonging to stopped platforms from state
	dl_list_for_each_safe(j, j_tmp, &s->jsons, struct pv_json, list)
	{
		if (!j->plat || !pv_platform_is_updated(j->plat))
			continue;

		pv_log(DEBUG, "removing json %s that belongs to platform %s",
		       j->name, j->plat->name);
		dl_list_del(&j->list);
		pv_jsons_free(j);
	}

	// remove objects belonging to stopped platforms from state
	dl_list_for_each_safe(o, o_tmp, &s->objects, struct pv_object, list)
	{
		if (!o->plat || !pv_platform_is_updated(o->plat))
			continue;

		pv_log(DEBUG, "removing object %s that belongs to platform %s",
		       o->name, o->plat->name);
		dl_list_del(&o->list);
		pv_object_free(o);
	}

	// remove volumes belonging to stopped platforms from state
	dl_list_for_each_safe(v, v_tmp, &s->volumes, struct pv_volume, list)
	{
		if (!v->plat || !pv_platform_is_updated(v->plat))
			continue;

		pv_log(DEBUG, "removing volume %s that belongs to platform %s",
		       v->name, v->plat->name);
		dl_list_del(&v->list);
		pv_volume_free(v);
	}

	// remove platforms belonging to stopped platforms from state
	dl_list_for_each_safe(p, p_tmp, &s->platforms, struct pv_platform, list)
	{
		if (!pv_platform_is_updated(p))
			continue;

		pv_log(DEBUG, "removing platform %s", p->name);
		dl_list_del(&p->list);
		pv_platform_free(p);
	}
}

static void pv_state_transfer_platforms(struct pv_state *pending,
					struct pv_state *current)
{
	struct pv_json *j, *j_tmp;
	struct pv_object *o, *o_tmp;
	struct pv_volume *v, *v_tmp;
	struct pv_disk *d;
	struct pv_platform *p, *p_tmp;

	pv_log(DEBUG,
	       "transferring artifacts that belong to platforms from rev %s to rev %s",
	       pending->rev, current->rev);

	// transfer jsons belonging to platforms from pending that do not exist in current
	dl_list_for_each_safe(j, j_tmp, &pending->jsons, struct pv_json, list)
	{
		if (!j->plat || pv_state_fetch_platform(current, j->plat->name))
			continue;

		pv_log(DEBUG,
		       "transferring json %s that belongs to platform %s",
		       j->name, j->plat->name);
		dl_list_del(&j->list);
		dl_list_add_tail(&current->jsons, &j->list);
	}

	// transfer objects belonging to platforms from pending that do not exist in current
	dl_list_for_each_safe(o, o_tmp, &pending->objects, struct pv_object,
			      list)
	{
		if (!o->plat || pv_state_fetch_platform(current, o->plat->name))
			continue;

		pv_log(DEBUG,
		       "transferring object %s that belongs to platform %s",
		       o->name, o->plat->name);
		dl_list_del(&o->list);
		dl_list_add_tail(&current->objects, &o->list);
	}

	// transfer volumes belonging to platforms from pending that do not exist in current
	dl_list_for_each_safe(v, v_tmp, &pending->volumes, struct pv_volume,
			      list)
	{
		if (!v->plat || pv_state_fetch_platform(current, v->plat->name))
			continue;

		pv_log(DEBUG,
		       "transferring volume %s that belongs to platform %s",
		       v->name, v->plat->name);
		dl_list_del(&v->list);
		dl_list_add_tail(&current->volumes, &v->list);

		if (v->disk) {
			d = pv_state_fetch_disk(current, v->disk->name);
			pv_log(DEBUG, "relinking volume %s to disk %s", v->name,
			       d->name);
			v->disk = d;
		}
	}

	// transfer platforms belonging to platforms from pending that do not exist in current
	dl_list_for_each_safe(p, p_tmp, &pending->platforms, struct pv_platform,
			      list)
	{
		if (pv_state_fetch_platform(current, p->name))
			continue;

		pv_log(DEBUG, "transferring platform %s", p->name);
		p->state = current;
		dl_list_del(&p->list);
		dl_list_add_tail(&current->platforms, &p->list);
	}
}

static void pv_state_transfer_groups(struct pv_state *current)
{
	struct pv_group *g, *g_tmp;
	struct pv_platform *p, *p_tmp;

	// empty current group revision list
	dl_list_for_each_safe(g, g_tmp, &current->groups, struct pv_group, list)
	{
		pv_group_empty_platform_refs(g);
	}

	// relink platform groups to current groups
	dl_list_for_each_safe(p, p_tmp, &current->platforms, struct pv_platform,
			      list)
	{
		if (!p->group)
			continue;

		g = pv_state_fetch_group(current, p->group->name);
		pv_log(DEBUG, "relinking platform %s to group %s", p->name,
		       g->name);
		pv_group_add_platform(g, p);
	}
}

void pv_state_transition(struct pv_state *pending, struct pv_state *current)
{
	int len = strlen(pending->rev) + 1;

	pv_state_remove_updated_platforms(current);
	pv_state_transfer_platforms(pending, current);
	pv_state_transfer_groups(current);

	// copy revision to current now that we have everything we need from pending
	current->rev = realloc(current->rev, len);
	SNPRINTF_WTRUNC(current->rev, len, "%s", pending->rev);

	pv_state_print(current);
}

state_spec_t pv_state_spec(struct pv_state *s)
{
	return s->spec;
}

static bool pv_state_json_is_dm(struct pv_json *js, jsmntok_t *tokv, int tokc)
{
	char *type = pv_json_get_value(js->value, "type", tokv, tokc);
	if (!type)
		return false;

	bool ret = !strncmp(type, "dm-verity", strlen(type));
	free(type);
	return ret;
}

static char *pv_state_get_object_id(struct dl_list *objects, const char *name)
{
	struct pv_object *obj, *tmp;
	dl_list_for_each_safe(obj, tmp, objects, struct pv_object, list)
	{
		if (!strncmp(obj->name, name, strlen(obj->name)))
			return obj->id;
	}
	return NULL;
}

static char *pv_state_get_formatted_nv_entry(struct dl_list *objects,
					     const char *pname,
					     const char *data_dev,
					     size_t *entry_size)
{
	char *entry = NULL;
	char *obj_name = NULL;
	if (pv_str_fmt_build(&obj_name, "%s/%s", pname, data_dev) < 0)
		return NULL;

	char *id = pv_state_get_object_id(objects, obj_name);
	if (!id)
		goto out;

	int e_size = pv_str_fmt_build(&entry, "%s %s\n", obj_name, id);
	if (e_size < 0)
		goto out;

	*entry_size = e_size;

out:
	if (obj_name)
		free(obj_name);

	return entry;
}

static char *pv_state_add_novalidate_obj(char *nv_list, size_t nv_size,
					 char *entry, size_t entry_size)
{
	char *tmp = realloc(nv_list, entry_size + 1 + nv_size);
	if (!tmp) {
		pv_log(DEBUG, "couldn't allocate nv_list memory");
		return NULL;
	}

	nv_list = tmp;
	memcpy(nv_list + nv_size, entry, entry_size);
	nv_list[nv_size + entry_size] = '\0';

	return nv_list;
}

static char *pv_state_get_novalidate_known_obj(struct dl_list *objects,
					       size_t *nv_size)
{
	const char *obj_exp[] = {
		"bsp/pantavisor",
		"bsp/kernel.img",
		"bsp/fit-image.its",
	};

	char *nv_list = NULL;

	struct pv_object *obj, *obj_tmp;
	dl_list_for_each_safe(obj, obj_tmp, objects, struct pv_object, list)
	{
		char *p = NULL;
		for (int i = 0; i < ARRAY_LEN(obj_exp); ++i) {
			p = strstr(obj->name, obj_exp[i]);
			if (!p)
				continue;

			// to be sure that the found str is at the beginning
			if (p == obj->name)
				break;
		}

		if (!p)
			continue;

		char *entry = NULL;
		int len = pv_str_fmt_build(&entry, "%s %s\n", obj->name,
					    obj->id);

		char *nv_tmp = pv_state_add_novalidate_obj(nv_list, *nv_size,
							   entry, len);
		if (nv_tmp) {
			nv_list = nv_tmp;
			*nv_size += len;
		}

		free(entry);
	}

	return nv_list;
}

/*
 * retrieve a string of all path/objectid pairs that
 * the handler will validate. This will prevent those
 * objects to be checked with a full sha256sum check
 * before starting the platforms.
 */
static char *pv_state_get_novalidate_list(struct pv_state *state)
{
	jsmntok_t *tokv = NULL;
	int tokc = 0;
	char *data_dev = NULL;
	char *entry = NULL;
	size_t nv_size = 0;
	char *nv_list =
		pv_state_get_novalidate_known_obj(&state->objects, &nv_size);

	struct pv_json *js, *js_tmp;
	dl_list_for_each_safe(js, js_tmp, &state->jsons, struct pv_json, list)
	{
		jsmnutil_parse_json(js->value, &tokv, &tokc);

		if (!pv_state_json_is_dm(js, tokv, tokc))
			goto next;

		data_dev =
			pv_json_get_value(js->value, "data_device", tokv, tokc);

		if (!data_dev)
			goto next;

		size_t entry_size = 0;
		entry = pv_state_get_formatted_nv_entry(
			&state->objects, js->plat->name, data_dev, &entry_size);

		if (!entry)
			goto next;

		char *nv_tmp = pv_state_add_novalidate_obj(nv_list, nv_size,
							   entry, entry_size);
		if (nv_tmp) {
			nv_list = nv_tmp;
			nv_size += entry_size;
		}

	next:
		if (tokv) {
			free(tokv);
			tokv = NULL;
			tokc = 0;
		}

		if (data_dev) {
			free(data_dev);
			data_dev = NULL;
		}

		if (entry) {
			free(entry);
			entry = NULL;
		}
	}
	return nv_list;
}

bool pv_state_validate_checksum(struct pv_state *s)
{
	struct pv_object *o;
	struct pv_json *j;
	char *validate_list = NULL;
	bool ret = false;

	if (getenv("pv_quickboot") ||
	    !pv_config_get_bool(PV_SECUREBOOT_CHECKSUM)) {
		pv_log(DEBUG, "state objects and JSONs checksum disabled");
		ret = true;
		goto out;
	}

	validate_list = pv_state_get_novalidate_list(s);

	if (validate_list)
		pv_log(DEBUG, "no validation list: %s", validate_list);

	pv_objects_iter_begin(s, o)
	{
		/* validate instance in $rev/trails/$name to match */
		char needle[PATH_MAX + 67];
		if (snprintf(needle, sizeof(char) * ARRAY_LEN(needle), "%s %s",
			     o->name, o->id) >= ARRAY_LEN(needle)) {
			pv_log(ERROR, "too long filename: for pv state: %zd",
			       strlen(o->name));
			goto out;
		}

		if (validate_list && strstr(validate_list, needle)) {
			pv_log(DEBUG,
			       "skipping validation of object named %s and id=%s",
			       o->name, o->id);
			continue;
		}

		if (!pv_storage_validate_trails_object_checksum(s->rev, o->name,
								o->id)) {
			pv_log(ERROR,
			       "trails object %s with checksum %s failed",
			       o->name, o->id);
			goto out;
		}
	}
	pv_objects_iter_end;

	pv_jsons_iter_begin(s, j)
	{
		if (!pv_storage_validate_trails_json_value(s->rev, j->name,
							   j->value)) {
			pv_log(ERROR, "json %s with value %s failed", j->name,
			       j->value);
			goto out;
		}
	}
	pv_objects_iter_end;

	ret = true;
out:
	if (validate_list)
		free(validate_list);
	return ret;
}

int pv_state_interpret_signal(struct pv_state *s, const char *name,
			      const char *signal, const char *payload)
{
	struct pv_platform *p;

	p = pv_state_fetch_platform(s, name);
	if (!p) {
		pv_log(WARN, "cannot find platform '%s' in state revision '%s'",
		       name, s->rev);
		return -1;
	}

	if (pv_str_matches(signal, strlen(signal), "ready", strlen("ready"))) {
		if (pv_platform_set_ready(p)) {
			pv_log(WARN,
			       "platform '%s' has not status_goal 'ready'",
			       p->name);
			return -1;
		}
	} else {
		pv_log(WARN, "signal '%s' not supported", signal);
		return -1;
	}

	return 0;
}

struct pv_volume *pv_state_search_volume(struct pv_state *s, const char *name)
{
	if (!s)
		return NULL;

	struct pv_volume *v, *tmp;

	dl_list_for_each_safe(v, tmp, &s->volumes, struct pv_volume, list)
	{
		if (pv_str_matches(name, strlen(name), v->name,
				   strlen(v->name)))
			return v;
	}

	return NULL;
}

char *pv_state_get_containers_json(struct pv_state *s)
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, 512);

	pv_json_ser_array(&js);
	{
		struct pv_platform *p, *tmp;

		dl_list_for_each_safe(p, tmp, &s->platforms, struct pv_platform,
				      list)
		{
			pv_platform_add_json(&js, p);
		}

		pv_json_ser_array_pop(&js);
	}

	return pv_json_ser_str(&js);
}

char *pv_state_get_groups_json(struct pv_state *s)
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, 512);

	pv_json_ser_array(&js);
	{
		struct pv_group *g, *tmp_g;

		dl_list_for_each_safe(g, tmp_g, &s->groups, struct pv_group,
				      list)
		{
			pv_group_add_json(&js, g);
		}

		pv_json_ser_array_pop(&js);
	}

	return pv_json_ser_str(&js);
}
