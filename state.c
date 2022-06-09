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

#include "state.h"
#include "drivers.h"
#include "paths.h"
#include "volumes.h"
#include "platforms.h"
#include "objects.h"
#include "jsons.h"
#include "addons.h"
#include "pantavisor.h"
#include "storage.h"
#include "utils/tsh.h"
#include "utils/math.h"
#include "utils/str.h"

#define MODULE_NAME             "state"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static void pv_state_init_groups(struct pv_state *s)
{
	struct pv_group *d = NULL, *r = NULL, *p = NULL, *a = NULL;

	dl_list_init(&s->groups);

	d = pv_group_new("data");
	r = pv_group_new("root");
	p = pv_group_new("platform");
	a = pv_group_new("app");

	if (!d || !r || !p || !a) {
		pv_log(ERROR, "could not create default groups");
		goto err;
	}

	pv_state_add_group(s, d);
	pv_state_add_group(s, r);
	pv_state_add_group(s, p);
	pv_state_add_group(s, a);

	return;

err:
	if (d)
		pv_group_free(d);
	if (r)
		pv_group_free(r);
	if (p)
		pv_group_free(p);
	if (a)
		pv_group_free(a);
}

struct pv_state* pv_state_new(const char *rev, state_spec_t spec)
{
	int len = strlen(rev) + 1;
	struct pv_state *s;

	s = calloc(1, sizeof(struct pv_state));
	if (s) {
		s->rev = calloc(len, sizeof(char));
		SNPRINTF_WTRUNC(s->rev, len, "%s", rev);
		s->spec = spec;
		dl_list_init(&s->platforms);
		dl_list_init(&s->volumes);
		dl_list_init(&s->disks);
		dl_list_init(&s->addons);
		dl_list_init(&s->objects);
		dl_list_init(&s->jsons);
		pv_state_init_groups(s);
		dl_list_init(&s->conditions);
		dl_list_init(&s->bsp.drivers);
		s->local = false;
	}

	return s;
}

static void pv_state_empty_groups(struct pv_state *s)
{
	int num_groups = 0;
	struct pv_group *g, *tmp;
	struct dl_list *groups = &s->groups;

	// Iterate over all groups from state
	dl_list_for_each_safe(g, tmp, groups,
            struct pv_group, list) {
		dl_list_del(&g->list);
		pv_group_free(g);
		num_groups++;
	}

	pv_log(INFO, "removed %d groups", num_groups);
}

static void pv_state_empty_conditions(struct pv_state *s)
{
	int num_conditions = 0;
	struct pv_condition *c, *tmp;
	struct dl_list *conditions = &s->conditions;

	// Iterate over all conditions from state
	dl_list_for_each_safe(c, tmp, conditions,
            struct pv_condition, list) {
		dl_list_del(&c->list);
		pv_condition_free(c);
		num_conditions++;
	}

	pv_log(INFO, "removed %d conditions", num_conditions);
}

void pv_state_free(struct pv_state *s)
{
	if (!s)
		return;

	pv_log(INFO, "removing state with revision %s", s->rev);

	if (s->rev)
		free(s->rev);
	if (!s->bsp.img.std.initrd) {
		if (s->bsp.img.ut.fit)
			free(s->bsp.img.ut.fit);
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
	pv_disks_empty(s);
	pv_addons_empty(s);
	pv_objects_empty(s);
	pv_jsons_empty(s);
	pv_state_empty_groups(s);
	pv_state_empty_conditions(s);

	if (s->json)
		free(s->json);

	free(s);
}

void pv_state_add_group(struct pv_state *s, struct pv_group *g)
{
	pv_log(DEBUG, "adding group %s to state", g->name);

	dl_list_init(&g->list);
	dl_list_add_tail(&s->groups, &g->list);
}

void pv_state_add_condition(struct pv_state *s, struct pv_condition *c)
{
	pv_log(DEBUG, "adding condition %s to state", c->key);

	dl_list_init(&c->list);
	dl_list_add_tail(&s->conditions, &c->list);
}

struct pv_group* pv_state_fetch_group(struct pv_state *s, const char *name)
{
	struct pv_group *g, *tmp;

	if (!name)
		return NULL;

	// Iterate over all groups from state
	dl_list_for_each_safe(g, tmp, &s->groups,
            struct pv_group, list) {
		if (pv_str_matches(g->name, strlen(g->name), name, strlen(name)))
			return g;
	}

	return NULL;
}

struct pv_platform* pv_state_fetch_platform(struct pv_state *s, const char *name)
{
	struct pv_platform *p, *tmp;

	if (!name)
		return NULL;

	// Iterate over all platforms from state
	dl_list_for_each_safe(p, tmp, &s->platforms,
            struct pv_platform, list) {
		if (pv_str_matches(p->name, strlen(p->name), name, strlen(name)))
			return p;
	}

	return NULL;
}

struct pv_object* pv_state_fetch_object(struct pv_state *s, const char *name)
{
	struct pv_object *o, *tmp;

	if (!name)
		return NULL;

	// Iterate over all objects from state
	dl_list_for_each_safe(o, tmp, &s->objects,
            struct pv_object, list) {
		if (pv_str_matches(o->name, strlen(o->name), name, strlen(name)))
			return o;
	}

	return NULL;
}

struct pv_json* pv_state_fetch_json(struct pv_state *s, const char *name)
{
	struct pv_json *j, *tmp;

	if (!name)
		return NULL;

	// Iterate over all groups from state
	dl_list_for_each_safe(j, tmp, &s->jsons,
            struct pv_json, list) {
		if (pv_str_matches(j->name, strlen(j->name), name, strlen(name)))
			return j;
	}

	return NULL;
}

struct pv_condition* pv_state_fetch_condition_value(struct pv_state *s,
	const char *plat,
	const char *key,
	const char *eval_value)
{
	struct pv_condition *c, *tmp;

	if (!plat || !key || !eval_value)
		return NULL;

	// Iterate over all conditions from state
	dl_list_for_each_safe(c, tmp, &s->conditions,
            struct pv_condition, list) {
		if (pv_str_matches(c->plat, strlen(c->plat), plat, strlen(plat)) &&
			pv_str_matches(c->key, strlen(c->key), key, strlen(key)) &&
			pv_str_matches(c->eval_value, strlen(c->eval_value), eval_value, strlen(eval_value)))
			return c;
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
	dl_list_for_each_safe(g, tmp_g, groups,
			struct pv_group, list) {
		pv_log(DEBUG, " group: '%s'", g->name);
	}
	struct pv_platform *p, *tmp_p;
    struct dl_list *platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp_p, platforms,
			struct pv_platform, list) {
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
	dl_list_for_each_safe(v, tmp_v, volumes,
			struct pv_volume, list) {
		pv_log(DEBUG, " volume: '%s'", v->name);
		pv_log(DEBUG, "  type: %d", v->type);
		if (v->plat)
			pv_log(DEBUG, "  platform: '%s'", v->plat->name);
	}
	struct pv_addon *a, *tmp_a;
	struct dl_list *addons = &s->addons;
	dl_list_for_each_safe(a, tmp_a, addons,
			struct pv_addon, list) {
		pv_log(DEBUG, " addon: '%s'", a->name);
	}
	struct pv_object *curr;
	pv_objects_iter_begin(s, curr) {
		pv_log(DEBUG, " object: '%s'", curr->name);
		pv_log(DEBUG, "  id: '%s'", curr->id);
		if (curr->plat)
			pv_log(DEBUG, "  platform: '%s'", curr->plat->name);
	}
	pv_objects_iter_end;
	struct pv_json *j, *tmp_j;
	struct dl_list *jsons = &s->jsons;
	dl_list_for_each_safe(j, tmp_j, jsons,
			struct pv_json, list) {
		pv_log(DEBUG, " json: '%s'", j->name);
		if (j->plat)
			pv_log(DEBUG, "  platform: '%s'", j->plat->name);
	}
}

static void pv_state_set_default_groups(struct pv_state *s)
{
	bool root_configured = false;
	struct pv_platform *p, *tmp, *first_p = NULL;
	struct dl_list *platforms = &s->platforms;
	struct pv_group *r, *d;

	if (dl_list_empty(platforms))
		return;

	r = pv_state_fetch_group(s, "root");
	d = pv_state_fetch_group(s, "platform");
	if (!r || !d) {
		pv_log(ERROR, "could not find group root or platform");
		return;
	}

	dl_list_for_each_safe(p, tmp, platforms,
			struct pv_platform, list) {
		// check if any platform has been configured in group root
		if (p->group == r)
			root_configured = true;
		// get first unconfigured platform
		if (!first_p && (p->group == NULL))
			first_p = p;
	}

	// if not, set first platform in group root
	if (!root_configured && first_p) {
		pv_log(WARN, "no platform was found in root group, "
				"so the first unconfigured one in alphabetical order will be set");
		first_p->group = r;
	}

	// set rest of the non configured platforms in group platform
	platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp, platforms,
            struct pv_platform, list) {
		if (p->group == NULL)
			p->group = d;
    }
}

static void pv_state_set_default_conditions_group(struct pv_state *s,
		struct pv_group *dependee,
		struct pv_group *dependent,
		const char *status)
{
	struct pv_platform *p_de, *p_dt, *tmp_de, *tmp_dt;
	struct pv_condition *c;

	dl_list_for_each_safe(p_de, tmp_de, &s->platforms,
            struct pv_platform, list) {
		if (p_de->group != dependee)
			continue;

		c = pv_state_fetch_condition_value(s, p_de->name, "status", status);
		if (!c) {
			c = pv_condition_new(p_de->name, "status", status);
			if (!c) {
				pv_log(ERROR, "could not create a new condition");
				return;
			}
			pv_state_add_condition(s, c);
		}

		dl_list_for_each_safe(p_dt, tmp_dt, &s->platforms,
				struct pv_platform, list) {
			if (p_dt->group != dependent)
				continue;

			pv_platform_add_condition(p_dt, c);
		}
	}
}

static void pv_state_set_default_conditions(struct pv_state *s)
{
	struct pv_group *d = NULL, *r = NULL, *p = NULL, *a = NULL;

	d = pv_state_fetch_group(s, "data");
	r = pv_state_fetch_group(s, "root");
	p = pv_state_fetch_group(s, "platform");
	a = pv_state_fetch_group(s, "app");

	if (!d || !r || !p || !a) {
		pv_log(ERROR, "could not find group data, root, platform or app");
		return;
	}

	// set every one to depend on data
	pv_state_set_default_conditions_group(s, d, r, "MOUNTED");
	pv_state_set_default_conditions_group(s, d, p, "MOUNTED");
	pv_state_set_default_conditions_group(s, d, a, "MOUNTED");

	// set platform and apps to depend on root
	pv_state_set_default_conditions_group(s, r, p, "STARTED");
	pv_state_set_default_conditions_group(s, r, a, "STARTED");

	// set app to depend on platform
	pv_state_set_default_conditions_group(s, p, a, "STARTED");

	// set state depend on app
	pv_state_set_default_conditions_group(s, a, NULL, "STARTED");
}

void pv_state_validate(struct pv_state *s)
{
	// remove platforms that have no loaded data
	pv_platforms_remove_not_installed(s);
	// add loggers for all platforms
	pv_platforms_add_all_loggers(s);
	// set groups for all undefined platforms
	pv_state_set_default_groups(s);
	// set conditions to honor runlevel order
	pv_state_set_default_conditions(s);
}

static int pv_state_mount_bsp_volumes(struct pv_state *s)
{
	struct pv_volume *v, *tmp;

	dl_list_for_each_safe(v, tmp, &s->volumes,
			struct pv_volume, list) {
		if (!v->plat)
			if (pv_volume_mount(v))
				return -1;
	}

	return pv_volumes_mount_firmware_modules();
}

int pv_state_start(struct pv_state *s)
{
	return pv_state_mount_bsp_volumes(s);
}

static int pv_state_start_platform(struct pv_state *s, struct pv_platform *p)
{
	struct pv_volume *v, *tmp;

	dl_list_for_each_safe(v, tmp, &s->volumes,
			struct pv_volume, list) {
		if (v->plat == p)
			if (pv_volume_mount(v)) {
				pv_log(ERROR, "volume %s could not be mounted", v->name);
				return -1;
			}
	}

	pv_platform_set_mounted(p);

	if (pv_str_matches(p->group->name, strlen(p->group->name), "data", strlen("data")))
		return 0;

	if (pv_platform_load_drivers(p, NULL, DRIVER_REQUIRED | DRIVER_OPTIONAL) < 0) {
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

	dl_list_for_each_safe(p, tmp_p, &s->platforms,
		struct pv_platform, list) {
		if (pv_platform_is_ready(p) || pv_platform_is_blocked(p)) {
			if (pv_platform_check_conditions(p))
				ret = pv_state_start_platform(s, p);
			else
				pv_platform_set_blocked(p);
		} else if (pv_platform_is_starting(p)) {
			if (!pv_platform_check_running(p))
				pv_log(DEBUG, "platform %s still not running", p->name);
		} else if (pv_platform_is_started(p)) {
			if (!pv_platform_check_running(p)) {
				pv_log(ERROR, "platform %s suddenly stopped", p->name);
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
				struct pv_platform, list) {
			if (pv_platform_is_stopping(p)) {
				if (pv_platform_check_running(p)) {
					pv_log(DEBUG, "platform %s still running", p->name);
					try_again = true;
					ret = false;
				}
			}
		}

		if (!try_again)
			break;

		pv_log(DEBUG, "some platforms are still running. Trying again in 1 second...");

		sleep(1);
		try_again = false;
	}

	return ret;
}

static void pv_state_lenient_stop(struct pv_state *s)
{
	struct pv_platform *p, *tmp_p;

	dl_list_for_each_safe(p, tmp_p, &s->platforms,
			struct pv_platform, list) {
		if (pv_platform_is_starting(p) || pv_platform_is_started(p))
			pv_platform_stop(p);
	}
}

static void pv_state_force_stop(struct pv_state *s)
{
	struct pv_platform *p, *tmp_p;

	dl_list_for_each_safe(p, tmp_p, &s->platforms,
			struct pv_platform, list) {
		if (pv_platform_is_stopping(p))
			pv_platform_force_stop(p);
	}
}

static int pv_state_unmount_platform_volumes(struct pv_state *s, struct pv_platform *p)
{
	int ret = 0;
	struct pv_volume *v, *tmp_v;

	dl_list_for_each_safe(v, tmp_v, &s->volumes,
			struct pv_volume, list) {
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
	dl_list_for_each_safe(p, tmp_p, &s->platforms,
			struct pv_platform, list) {
		if (!(pv_platform_is_stopping(p) ||
			pv_platform_is_starting(p) ||
			pv_platform_is_started(p))) {
			if (pv_state_unmount_platform_volumes(s, p))
				ret = -1;
		}
	}

	return ret;
}

int pv_state_stop(struct pv_state *s)
{
	int ret = 0;

	if (s == NULL)
		return -1;

	pv_log(DEBUG, "stopping state %s", s->rev);

	pv_state_lenient_stop(s);

	if (!pv_state_check_all_stopped(s)) {
		pv_state_force_stop(s);
		ret = -1;
	}

	// unmount all platform related volumes
	if (pv_state_unmount_platforms_volumes(s))
		ret = -1;

	// unmount bsp volumes
	if (pv_state_unmount_platform_volumes(s, NULL))
		ret = -1;

	return ret;
}

static bool pv_state_group_requires_reboot(struct pv_group *g)
{
	int len;
	char *name;

	if (!g || !g->name)
		return true;

	name = g->name;
	len = strlen(name);

	// some groups need reboot to keep backwards compatibility with runlevel behavior
	if (pv_str_matches(name, len, "data", strlen("data")) ||
		pv_str_matches(name, len, "root", strlen("root")) ||
		pv_str_matches(name, len, "platform", strlen("platform"))) {
		return true;
	}

	return false;
}

static bool pv_state_compare_objects(struct pv_state *current, struct pv_state *pending)
{
	struct pv_object *o, *tmp, *pend_o, *curr_o;
	struct pv_platform *p;

	if (!current || !pending)
		return true;

	// search for modified or deleted objects
	dl_list_for_each_safe(o, tmp, &current->objects,
			struct pv_object, list) {
		pend_o = pv_state_fetch_object(pending, o->name);
		if (!pend_o || strcmp(o->id, pend_o->id)) {
			pv_log(DEBUG, "object %s has been modified or deleted in the pending update",
				o->name);
			// changes in objects belonging to bsp require reboot
			if (!o->plat) {
				pv_log(DEBUG, "object belongs to bsp");
				return true;
			}
			// changes in objects belonging to platforms in certain groups require reboot
			if (o->plat->group && pv_state_group_requires_reboot(o->plat->group)) {
				pv_log(DEBUG, "object belongs to platform %s in group %s",
					o->plat->name, o->plat->group->name);
				return true;
			}
			// lenient stop of platform and continue
			if (pv_platform_is_starting(o->plat) || pv_platform_is_started(o->plat))
				pv_platform_stop(o->plat);
			// set to updated so we can remove it later
			pv_platform_set_updated(o->plat);
		}
	}

	// search for new objects
	dl_list_for_each_safe(o, tmp, &pending->objects,
			struct pv_object, list) {
		curr_o = pv_state_fetch_object(current, o->name);
		if (!curr_o) {
			pv_log(DEBUG, "object %s has been added in the pending update", o->name);
			// new objects belonging to bsp require reboot
			if (!o->plat) {
				pv_log(DEBUG, "object belongs to bsp");
				return true;
			}
			// new objects belonging to platforms in certain groups require reboot
			if (o->plat->group && pv_state_group_requires_reboot(o->plat->group)) {
				pv_log(DEBUG, "object belongs to platform %s in group %s",
					o->plat->name, o->plat->group->name);
				return true;
			}
			// lenient stop of platform and continue
			p = pv_state_fetch_platform(current, o->plat->name);
			if (!p)
				continue;
			if (pv_platform_is_starting(p) || pv_platform_is_started(p))
				pv_platform_stop(p);
			// set to updated so we can remove it later
			pv_platform_set_updated(p);
		}
	}

	return false;
}

static bool pv_state_compare_jsons(struct pv_state *current, struct pv_state *pending)
{
	struct pv_json *j, *tmp, *pend_j, *curr_j;
	struct pv_platform *p;

	if (!current || !pending)
		return true;

	// search for modified or deleted jsons
	dl_list_for_each_safe(j, tmp, &current->jsons,
			struct pv_json, list) {
		pend_j = pv_state_fetch_json(pending, j->name);
		if (!pend_j || strcmp(j->value, pend_j->value)) {
			pv_log(DEBUG, "json %s has been modified or deleted in the pending update",
				j->name);
			// changes in jsons belonging to bsp require reboot
			if (!j->plat) {
				pv_log(DEBUG, "json belongs to bsp");
				return true;
			}
			// changes in jsons belonging to platforms in certain groups require reboot
			if (j->plat->group && pv_state_group_requires_reboot(j->plat->group)) {
				pv_log(DEBUG, "json belongs to platform %s in group %s",
					j->plat->name, j->plat->group->name);
				return true;
			}
			// lenient stop of platform and continue
			if (pv_platform_is_starting(j->plat) || pv_platform_is_started(j->plat))
				pv_platform_stop(j->plat);
			// set to updated so we can remove it later
			pv_platform_set_updated(j->plat);
		}
	}

	// search for new jsons
	dl_list_for_each_safe(j, tmp, &pending->jsons,
			struct pv_json, list) {
		curr_j = pv_state_fetch_json(current, j->name);
		if (!curr_j) {
			pv_log(DEBUG, "json %s has been added in the pending update", j->name);
			// new jsons belonging to bsp require reboot
			if (!j->plat) {
				pv_log(DEBUG, "json belongs to bsp");
				return true;
			}
			// new jsons belonging to platforms in certain groups require reboot
			if (j->plat->group && pv_state_group_requires_reboot(j->plat->group)) {
				pv_log(DEBUG, "json belongs to platform %s in group %s",
					j->plat->name, j->plat->group->name);
				return true;
			}
			// lenient stop of platform and continue
			p = pv_state_fetch_platform(current, j->plat->name);
			if (!p)
				continue;
			if (pv_platform_is_starting(p) || pv_platform_is_started(p))
				pv_platform_stop(p);
			// set to updated so we can remove it later
			pv_platform_set_updated(p);
		}
	}

	return false;
}

int pv_state_stop_platforms(struct pv_state *current, struct pv_state *pending)
{
	if (pv_state_compare_jsons(current, pending) ||
		pv_state_compare_objects(current, pending)) {
		pv_log(INFO, "could not just stop individual platforms for update");
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

	pv_log(DEBUG, "removing artifacts that belong to stopped platforms from rev %s",
		s->rev);

	// remove jsons belonging to stopped platforms from state
	dl_list_for_each_safe(j, j_tmp, &s->jsons,
			struct pv_json, list) {
		if (!j->plat || !pv_platform_is_updated(j->plat))
			continue;

		pv_log(DEBUG, "removing json %s that belongs to platform %s",
			j->name, j->plat->name);
		dl_list_del(&j->list);
		pv_jsons_free(j);
	}

	// remove objects belonging to stopped platforms from state
	dl_list_for_each_safe(o, o_tmp, &s->objects,
			struct pv_object, list) {
		if (!o->plat || !pv_platform_is_updated(o->plat))
			continue;

		pv_log(DEBUG, "removing object %s that belongs to platform %s",
			o->name, o->plat->name);
		dl_list_del(&o->list);
		pv_object_free(o);
	}

	// remove volumes belonging to stopped platforms from state
	dl_list_for_each_safe(v, v_tmp, &s->volumes,
			struct pv_volume, list) {
		if (!v->plat || !pv_platform_is_updated(v->plat))
			continue;

		pv_log(DEBUG, "removing volume %s that belongs to platform %s",
			v->name, v->plat->name);
		dl_list_del(&v->list);
		pv_volume_free(v);
	}

	// remove platforms belonging to stopped platforms from state
	dl_list_for_each_safe(p, p_tmp, &s->platforms,
			struct pv_platform, list) {
		if (!pv_platform_is_updated(p))
			continue;

		pv_log(DEBUG, "removing platform %s", p->name);
		dl_list_del(&p->list);
		pv_platform_free(p);
	}
}

static void pv_state_transfer_platforms(struct pv_state *pending, struct pv_state *current)
{
	struct pv_json *j, *j_tmp;
	struct pv_object *o, *o_tmp;
	struct pv_volume *v, *v_tmp;
	struct pv_platform *p, *p_tmp;

	pv_log(DEBUG, "transferring artifacts that belong to platforms from rev %s to rev %s",
		pending->rev, current->rev);

	// transfer jsons belonging to platforms from pending that do not exist in current
	dl_list_for_each_safe(j, j_tmp, &pending->jsons,
		struct pv_json, list) {
		if (!j->plat || pv_state_fetch_platform(current, j->plat->name))
			continue;

		pv_log(DEBUG, "transferring json %s that belongs to platform %s",
			j->name, j->plat->name);
		dl_list_del(&j->list);
		dl_list_add_tail(&current->jsons, &j->list);
	}

	// transfer objects belonging to platforms from pending that do not exist in current
	dl_list_for_each_safe(o, o_tmp, &pending->objects,
		struct pv_object, list) {
		if (!o->plat || pv_state_fetch_platform(current, o->plat->name))
			continue;

		pv_log(DEBUG, "transferring object %s that belongs to platform %s",
			o->name, o->plat->name);
		dl_list_del(&o->list);
		dl_list_add_tail(&current->objects, &o->list);
	}

	// transfer volumes belonging to platforms from pending that do not exist in current
	dl_list_for_each_safe(v, v_tmp, &pending->volumes,
		struct pv_volume, list) {
		if (!v->plat || pv_state_fetch_platform(current, v->plat->name))
			continue;

		pv_log(DEBUG, "transferring volume %s that belongs to platform %s",
			v->name, v->plat->name);
		dl_list_del(&v->list);
		dl_list_add_tail(&current->volumes, &v->list);
	}

	// transfer platforms belonging to platforms from pending that do not exist in current
	dl_list_for_each_safe(p, p_tmp, &pending->platforms,
		struct pv_platform, list) {
		if (pv_state_fetch_platform(current, p->name))
			continue;

		pv_log(DEBUG, "transferring platform %s", p->name);
		p->state = current;
		dl_list_del(&p->list);
		dl_list_add_tail(&current->platforms, &p->list);
	}
}

static void pv_state_transfer_groups(struct pv_state *pending, struct pv_state *current)
{
	struct pv_platform *p, *tmp;
	struct pv_group *g;

	// relink platform groups to current groups
	dl_list_for_each_safe(p, tmp, &current->platforms,
			struct pv_platform, list) {
		if (!p->group)
			continue;

		g = pv_state_fetch_group(current, p->group->name);
		pv_log(DEBUG, "relinking platform %s to group %s", p->name, g->name);
		p->group = g;
	}
}

static void pv_state_transfer_conditions(struct pv_state *pending, struct pv_state *current)
{
	struct pv_condition *c, *tmp_c, *curr_c;
	struct pv_condition_ref *cr, *tmp_cr;
	struct pv_platform *p, *tmp_p;

	// remove removed conditions from current
	dl_list_for_each_safe(c, tmp_c, &current->conditions,
			struct pv_condition, list) {
		if (!pv_state_fetch_condition_value(pending, c->plat, c->key, c->eval_value)) {
			pv_log(DEBUG, "removing condition %s unused in pending state", c->key);
			dl_list_del(&c->list);
			pv_condition_free(c);
		}
	}

	// move new conditions to current
	dl_list_for_each_safe(c, tmp_c, &pending->conditions,
			struct pv_condition, list) {
		if (!pv_state_fetch_condition_value(current, c->plat, c->key, c->eval_value)) {
			pv_log(DEBUG, "adding new condition %s from pending state", c->key);
			dl_list_del(&c->list);
			dl_list_add_tail(&current->conditions, &c->list);
		}
	}

	// relink platform conditions to current groups
	dl_list_for_each_safe(p, tmp_p, &current->platforms,
			struct pv_platform, list) {
		dl_list_for_each_safe(cr, tmp_cr, &p->condition_refs,
				struct pv_condition_ref, list) {
			curr_c = pv_state_fetch_condition_value(current,
				cr->ref->plat,
				cr->ref->key,
				cr->ref->eval_value);
			pv_log(DEBUG, "relinking condition %s to platform %s", curr_c->key, p->name);
			cr->ref = curr_c;
		}
	}
}

void pv_state_transition(struct pv_state *pending, struct pv_state *current)
{
	int len = strlen(pending->rev) + 1;

	pv_state_remove_updated_platforms(current);
	pv_state_transfer_platforms(pending, current);
	pv_state_transfer_groups(pending, current);
	pv_state_transfer_conditions(pending, current);

	// copy revision to current now that we have everything we need from pending
	current->rev = realloc(current->rev, len);
	SNPRINTF_WTRUNC(current->rev, len, "%s", pending->rev);

	pv_state_print(current);
}

state_spec_t pv_state_spec(struct pv_state *s)
{
	return s->spec;
}

/*
 * retrieve a string of all path/objectid pairs that
 * the handler will validate. This will prevent those
 * objects to be checked with a full sha256sum check
 * before starting the platforms.
 */
static char* _pv_state_get_novalidate_list(char *rev)
{
#define _pv_bufsize_1 (1288 * 1024)
#define _cmd_fmt " novalidatelist %s"
	char rev_path[PATH_MAX], hdl_path[PATH_MAX];
	char sout[_pv_bufsize_1] = {0}, serr[_pv_bufsize_1] = {0};
	char *_sout = sout, *_serr = serr;
	char *result = NULL;
	int res;
	char *cmd = NULL;
	struct dirent *dp;
	DIR *volmountdir = opendir("/lib/pv/volmount/verity");

	// Unable to open directory stream
	if (!volmountdir)
		goto out;

	while ((dp = readdir(volmountdir)) != NULL) {
		struct stat st;

		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;

		pv_paths_storage_trail(rev_path, PATH_MAX, rev);
		pv_paths_lib_volmount(hdl_path, PATH_MAX, "verity", dp->d_name);
		if(stat (hdl_path, &st)) {
			pv_log(WARN, "illegal handler file %s, error=%s", hdl_path, strerror(errno));
			goto out;
		}

		// if not executable, we let it pass ...
		if (!(st.st_mode & S_IXUSR))
			continue;

		// now we make the cmd for the volmount handler. every handler is expected
		// to implement a novalidatelist subcommand; if not relevant the handler
		// shall return an empty result...
		int len = (ARRAY_LEN(_cmd_fmt) + strlen(hdl_path) + strlen(rev_path) + 2);
		cmd = realloc(cmd, len * sizeof(char));
		int len_o = snprintf(cmd, sizeof(char) * len, "%s "_cmd_fmt, hdl_path, rev_path);
		if (len_o >= len) {
			pv_log(WARN, "illegal handler command (cut off): %s - %s", cmd, strerror(errno));
			goto out;
		}

		// now we run that handler cmd with 20 seconds timeout ...
		res = tsh_run_output(cmd, 20, _sout, _pv_bufsize_1 - 1, _serr, _pv_bufsize_1 - 1);

		if (res < 0) {
			pv_log(WARN, "error running novalidatelist command (%s): %s", cmd, strerror(errno));
			continue;
		}

		// if command fails, we dont abort as some handlers might be buggy ...
		// we just ignore the result of this handler ...
		if (res > 0) {
			pv_log(WARN, "command exited with error code: %d", res);
			pv_log(DEBUG, "stdout: %s", sout);
			pv_log(DEBUG, "stderr: %s", serr);
			continue;
		}

		if (strlen(serr) > 0)
			pv_log(WARN, "get_novalidatelist stderr output: %s", serr);

		_sout += strlen(_sout);
		*_sout = ' ';
		_sout++;
		*_sout = 0;
	}

	result = strndup(sout, _pv_bufsize_1 - 1);;
 out:
	if (volmountdir)
		closedir(volmountdir);
	if (cmd)
		free(cmd);
	return result;
}

bool pv_state_validate_checksum(struct pv_state *s)
{
	struct pv_object *o;
	struct pv_json *j;

	char *validate_list = _pv_state_get_novalidate_list(s->rev);
	if (validate_list)
		pv_log(DEBUG, "no validation list is: %s", validate_list);

	pv_objects_iter_begin(s, o) {
		/* validate instance in $rev/trails/$name to match */
		char needle[PATH_MAX + 67];
		if (snprintf(needle, sizeof(char) * ARRAY_LEN(needle), "%s %s", o->name, o->id) >= ARRAY_LEN(needle)) {
			pv_log(ERROR, "too long filename: for pv state: %d", strlen(o->name));
			return false;
		}

		if (validate_list && strstr(validate_list, needle)) {
			pv_log(DEBUG, "skipping validation of object named %s and id=%s", o->name, o->id);
			continue;
		}


		if (!pv_storage_validate_trails_object_checksum(s->rev, o->name, o->id)) {
			pv_log(ERROR, "trails object %s with checksum %s failed", o->name, o->id);
			return false;
		}
	}
	pv_objects_iter_end;

	pv_jsons_iter_begin(s, j) {
		if (!pv_storage_validate_trails_json_value(s->rev, j->name, j->value)) {
			pv_log(ERROR, "json %s with value %s failed", j->name, j->value);
			return false;
		}
	}
	pv_objects_iter_end;

	return true;
}

int pv_state_report_condition(struct pv_state *s, const char *plat, const char *key, const char *value)
{
	struct pv_condition *c, *tmp;

	pv_log(DEBUG, "condition from platform '%s' reported with key '%s' and value '%s'",
		plat, key, value);

	// Iterate over all conditions from state
	dl_list_for_each_safe(c, tmp, &s->conditions,
            struct pv_condition, list) {
		if ((pv_str_matches(c->plat, strlen(c->plat), plat, strlen(plat)) ||
			pv_str_matches(c->plat, strlen(c->plat), "*", strlen("*"))) &&
			pv_str_matches(c->key, strlen(c->key), key, strlen(key))) {
			pv_condition_set_value(c, value);
			pv_log(DEBUG, "reported condition updated with new value");
		}
	}

	return 0;
}

bool pv_state_check_conditions(struct pv_state *s)
{
	struct pv_condition *c, *tmp;

	if (!s)
		return false;

	if (dl_list_empty(&s->conditions))
		goto out;

	dl_list_for_each_safe(c, tmp, &s->conditions,
			struct pv_condition, list) {
		if (!pv_condition_check(c))
			return false;
	}

out:
	return true;
}

char* pv_state_get_containers_json(struct pv_state *s)
{
	int len = 1, line_len;
	char *json = calloc(len + 1, sizeof(char)), *line;
	struct pv_platform *p, *tmp;

	// open json
	json[0]='[';

	if (dl_list_empty(&s->platforms))
		goto close;

	dl_list_for_each_safe(p, tmp, &s->platforms,
			struct pv_platform, list) {
		line = pv_platform_get_json(p);
		line_len = strlen(line) + 1;
		json = realloc(json, len + line_len + 1);
		SNPRINTF_WTRUNC(&json[len], line_len + 1, "%s,", line);
		len += line_len;
		free(line);
	}

	// remove ,
	len--;

close:
	// close json
	json = realloc(json, len + 2);
	json[len] = ']';
	json[len + 1] = '\0';

	return json;
}

char* pv_state_get_conditions_json(struct pv_state *s)
{
	int len = 1, line_len;
	char *json = calloc(len + 1, sizeof(char)), *line;
	struct pv_condition *c, *tmp;

	// open json
	json[0]='[';

	if (dl_list_empty(&s->groups))
		goto close;

	dl_list_for_each_safe(c, tmp, &s->conditions,
			struct pv_condition, list) {
		line = pv_condition_get_json(c);
		line_len = strlen(line) + 1;
		json = realloc(json, len + line_len + 1);
		SNPRINTF_WTRUNC(&json[len], line_len + 1, "%s,", line);
		len += line_len;
		free(line);
	}

	// remove ,
	len--;

close:
	// close json
	json = realloc(json, len + 2);
	json[len] = ']';
	json[len + 1] = '\0';

	return json;
}
