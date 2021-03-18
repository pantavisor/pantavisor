/*
 * Copyright (c) 2020 Pantacor Ltd.
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

#include "state.h"
#include "volumes.h"
#include "platforms.h"
#include "objects.h"
#include "jsons.h"
#include "addons.h"
#include "pantavisor.h"

#define MODULE_NAME             "state"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

struct pv_state* pv_state_new(char *rev, state_spec_t spec)
{
	struct pv_state *s;

	s = calloc(1, sizeof(struct pv_state));
	if (s) {
		strncpy(s->rev, rev, strlen(rev));
		s->spec = spec;
		dl_list_init(&s->platforms);
		dl_list_init(&s->volumes);
		dl_list_init(&s->addons);
		dl_list_init(&s->objects);
		dl_list_init(&s->jsons);
	}

	return s;
}

void pv_state_free(struct pv_state *s)
{
	if (!s)
		return;

	pv_log(INFO, "removing state with revision %s", s->rev);

	if (s->bsp.kernel)
		free(s->bsp.kernel);
	if (s->bsp.fdt)
		free(s->bsp.fdt);
	if (s->bsp.firmware)
		free(s->bsp.firmware);
	if (s->bsp.modules)
		free(s->bsp.modules);
	if (s->bsp.initrd)
		free(s->bsp.initrd);

	pv_platforms_empty(s);
	pv_volumes_empty(s);
	pv_addons_empty(s);
	pv_objects_empty(s);
	pv_jsons_empty(s);

	if (s->json)
		free(s->json);

	free(s);
}

static void pv_state_transfer_platforms(struct pv_state *in, struct pv_state *out, int runlevel)
{
	struct pv_platform *p, *p_tmp;
	struct dl_list *platforms;

	// remove existing platforms from out
	platforms = &out->platforms;
	dl_list_for_each_safe(p, p_tmp, platforms,
		struct pv_platform, list) {
		if (p->runlevel < runlevel)
			continue;

		pv_log(DEBUG, "removing platform %s from rev %s", p->name, out->rev);
		dl_list_del(&p->list);
		pv_platform_free(p);
	}

	// transfer existing platforms from in to out
	platforms = &in->platforms;
	dl_list_for_each_safe(p, p_tmp, platforms,
		struct pv_platform, list) {
		if (p->runlevel < runlevel)
			continue;

		pv_log(DEBUG, "transferring platform %s from rev %s to rev %s", p->name, in->rev, out->rev);
		dl_list_del(&p->list);
		dl_list_add_tail(&out->platforms, &p->list);
	}
}

static void pv_state_transfer_volumes(struct pv_state *in, struct pv_state *out, int runlevel)
{
	struct pv_volume *v, *v_tmp;
	struct dl_list *volumes;

	// remove existing volumes from out
	volumes = &out->volumes;
	dl_list_for_each_safe(v, v_tmp, volumes,
		struct pv_volume, list) {
		if (!v->plat || (v->plat->runlevel < runlevel))
			continue;

		pv_log(DEBUG, "removing volume %s linked to platform %s from rev %s", v->name, v->plat->name, out->rev);
		dl_list_del(&v->list);
		pv_volume_free(v);
	}

	// transfer existing volumes from in to out
	volumes = &in->volumes;
	dl_list_for_each_safe(v, v_tmp, volumes,
		struct pv_volume, list) {
		if (!v->plat || (v->plat->runlevel < runlevel))
			continue;

		pv_log(DEBUG, "transferring volume %s linked to platform %s from rev %s to rev %s", v->name, v->plat->name, in->rev, out->rev);
		dl_list_del(&v->list);
		dl_list_add_tail(&out->volumes, &v->list);
	}
}

static void pv_state_transfer_jsons(struct pv_state *in, struct pv_state *out, int runlevel)
{
	struct pv_json *j, *j_tmp;
	struct dl_list *jsons;

	// remove existing jsons from out
	jsons = &out->jsons;
	dl_list_for_each_safe(j, j_tmp, jsons,
		struct pv_json, list) {
		if (!j->plat || (j->plat->runlevel < runlevel))
			continue;

		pv_log(DEBUG, "removing json %s linked to platform %s from rev %s", j->name, j->plat->name, out->rev);
		dl_list_del(&j->list);
		pv_json_free(j);
	}

	// transfer existing json from in to out
	jsons = &in->jsons;
	dl_list_for_each_safe(j, j_tmp, jsons,
		struct pv_json, list) {
		if (!j->plat || (j->plat->runlevel < runlevel))
			continue;

		pv_log(DEBUG, "transferring json %s linked to platform %s from rev %s to rev %s", j->name, j->plat->name, in->rev, out->rev);
		dl_list_del(&j->list);
		dl_list_add_tail(&out->jsons, &j->list);
	}
}

static void pv_state_transfer_objects(struct pv_state *in, struct pv_state *out, int runlevel)
{
	struct pv_object *o, *o_tmp;
	struct dl_list *objects;

	// remove existing objects from out
	objects = &out->objects;
	dl_list_for_each_safe(o, o_tmp, objects,
		struct pv_object, list) {
		if (!o->plat || (o->plat->runlevel < runlevel))
			continue;

		pv_log(DEBUG, "removing object %s linked to platform %s from rev %s", o->name, o->plat->name, out->rev);
		dl_list_del(&o->list);
		pv_object_free(o);
	}

	// transfer existing objects from in to out
	objects = &in->objects;
	dl_list_for_each_safe(o, o_tmp, objects,
		struct pv_object, list) {
		if (!o->plat || (o->plat->runlevel < runlevel))
			continue;

		pv_log(DEBUG, "transferring object %s linked to platform %s from rev %s to rev %s", o->name, o->plat->name, in->rev, out->rev);
		dl_list_del(&o->list);
		dl_list_add_tail(&out->objects, &o->list);
	}
}

void pv_state_print(struct pv_state *s)
{
	if (!s)
		return;

	pv_log(DEBUG, "state %d:", s->rev);
	pv_log(DEBUG, " kernel: '%s'", s->bsp.kernel);
	pv_log(DEBUG, " initrd: '%s'", s->bsp.initrd);
	struct pv_platform *p, *tmp_p;
    struct dl_list *platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp_p, platforms,
			struct pv_platform, list) {
		pv_log(DEBUG, " platform: '%s'", p->name);
		pv_log(DEBUG, "  type: '%s'", p->type);
		pv_log(DEBUG, "  runlevel: %d", p->runlevel);
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

void pv_state_validate(struct pv_state *s)
{
	if (!s)
		return;

	// remove platforms that have no loaded data
	pv_platforms_remove_not_installed(s);
	// set runlevel in all undefined platforms
	pv_platforms_default_runlevel(s);
	// add loggers for all platforms
	pv_platforms_add_all_loggers(s);
}

void pv_state_transfer(struct pv_state *in, struct pv_state *out, int runlevel)
{
	pv_log(INFO, "transferring state from rev %s to rev %s", in->rev, out->rev);

	pv_state_transfer_objects(in, out, runlevel);
	pv_state_transfer_volumes(in, out, runlevel);
	pv_state_transfer_jsons(in, out, runlevel);
	pv_state_transfer_platforms(in, out, runlevel);

	strncpy(out->rev, in->rev, strlen(in->rev));

	pv_state_print(out);
}

int pv_state_compare_states(struct pv_state *pending, struct pv_state *current)
{
	int runlevel = MAX_RUNLEVEL;
	struct pv_platform *p, *tmp_p, *curr_p;
	struct dl_list *platforms;
	struct pv_object *o, *tmp_o, *curr_o;
	struct dl_list *objects;
	struct pv_json *j, *tmp_j, *curr_j;
	struct dl_list *jsons;

	if (!pending || !current)
		return 0;

	// search for deleted platforms or changes in runlevel
	platforms = &current->platforms;
	dl_list_for_each_safe(p, tmp_p, platforms,
		struct pv_platform, list) {
		curr_p = pv_platform_get_by_name(pending, p->name);
		// if exist, check if runlevel has changed
		if (curr_p && (curr_p->runlevel != p->runlevel)) {
			pv_log(DEBUG, "platform %s runlevel has changed", p->name);
			return 0;
		// if not, it means the platform has been deleted
		} else if (!curr_p) {
			pv_log(DEBUG, "platform %s has been deleted in last update", p->name);
			// if the platform has been deleted, we respect its runlevel
			if(p->runlevel < runlevel) {
				runlevel = p->runlevel;
			}
		}
	}

	// search for changes in objects
	objects = &pending->objects;
	dl_list_for_each_safe(o, tmp_o, objects,
		struct pv_object, list) {
		curr_o = pv_objects_get_by_name(current, o->name);
		if (!curr_o || strcmp(o->id, curr_o->id)) {
			if (!o->plat) {
				pv_log(DEBUG, "bsp object %s has been changed in last update", o->name);
				return 0;
			}

			pv_log(DEBUG, "object %s from platform %s has been changed in last update", o->name, o->plat->name);
			if (o->plat->runlevel < runlevel) {
				runlevel = o->plat->runlevel;
			}
		}
	}

	// search for deleted objects
	objects = &current->objects;
	dl_list_for_each_safe(o, tmp_o, objects,
		struct pv_object, list) {
		curr_o = pv_objects_get_by_name(pending, o->name);
		if (!curr_o) {
			if (!o->plat) {
				pv_log(DEBUG, "bsp object %s has been deleted in last update", o->name);
				return 0;
			}

			pv_log(DEBUG, "object %s from platform %s has been deleted in last update", o->name, o->plat->name);
			if (o->plat->runlevel < runlevel) {
				runlevel = o->plat->runlevel;
			}
		}
	}

	// search for changes in jsons
	jsons = &pending->jsons;
	dl_list_for_each_safe(j, tmp_j, jsons,
		struct pv_json, list) {
		curr_j = pv_jsons_get_by_name(current, j->name);
		if (!curr_j || strcmp(j->value, curr_j->value)) {
			if (!j->plat) {
				pv_log(DEBUG, "global or bsp json %s has been changed in last update", j->name);
				return 0;
			}

			pv_log(DEBUG, "json %s from platform %s has been changed in last update", j->name, j->plat->name);
			if (j->plat->runlevel < runlevel) {
				runlevel = j->plat->runlevel;
			}
		}
	}

	// search for deleted jsons
	jsons = &current->jsons;
	dl_list_for_each_safe(j, tmp_j, jsons,
		struct pv_json, list) {
		curr_j = pv_jsons_get_by_name(pending, j->name);
		if (!curr_j) {
			if (!j->plat) {
				pv_log(DEBUG, "global or bsp json %s has been deleted in last update", j->name);
				return 0;
			}

			pv_log(DEBUG, "json %s from platform %s has been deleted in last update", j->name, j->plat->name);
			if (j->plat->runlevel < runlevel) {
				runlevel = j->plat->runlevel;
			}
		}
	}

	return runlevel;
}

state_spec_t pv_state_spec(struct pv_state *s)
{
	return s->spec;
}
