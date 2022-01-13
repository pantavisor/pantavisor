/*
 * Copyright (c) 2020-2021 Pantacor Ltd.
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
		s->rev = calloc(1, len * sizeof(char*));
		SNPRINTF_WTRUNC(s->rev, len, "%s", rev);
		s->spec = spec;
		dl_list_init(&s->platforms);
		dl_list_init(&s->volumes);
		dl_list_init(&s->disks);
		dl_list_init(&s->addons);
		dl_list_init(&s->objects);
		dl_list_init(&s->jsons);
		pv_state_init_groups(s);
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

	pv_log(INFO, "removed %g groups", num_groups);
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

	pv_platforms_empty(s);
	pv_volumes_empty(s);
	pv_disks_empty(s);
	pv_addons_empty(s);
	pv_objects_empty(s);
	pv_jsons_empty(s);
	pv_state_empty_groups(s);

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

struct pv_group* pv_state_fetch_group(struct pv_state *s, const char *name)
{
	struct pv_group *g, *tmp;
	struct dl_list *groups = &s->groups;

	// Iterate over all groups from state
	dl_list_for_each_safe(g, tmp, groups,
            struct pv_group, list) {
		if (pv_str_matches(g->name, strlen(g->name), name, strlen(name)))
			return g;
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
		pv_log(DEBUG, "  runlevel: %d", p->runlevel);
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
		first_p->runlevel = RUNLEVEL_ROOT;
	}

	// set rest of the non configured platforms in group platform
	platforms = &s->platforms;
	dl_list_for_each_safe(p, tmp, platforms,
            struct pv_platform, list) {
		if (p->group == NULL)
			p->group = d;
		p->runlevel = RUNLEVEL_PLATFORM;
    }
}

static int pv_check_group_conditions(struct pv_state *s)
{
	int ret = 0;
	struct pv_group *g, *tmp_g;
	struct pv_condition *c, *tmp_c;

	dl_list_for_each_safe(g, tmp_g, &s->groups,
			struct pv_group, list) {
		dl_list_for_each_safe(c, tmp_c, &g->conditions,
				struct pv_condition, list) {
			if (!pv_platform_get_by_name(s, c->plat)) {
				pv_log(ERROR, "condition %s from group %s linked to unknown platform %s",
					c->key, g->name, c->plat);
				ret = -1;
			}
		}
	}

	return ret;
}

int pv_state_validate(struct pv_state *s)
{
	// remove platforms that have no loaded data
	pv_platforms_remove_not_installed(s);
	// add loggers for all platforms
	pv_platforms_add_all_loggers(s);
	// set groups for all undefined platforms
	pv_state_set_default_groups(s);
	// check all group conditions can be met
	return pv_check_group_conditions(s);
}


static void pv_state_remove_platforms(struct pv_state *out)
{
	struct pv_json *j, *j_tmp;
	struct pv_object *o, *o_tmp;
	struct pv_volume *v, *v_tmp;
	struct pv_platform *p, *p_tmp;
	struct dl_list *jsons, *objects, *volumes, *platforms;

	// remove existing jsons from out
	jsons = &out->jsons;
	dl_list_for_each_safe(j, j_tmp, jsons,
		struct pv_json, list) {
		if (!j->plat || (j->plat->status == PLAT_STARTED))
			continue;

		pv_log(DEBUG, "removing json %s linked to platform %s from rev %s", j->name, j->plat->name, out->rev);
		dl_list_del(&j->list);
		pv_jsons_free(j);
	}

	// remove existing objects from out
	objects = &out->objects;
	dl_list_for_each_safe(o, o_tmp, objects,
		struct pv_object, list) {
		if (!o->plat || (o->plat->status == PLAT_STARTED))
			continue;

		pv_log(DEBUG, "removing object %s linked to platform %s from rev %s", o->name, o->plat->name, out->rev);
		dl_list_del(&o->list);
		pv_object_free(o);
	}

	// remove existing volumes from out
	volumes = &out->volumes;
	dl_list_for_each_safe(v, v_tmp, volumes,
		struct pv_volume, list) {
		if (!v->plat || (v->plat->status == PLAT_STARTED))
			continue;

		pv_log(DEBUG, "removing volume %s linked to platform %s from rev %s", v->name, v->plat->name, out->rev);
		dl_list_del(&v->list);
		pv_volume_free(v);
	}

	// remove existing platforms from out
	platforms = &out->platforms;
	dl_list_for_each_safe(p, p_tmp, platforms,
		struct pv_platform, list) {
		if (p->status == PLAT_STARTED)
			continue;

		pv_log(DEBUG, "removing platform %s from rev %s", p->name, out->rev);
		dl_list_del(&p->list);
		pv_platform_free(p);
	}
}

static void pv_state_transfer_platforms(struct pv_state *in, struct pv_state *out)
{
	struct pv_json *j, *j_tmp;
	struct pv_object *o, *o_tmp;
	struct pv_volume *v, *v_tmp;
	struct pv_platform *p, *p_tmp;
	struct dl_list *jsons, *objects, *volumes, *platforms;

	// transfer existing json from in to out
	jsons = &in->jsons;
	dl_list_for_each_safe(j, j_tmp, jsons,
		struct pv_json, list) {
		if (!j->plat || pv_platform_get_by_name(out, j->plat->name))
			continue;

		pv_log(DEBUG, "transferring json %s linked to platform %s from rev %s to rev %s", j->name, j->plat->name, in->rev, out->rev);
		dl_list_del(&j->list);
		dl_list_add_tail(&out->jsons, &j->list);
	}

	// transfer existing objects from in to out
	objects = &in->objects;
	dl_list_for_each_safe(o, o_tmp, objects,
		struct pv_object, list) {
		if (!o->plat || pv_platform_get_by_name(out, o->plat->name))
			continue;

		pv_log(DEBUG, "transferring object %s linked to platform %s from rev %s to rev %s", o->name, o->plat->name, in->rev, out->rev);
		dl_list_del(&o->list);
		dl_list_add_tail(&out->objects, &o->list);
	}

	// transfer existing volumes from in to out
	volumes = &in->volumes;
	dl_list_for_each_safe(v, v_tmp, volumes,
		struct pv_volume, list) {
		if (!v->plat || pv_platform_get_by_name(out, v->plat->name))
			continue;

		pv_log(DEBUG, "transferring volume %s linked to platform %s from rev %s to rev %s", v->name, v->plat->name, in->rev, out->rev);
		dl_list_del(&v->list);
		dl_list_add_tail(&out->volumes, &v->list);
	}

	// transfer existing platforms from in to out
	platforms = &in->platforms;
	dl_list_for_each_safe(p, p_tmp, platforms,
		struct pv_platform, list) {
		if (pv_platform_get_by_name(out, p->name))
			continue;

		pv_log(DEBUG, "transferring platform %s from rev %s to rev %s", p->name, in->rev, out->rev);
		dl_list_del(&p->list);
		dl_list_add_tail(&out->platforms, &p->list);
	}
}

int pv_state_start(struct pv_state *s)
{
	return pv_volumes_mount_firmware_modules();
}

static int pv_state_start_platform(struct pv_state *s, struct pv_platform *p)
{
	struct pv_volume *v, *tmp;

	dl_list_for_each_safe(v, tmp, &s->volumes,
			struct pv_volume, list) {
		if (v->plat == p)
			if (pv_volume_mount(v))
				return -1;
	}

	if (pv_platform_start(p))
		return -1;

	return 0;
}

int pv_state_run(struct pv_state *s)
{
	int ret = 0;
	struct pv_platform *p, *tmp;

	dl_list_for_each_safe(p, tmp, &s->platforms,
			struct pv_platform, list) {
		if ((p->status == PLAT_READY) || (p->status == PLAT_BLOCKED)) {
			if (pv_group_check_conditions(p->group))
				ret = pv_state_start_platform(s, p);
			else
				p->status = PLAT_BLOCKED;
		} else if ((p->status == PLAT_STARTING) || (p->status == PLAT_STARTED)) {
			if (pv_platform_check_running(p))
				p->status = PLAT_STARTED;
			else {
				p->status = PLAT_STOPPED;
				ret = -1;
			}
		}
	}

	// TODO: ret properly

	return ret;
}

int pv_state_stop(struct pv_state *s)
{
	int ret = 0;
	struct pv_platform *p, *tmp_p;
	struct pv_volume *v, *tmp_v;

	dl_list_for_each_safe(p, tmp_p, &s->platforms,
			struct pv_platform, list) {
		if ((p->status == PLAT_STARTING) || (p->status == PLAT_STARTED)) {
			ret = pv_platform_stop(p);
			p->status = PLAT_STOPPED;
		}
	}

	dl_list_for_each_safe(v, tmp_v, &s->volumes,
			struct pv_volume, list) {
		pv_volume_unmount(v);
	}

	// TODO: ret properly

	return ret;
}

void pv_state_transfer(struct pv_state *in, struct pv_state *out)
{
	int len = strlen(in->rev) + 1;

	pv_log(INFO, "transferring state from rev %s to rev %s", in->rev, out->rev);

	pv_state_remove_platforms(out);
	pv_state_transfer_platforms(in, out);

	out->rev = realloc(out->rev, len);
	SNPRINTF_WTRUNC(out->rev, len, "%s", in->rev);

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
			p->updated = true;
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
			if (curr_o)
				curr_o->plat->updated = true;
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
			o->plat->updated = true;
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
			if (curr_j)
				curr_j->plat->updated = true;
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
			j->plat->updated = true;
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

/*
 * retrieve a string of all path/objectid pairs that
 * the handler will validate. This will prevent those
 * objects to be checked with a full sha256sum check
 * before starting the platforms.
 */
static char* _pv_state_get_novalidate_list(char *rev)
{
#define _pv_bufsize_1 (1288 * 1024)
#define _path_fmt "/lib/pv/volmount/%s"
#define _cmd_fmt " novalidatelist %s"
	char *path = pv_storage_get_rev_path(rev);
	char sout[_pv_bufsize_1] = {0}, serr[_pv_bufsize_1] = {0};
	char *_sout = sout, *_serr = serr;
	char *result = NULL;
	int res;
	char *cmd = NULL;
	struct dirent *dp;
	DIR *volmountdir = opendir("/lib/pv/volmount");

        // Unable to open directory stream
        if (!volmountdir)
            goto out;

        while ((dp = readdir(volmountdir)) != NULL) {
		struct stat st;

		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;

		char _hdl_path [PATH_MAX];
		SNPRINTF_WTRUNC(_hdl_path, ARRAY_LEN(_hdl_path), _path_fmt, dp->d_name);
		if(stat (_hdl_path, &st)) {
			pv_log(WARN, "illegal handler file %s, error=%s", _hdl_path, strerror(errno));
			goto out;
		}

		// if not executable, we let it pass ...
		if (!(st.st_mode & S_IXUSR))
			continue;

		// now we make the cmd for the volmount handler. every handler is expected
		// to implement a novalidatelist subcommand; if not relevant the handler
		// shall return an empty result...
		int len = (ARRAY_LEN(_path_fmt _cmd_fmt) + strlen(dp->d_name) + strlen(path) + 2);
		cmd = realloc(cmd, len * sizeof(char));
		int len_o = snprintf(cmd, sizeof(char) * len, _path_fmt _cmd_fmt, dp->d_name, path);
		if (len_o >= len) {
			pv_log(WARN, "illegal handler command (cut off): %s - %s", cmd, strerror(errno));
			goto out;
		}

		// now we run that handler cmd with 20 seconds timeout ...
		res = tsh_run_output(cmd, 20, _sout, _pv_bufsize_1 - 1, _serr, _pv_bufsize_1 - 1);

		if (res < 0) {
			pv_log(WARN, "error running novalidatelist command: %s", strerror(errno));
			goto out;
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

int pv_state_report_condition(struct pv_state *s, char *plat, char *key, char *value)
{
	int ret = -1;
	struct pv_group *g, *tmp;

	pv_log(DEBUG, "condition from platform %s reported with key '%s' and value '%s'",
		plat, key, value);

	dl_list_for_each_safe(g, tmp, &s->groups,
			struct pv_group, list) {
		if (!pv_group_report_condition(g, plat, key, value))
			ret = 0;
	}

	if (ret)
		pv_log(WARN, "condition not found in state");

	return ret;
}

char* pv_state_get_containers_json(struct pv_state *s)
{
	int len = 1, line_len;
	char *json = calloc(1, len), *line;
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
		snprintf(&json[len], line_len + 1, "%s,", line);
		len += line_len;
		free(line);
	}

	// remove ,
	len -= 1;

close:
	// close json
	len += 2;
	json = realloc(json, len);
	json[len-2] = ']';
	json[len-1] = '\0';

	return json;
}

char* pv_state_get_conditions_json(struct pv_state *s)
{
	int len = 1, line_len;
	char *json = calloc(1, len), *line;
	struct pv_group *g, *tmp;

	// open json
	json[0]='[';

	if (dl_list_empty(&s->groups))
		goto close;

	dl_list_for_each_safe(g, tmp, &s->groups,
			struct pv_group, list) {
		line = pv_group_get_json(g);
		line_len = strlen(line) + 1;
		json = realloc(json, len + line_len + 1);
		snprintf(&json[len], line_len + 1, "%s,", line);
		len += line_len;
		free(line);
	}

	// remove ,
	len -= 1;

close:
	// close json
	len += 2;
	json = realloc(json, len + 1);
	json[len-2] = ']';
	json[len-1] = '\0';

	return json;
}
