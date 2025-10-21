/*
 * Copyright (c) 2022-2024 Pantacor Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/limits.h>

#include "utils/tsh.h"
#include "utils/str.h"
#include "drivers.h"
#include "metadata.h"
#include "state.h"
#include "json.h"
#include "config.h"

#define MODULE_NAME "drivers"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define USER_META_KEY "user-meta"
#define DEV_META_KEY "device-meta"

// modprobe + remove option + module name + module options
#define DRIVER_MGMT_COMMAND "/sbin/modprobe %s %s %s"

static char *_sub_meta_values(char *str)
{
	// find key for meta from ${user-meta:KEY} component of string
	int _start = 0, _end = 0;
	char *_tok, *_t, *_at, *new;
	char *_var, *_param, *_tstr;
	int _nt = 0;
	size_t newlen = 0;

	if (!strchr(str, '$'))
		return strdup(str);

	newlen = strlen(str);
	new = calloc(newlen, sizeof(char));
	if (!new)
		return NULL;

	while ((_at = strchr(str + _start, '$')) != NULL) {
		_t = strchr(_at, '{');
		if (!_t || ((_t - _at) != 1)) {
			free(new);
			return NULL;
		}
		_t++;
		memcpy(new + _nt, str + _start, (_at - (str + _end)));
		_nt = _nt + (_at - (str + _end));
		_var = strchr(_t, '}');
		_end = _var - (str);
		_tstr = strdup(_t);
		strtok(_tstr, "{:}");
		_tok = strtok(NULL, "{:}");
		_param = pv_metadata_get_usermeta(_tok);
		if (_param) {
			if (_nt + strlen(_param) + 1 > newlen) {
				newlen += strlen(_param) + 1;
				char *p = realloc(new, newlen);
				if (!p) {
					if (_tstr)
						free(_tstr);
					free(new);
					return NULL;
				} else {
					new = p;
				}
			}
			memcpy(new + _nt, _param, strlen(_param) + 1);
			_nt += strlen(_param);
		}
		free(_tstr);
		_start = _end + 1;
		_end++;
	}

	return new;
}

static int driver_single_op(char *name, bool load, char *options)
{
	if (!name || !strlen(name)) {
		pv_log(WARN, "no module name provided, nothing to load");
		return -1;
	}

	char *ld = load ? "" : "-r";
	char *op = options ? options : "";

	int len = snprintf(NULL, 0, DRIVER_MGMT_COMMAND, name, ld, op) + 1;
	char *cmd = calloc(len, sizeof(char));
	if (!cmd)
		return -1;

	snprintf(cmd, len, DRIVER_MGMT_COMMAND, name, ld, op);
	int status = 0;
	tsh_run(cmd, 0, &status);
	// XXX: fix me ... waitpid in a loop for timeout to avoid dead hang in modprobe
	status = WEXITSTATUS(status);
	if (status != 0) {
		pv_log(WARN, "cannot %s module %s with options: %s",
		       load ? "load" : "unload", name, options);
	}

	free(cmd);
	return status;
}

static int pv_drivers_load_single(char *name, char *options)
{
	return driver_single_op(name, true, options);
}

static int pv_drivers_unload_single(char *name)
{
	return driver_single_op(name, false, NULL);
}

static int _pv_drivers_modprobe(char **modules, mod_action_t action)
{
	int ret = 0, status;
	char cmd[PATH_MAX];
	char **module, *tmp, *mod;

	if (!modules)
		return ret;

	module = modules;
	while (*module) {
		tmp = _sub_meta_values(*module);
		if (!tmp) {
			pv_log(WARN, "illegal module value '%s'", *module);
			ret++;
			goto next;
		}

		if (action == MOD_UNLOAD)
			mod = strtok(tmp, " ");
		else
			mod = tmp;
		pv_log(DEBUG, "%s '%s' module",
		       action == MOD_LOAD ? "loading" : "unloading", mod);
		sprintf(cmd, "/sbin/modprobe %s %s",
			action == MOD_LOAD ? "" : "-r", mod);
		tsh_run(cmd, 1, &status);
		if (WEXITSTATUS(status) == 0)
			ret++;
		;
	next:
		module++;
		if (tmp)
			free(tmp);
		tmp = NULL;
	}

	return ret;
}

void pv_drivers_load_early()
{
	if (!pv_config_get_bool(PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO))
		return;

	// load fs module from pantavisor.conf
	char *fstype = pv_config_get_str(PV_STORAGE_FSTYPE);
	if (pv_drivers_load_single(fstype, NULL) != 0)
		pv_log(WARN, "cannot load filesystem module");

	// some driver will fail (not found), but that's ok
	// because at this point we have only a few drivers,
	// so we send the output to /dev/null
	int r = -1;
	tsh_run("/sbin/mdev -s > /dev/null 2>&1", 0, &r);
	if (r != 0)
		pv_log(WARN, "Cannot load drivers using mdev error: %d", r);
}

const char *pv_drivers_state_str(char *match)
{
	int state;

	state = pv_drivers_state(match);
	switch (state) {
	case MOD_LOADED:
		return "LOADED";
	case MOD_UNLOADED:
		return "UNLOADED";
	default:
		return "UNKNOWN";
	}
}

const char *pv_drivers_type_str(plat_driver_t type)
{
	switch (type) {
	case DRIVER_REQUIRED:
		return "REQUIRED";
	case DRIVER_OPTIONAL:
		return "OPTIONAL";
	case DRIVER_MANUAL:
		return "MANUAL";
	default:
		return "UNKNOWN";
	}
}

char *pv_drivers_state_all(struct pv_platform *p)
{
	struct pv_json_ser js;
	struct pv_platform_driver *d, *tmp;

	if (dl_list_empty(&p->drivers))
		return strdup("[]");

	pv_json_ser_init(&js, 4096);

	pv_json_ser_array(&js);

	dl_list_for_each_safe(d, tmp, &p->drivers, struct pv_platform_driver,
			      list)
	{
		const char *statechar = pv_drivers_state_str(d->match);
		const char *typechar = pv_drivers_type_str(d->type);

		pv_json_ser_object(&js);
		{
			pv_json_ser_key(&js, "name");
			pv_json_ser_string(&js, d->match);
			pv_json_ser_key(&js, "type");
			pv_json_ser_string(&js, typechar);
			pv_json_ser_key(&js, "status");
			pv_json_ser_string(&js, statechar);

			pv_json_ser_object_pop(&js);
		}
	}
	pv_json_ser_array_pop(&js);

	return pv_json_ser_str(&js);
}

int pv_drivers_state(char *match)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_state *s = pv->state;
	struct pv_driver *d, *tmp;

	if (!match)
		return -1;

	if (dl_list_empty(&s->bsp.drivers))
		return -1;

	dl_list_for_each_safe(d, tmp, &s->bsp.drivers, struct pv_driver, list)
	{
		if (strcmp(d->alias, match))
			continue;
		return d->loaded;
	}

	return -1;
}

static int _pv_drivers_set(char *match, mod_action_t action)
{
	int changed = 0;
	struct pantavisor *pv = pv_get_instance();
	struct pv_state *s = pv->state;
	struct pv_driver *d, *tmp;

	if (!match)
		return 0;

	if (!strlen(match))
		return 0;

	if (dl_list_empty(&s->bsp.drivers))
		return 0;

	dl_list_for_each_safe(d, tmp, &s->bsp.drivers, struct pv_driver, list)
	{
		if (strcmp(d->alias, match))
			continue;
		changed += _pv_drivers_modprobe(d->modules, action);
		int len = pv_str_count_list(d->modules);
		pv_log(DEBUG, "changed=%d, len=%d", changed, len);
		if (changed != len) {
			pv_log(WARN,
			       "not all modules were loaded/unloaded correctly");
			return -1;
		}
		if (!changed)
			return 0;
		if (action == MOD_LOAD)
			d->loaded = true;
		else
			d->loaded = false;
		return changed;
	}

	return 0;
}

int pv_drivers_load(char *match)
{
	return _pv_drivers_set(match, MOD_LOAD);
}

int pv_drivers_unload(char *match)
{
	return _pv_drivers_set(match, MOD_UNLOAD);
}

struct pv_driver *pv_drivers_add(struct pv_state *s, char *alias, int len,
				 char **modules)
{
	int i = 0;
	struct pv_driver *this = calloc(1, sizeof(struct pv_driver));

	if (this) {
		this->alias = strdup(alias);
		this->modules = calloc(len + 1, sizeof(char *));
		while (i < len) {
			this->modules[i] = strdup(modules[i]);
			pv_log(DEBUG, "adding module %s", this->modules[i]);
			i++;
		}
		modules[i] = 0;

		dl_list_init(&this->list);
		dl_list_add(&s->bsp.drivers, &this->list);
		return this;
	}
	return NULL;
}

void pv_drivers_empty(struct pv_state *s)
{
	int num_obj = 0;
	struct pv_driver *curr, *tmp;
	struct dl_list *head = &s->bsp.drivers;

	dl_list_for_each_safe(curr, tmp, head, struct pv_driver, list)
	{
		dl_list_del(&curr->list);
		pv_driver_free(curr);
		num_obj++;
	}

	pv_log(DEBUG, "cleared %d drivers", num_obj);
}
