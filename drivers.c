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

#define MODULE_NAME			"drivers"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define USER_META_KEY	"user-meta"
#define DEV_META_KEY	"device-meta"

static char *_sub_meta_values(char *str)
{
	// find key for meta from ${user-meta:KEY} component of string
	int _start = 0, _end = 0, type;
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

	while ((_at = strchr(str+_start, '$')) != NULL) {
		_t = strchr(_at, '{');
		if (!_t || ((_t-_at) != 1))
			return NULL;
		_t++;
		memcpy(new+_nt, str+_start, (_at-(str+_end)));
		_nt = _nt + (_at-(str+_end));
		_var = strchr(_t, '}');
		_end = _var-(str);
		_start = _at-(str+_start);
		_tstr = strdup(_t);
		_tok = strtok(_tstr, "{:}");
		if (!strcmp(_tok, USER_META_KEY))
			type = USER_META;
		else if (!strcmp(_tok, DEV_META_KEY))
			type = DEVICE_META;
		_tok = strtok(NULL, "{:}");
		_param = pv_metadata_get_usermeta(_tok);
		if (_param) {
			if (_nt + strlen(_param) + 1 > newlen) {
				newlen += strlen(_param) + 1;
				new = realloc(new, newlen);
				if (!new)
					return NULL;
			}
			memcpy(new+_nt, _param, strlen(_param) + 1);
			_nt += strlen(_param);
		}
		free(_tstr);
		_start = _end + 1;
		_end++;
	}

	return new;
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
		pv_log(DEBUG, "%s '%s' module", action == MOD_LOAD ? "loading" : "unloading", mod);
		sprintf(cmd, "/sbin/modprobe %s %s", action == MOD_LOAD ? "" : "-r", mod);
		tsh_run(cmd, 1, &status);
		if (WEXITSTATUS(status) == 0)
			ret++;;
	next:
		module++;
		if (tmp)
			free(tmp);
		tmp = NULL;
	}

	return ret;
}

const char *pv_drivers_state_str(char *match)
{
	int state;

	state = pv_drivers_state(match);
	switch (state) {
		case MOD_LOADED: return "LOADED";
		case MOD_UNLOADED: return "UNLOADED";
		default: return "UNKNOWN";
	}
}

const char *pv_drivers_type_str(plat_driver_t type)
{
	switch (type) {
		case DRIVER_REQUIRED: return "REQUIRED";
		case DRIVER_OPTIONAL: return "OPTIONAL";
		case DRIVER_MANUAL: return "MANUAL";
		default: return "UNKNOWN";
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

	dl_list_for_each_safe(d, tmp, &p->drivers,
			struct pv_platform_driver, list) {
		const char* statechar = pv_drivers_state_str(d->match);
		const char* typechar = pv_drivers_type_str(d->type);

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

	dl_list_for_each_safe(d, tmp, &s->bsp.drivers,
			struct pv_driver, list) {
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

	dl_list_for_each_safe(d, tmp, &s->bsp.drivers,
			struct pv_driver, list) {
		if (strcmp(d->alias, match))
			continue;
		changed += _pv_drivers_modprobe(d->modules, action);
		int len = pv_str_count_list(d->modules);
		pv_log(DEBUG, "changed=%d, len=%d", changed, len);
		if (changed != len) {
			pv_log(WARN, "not all modules were loaded/unloaded correctly");
			changed = false;
		}
		if (!changed)
			continue;
		if (action == MOD_LOAD)
			d->loaded = true;
		else
			d->loaded = false;
	}

	return changed;
}

int pv_drivers_load(char *match)
{
	return _pv_drivers_set(match, MOD_LOAD);
}

int pv_drivers_unload(char *match)
{
	return _pv_drivers_set(match, MOD_UNLOAD);
}

struct pv_driver* pv_drivers_add(struct pv_state *s, char *alias,
					int len, char **modules)
{
	int i = 0;
	struct pv_driver *this = calloc(1, sizeof(struct pv_driver));

	if (this) {
		this->alias = strdup(alias);
		this->modules = calloc(len + 1, sizeof(char*));
		while (i < len) {
			pv_log(DEBUG, "adding module %s", this->modules[i]);
			this->modules[i] = strdup(modules[i]);
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

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_driver, list) {
		dl_list_del(&curr->list);
		pv_driver_free(curr);
		num_obj++;
	}

	pv_log(DEBUG, "cleared %d drivers", num_obj);
}
