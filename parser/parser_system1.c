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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#define MODULE_NAME             "parser-system1"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"
#include "addons.h"
#include "platforms.h"
#include "volumes.h"
#include "objects.h"
#include "pantavisor.h"
#include "device.h"
#include "parser.h"

#define PV_NS_NETWORK	0x1
#define PV_NS_UTS	0x2
#define PV_NS_IPC	0x4

static int parse_bsp(struct pv_state *s, char *value, int n)
{
	int c;
	int ret = 0, tokc, size;
	char *str, *buf;
	struct pv_volume *v;
	jsmntok_t *tokv;
	jsmntok_t **key, **key_i;

	// take null terminate copy of item to parse
	buf = calloc(1, (n+1) * sizeof(char));
	buf = strncpy(buf, value, n);

	pv_log(DEBUG, "buf_size=%d, buf='%s'", strlen(buf), buf);
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	s->kernel = get_json_key_value(buf, "linux", tokv, tokc);
	s->initrd = get_json_key_value(buf, "initrd", tokv, tokc);
	s->firmware = get_json_key_value(buf, "firmware", tokv, tokc);
	s->modules = get_json_key_value(buf, "modules", tokv, tokc);

	if (s->firmware) {
		v = pv_volume_add(s, s->firmware);
		v->plat = NULL;
		v->type = VOL_LOOPIMG;
	}

	if (s->modules) {
		v = pv_volume_add(s, s->modules);
		v->plat = NULL;
		v->type = VOL_LOOPIMG;
	}

	if (!s->kernel || !s->initrd) {
		pv_log(ERROR, "kernel or initrd not configured in bsp/run.json. Cannot continue.", strlen(buf), buf);
		goto out;
	}

	// get addons and create empty items
	key = jsmnutil_get_object_keys(buf, tokv);
	key_i = key;
	while (*key_i) {
		c = (*key_i)->end - (*key_i)->start;
		if (strncmp("addons", buf+(*key_i)->start, strlen("addons"))) {
			key_i++;
			continue;
		}

		// parse array data
		jsmntok_t *k = (*key_i+2);
		size = (*key_i+1)->size;
		while ((str = json_array_get_one_str(buf, &size, &k)))
			pv_addon_add(s, str);

		break;
	}
	jsmnutil_tokv_free(key);

	ret = 1;

out:
	if (tokv)
		free(tokv);
	if (buf)
		free(buf);

	return ret;
}

static int parse_storage(struct pv_state *s, struct pv_platform *p, char *buf)
{
	int tokc, n, ret;
	char *key, *value, *pt;
	jsmntok_t *tokv;
	jsmntok_t *tokv_t;
	jsmntok_t **k, **keys;

	if (!buf)
		return 1;

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	keys = jsmnutil_get_object_keys(buf, tokv);
	k = keys;

	// platform head is pv->state->platforms
	while (*k) {
		n = (*k)->end - (*k)->start;

		// copy key
		key = malloc(n+1);
		snprintf(key, n+1, "%s", buf+(*k)->start);

		// copy value
		n = (*k+1)->end - (*k+1)->start;
		value = malloc(n+1);
		snprintf(value, n+1, "%s", buf+(*k+1)->start);

		ret = jsmnutil_parse_json(value, &tokv_t, &tokc);
		pt = get_json_key_value(value, "persistence", tokv_t, tokc);

		if (pt) {
			struct pv_volume *v = pv_volume_add(s, key);
			v->plat = p;
			if (!strcmp(pt, "permanent"))
				v->type = VOL_PERMANENT;
			else if (!strcmp(pt, "revision"))
				v->type = VOL_REVISION;
			else if (!strcmp(pt, "boot"))
				v->type = VOL_BOOT;
			else {
				pv_log(WARN, "invalid persistence value '%s' for platform '%s', default to BOOT", pt, p->name);
				v->type = VOL_BOOT;
			}
			free(pt);
		}

		// free intermediates
		if (key) {
			free(key);
			key = 0;
		}
		if (value) {
			free(value);
			value = 0;
		}
		k++;
	}
	jsmnutil_tokv_free(keys);

	return 1;
}

static int parse_platform(struct pv_state *s, char *buf, int n)
{
	int tokc, ret, size, c;
	char *name, *tmp = 0;
	char *config = 0, *shares = 0;
	struct pv_platform *this;
	struct pv_volume *v;
	jsmntok_t *tokv, *t;
	jsmntok_t **key, **key_i;

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	name = get_json_key_value(buf, "name", tokv, tokc);

	this = pv_platform_add(s, name);
	if (!this)
		goto out;

	this->type = get_json_key_value(buf, "type", tokv, tokc);

	config = get_json_key_value(buf, "config", tokv, tokc);
	shares = get_json_key_value(buf, "share", tokv, tokc);

	tmp = get_json_key_value(buf, "root-volume", tokv, tokc);
	if (!tmp)
		goto out;

	v = pv_volume_add(s, tmp);
	v->plat = this;
	v->type = VOL_LOOPIMG;

	if (tmp) {
		free(tmp);
		tmp = 0;
	}

	key = jsmnutil_get_object_keys(buf, tokv);
	key_i = key;
	while (*key_i) {
		c = (*key_i)->end - (*key_i)->start;
		if (strncmp("volumes", buf+(*key_i)->start, strlen("volumes"))) {
			key_i++;
			continue;
		}

		// parse array data
		jsmntok_t *k = (*key_i+2);
		size = (*key_i+1)->size;
		while ((tmp = json_array_get_one_str(buf, &size, &k))) {
			v = pv_volume_add(s, tmp);
			v->plat = this;
			v->type = VOL_LOOPIMG;
			free(tmp);
		}

		break;
	}
	jsmnutil_tokv_free(key);

	tmp = get_json_key_value(buf, "storage", tokv, tokc);

	// parse storage volumes
	if (!parse_storage(s, this, tmp))
		goto out;

	// free intermediates
	if (name) {
		free(name);
		name = 0;
	}
	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	ret = jsmnutil_parse_json(config, &tokv, &tokc);
	t = tokv+1;
	this->configs = calloc(1, 2 * sizeof(char *));
	this->configs[1] = NULL;
	this->configs[0] = strdup(config);

	// free intermediates
	if (config) {
		free(config);
		config = 0;
	}
	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	this->json = strdup(buf);
	this->done = true;

out:
	if (name)
		free(name);
	if (tmp)
		free(tmp);
	if (tokv)
		free(tokv);
	if (config)
		free(config);

	return 0;
}

void system1_free(struct pv_state *this)
{
	if (!this)
		return;

	if (this->initrd)
		free(this->initrd);

	free(this->json);

	struct pv_platform *pt, *p = this->platforms;
	while (p) {
		free(p->type);
		char **config = p->configs;
		while (config && *config) {
			free(*config);
			config++;
		}
		free(p->json);
		pt = p;
		p = p->next;
		free(pt);
	}
	struct pv_volume *vt, *v = this->volumes;
	while (v) {
		free(v->name);
		vt = v;
		v = v->next;
		free(vt);
	}
	struct pv_object *ot, *o = this->objects;
	while (o) {
		free(o->name);
		free(o->id);
		free(o->relpath);
		free(o->geturl);
		free(o->objpath);
		ot = o;
		o = o->next;
		free(ot);
	}
}

void system1_print(struct pv_state *this)
{
	if (!this)
		return;

	// print
	struct pv_platform *p = this->platforms;
	pv_log(DEBUG, "kernel: '%s'\n", this->kernel);
	pv_log(DEBUG, "initrd: '%s'\n", this->initrd);
	while (p) {
		pv_log(DEBUG, "platform: '%s'\n", p->name);
		pv_log(DEBUG, "  type: '%s'\n", p->type);
		pv_log(DEBUG, "  configs:\n");
		char **config = p->configs;
		while (config && *config) {
			pv_log(DEBUG, "    '%s'\n", *config);
			config++;
		}
		p = p->next;
	}
	struct pv_volume *v = this->volumes;
	while (v) {
		pv_log(DEBUG, "volume: '%s'\n", v->name);
		pv_log(DEBUG, "  type: '%d'\n", v->type);

		v = v->next;
	}
	struct pv_object *o = this->objects;
	while (o) {
		pv_log(DEBUG, "object: \n");
		pv_log(DEBUG, "  name: '%s'\n", o->name);
		pv_log(DEBUG, "  name: '%s'\n", o->id);
		o = o->next;
	}
}

struct pv_state* system1_parse(struct pantavisor *pv, struct pv_state *this, char *buf, int rev)
{
	int tokc, ret, count, n;
	char *key = 0, *value = 0, *ext = 0;
	jsmntok_t *tokv;
	jsmntok_t **k, **keys;

	// Parse full state json
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	count = json_get_key_count(buf, "bsp/run.json", tokv, tokc);
	if (!count || (count > 1)) {
		pv_log(WARN, "Invalid bsp/run.json count in state");
		goto out;
	}

	value = get_json_key_value(buf, "bsp/run.json", tokv, tokc);
	if (!value) {
		pv_log(WARN, "Unable to get pantavisor.json value from state");
		goto out;
	}

	this->rev = rev;

	if (!parse_bsp(this, value, strlen(value))) {
		free(this);
		this = 0;
		goto out;
	}
	free(value);

	keys = jsmnutil_get_object_keys(buf, tokv);
	k = keys;

	// platform head is pv->state->platforms
	while (*k) {
		n = (*k)->end - (*k)->start;

		// avoid pantavisor.json and #spec special keys
		if (!strncmp("bsp/run.json", buf+(*k)->start, n) ||
		    !strncmp("#spec", buf+(*k)->start, n)) {
			k++;
			continue;
		}

		// copy key
		key = malloc(n+1);
		snprintf(key, n+1, "%s", buf+(*k)->start);

		// copy value
		n = (*k+1)->end - (*k+1)->start;
		value = malloc(n+1);
		snprintf(value, n+1, "%s", buf+(*k+1)->start);

		// check extension in case of file (json=platform, other=file)
		ext = strrchr(key, '/');
		if (ext && !strcmp(ext, "/run.json")) {
			parse_platform(this, value, strlen(value));
		} else if ((ext = strrchr(key, '.')) && !strcmp(ext, ".json")) {
			pv_log(DEBUG, "skipping '%s'\n", key);
		} else {
			pv_objects_add(this, key, value, pv->config->storage.mntpoint);
		}

		// free intermediates
		if (key) {
			free(key);
			key = 0;
		}
		if (value) {
			free(value);
			value = 0;
		}
		k++;
	}
	jsmnutil_tokv_free(keys);

	// copy buffer
	this->json = strdup(buf);

	system1_print(this);

	// remove platforms that have no loaded data
	pv_platforms_remove_not_done(this);

out:
	if (key)
		free(key);
	if (value)
		free(value);
	if (tokv)
		free(tokv);

	return this;
}
