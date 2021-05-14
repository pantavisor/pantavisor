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

#define MODULE_NAME             "parser-multi1"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"
#include "addons.h"
#include "platforms.h"
#include "volumes.h"
#include "objects.h"
#include "pantavisor.h"
#include "parser.h"
#include "state.h"
#include "json.h"

#define PV_NS_NETWORK	0x1
#define PV_NS_UTS	0x2
#define PV_NS_IPC	0x4

typedef struct ns_share_t { char *name; unsigned long val; } ns_share_t;
ns_share_t ns_share[] = {
	{ "NETWORK", PV_NS_NETWORK },
	{ "UTS", PV_NS_UTS },
	{ "IPC", PV_NS_IPC },
	{ NULL, 0xff }
};

static unsigned long ns_share_flag(char *key)
{
	for (ns_share_t *ns = ns_share; ns->name != NULL; ns++) {
		if (!strcmp(ns->name, key))
			return ns->val;
	}

	return 0;
}

static int parse_pantavisor(struct pv_state *s, char *value, int n)
{
	int c;
	int ret = 0, tokc, size;
	char *str, *buf;
	jsmntok_t *tokv;
	jsmntok_t **key, **key_i;

	// take null terminate copy of item to parse
	buf = calloc(1, (n+1) * sizeof(char));
	buf = memcpy(buf, value, n);

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	s->bsp.kernel = pv_json_get_value(buf, "linux", tokv, tokc);
	s->bsp.fdt = pv_json_get_value(buf, "fdt", tokv, tokc);
	s->bsp.initrd = pv_json_get_value(buf, "initrd", tokv, tokc);
	s->bsp.firmware = pv_json_get_value(buf, "firmware", tokv, tokc);

	if (!s->bsp.kernel || !s->bsp.initrd)
		goto out;

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
		while ((str = pv_json_array_get_one_str(buf, &size, &k)))
			pv_addon_add(s, str);

		break;
	}
	jsmnutil_tokv_free(key);

	// get platforms and create empty items
	key = jsmnutil_get_object_keys(buf, tokv);
	key_i = key;
	while (*key_i) {
		c = (*key_i)->end - (*key_i)->start;
		if (strncmp("platforms", buf+(*key_i)->start, strlen("platforms"))) {
			key_i++;
			continue;
		}

		// parse array data
		jsmntok_t *k = (*key_i+2);
		size = (*key_i+1)->size;
		while ((str = pv_json_array_get_one_str(buf, &size, &k)))
			pv_platform_add(s, str);

		break;
	}
	jsmnutil_tokv_free(key);

	// get volumes and create empty items
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
		while ((str = pv_json_array_get_one_str(buf, &size, &k))) {
			struct pv_volume *v = pv_volume_add(s, str);
			v->type = VOL_LOOPIMG;
			free(str);
		}

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

static int parse_platform(struct pv_state *s, char *buf, int n)
{
	int i;
	int tokc, ret, size;
	jsmntok_t *tokv, *t;
	char *name, *str;
	char *configs, *shares;
	struct pv_platform *this;

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	name = pv_json_get_value(buf, "name", tokv, tokc);

	this = pv_platform_get_by_name(s, name);
	if (!this)
		goto out;

	this->type = pv_json_get_value(buf, "type", tokv, tokc);
	this->exec = pv_json_get_value(buf, "exec", tokv, tokc);

	configs = pv_json_get_value(buf, "configs", tokv, tokc);
	shares = pv_json_get_value(buf, "share", tokv, tokc);

	// free intermediates
	if (name) {
		free(name);
		name = 0;
	}
	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	ret = jsmnutil_parse_json(configs, &tokv, &tokc);
	size = jsmnutil_array_count(buf, tokv);
	t = tokv+1;
	this->configs = calloc(1, (size + 1) * sizeof(char *));
	this->configs[size] = NULL;
	i = 0;
	while ((str = pv_json_array_get_one_str(configs, &size, &t))) {
		this->configs[i] = str;
		i++;
	}

	// free intermediates
	if (configs) {
		free(configs);
		configs = 0;
	}
	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	ret = jsmnutil_parse_json(shares, &tokv, &tokc);
	size = jsmnutil_array_count(shares, tokv);
	t = tokv+1;
	this->ns_share = 0;
	while ((str = pv_json_array_get_one_str(shares, &size, &t))) {
		this->ns_share |= ns_share_flag(str);
		free(str);
		i++;
	}

	// free intermediates
	if (shares) {
		free(shares);
		shares = 0;
	}
	if (tokv) {
		free(tokv);
		tokv = 0;
	}

	this->status = PLAT_INSTALLED;

out:
	if (name)
		free(name);
	if (tokv)
		free(tokv);

	return 0;
}

struct pv_state* multi1_parse(struct pantavisor *pv, struct pv_state *this, char *buf)
{
	int tokc, ret, count, n;
	char *key = 0, *value = 0, *ext = 0;
	jsmntok_t *tokv;
	jsmntok_t **k, **keys;

	// Parse full state json
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	count = pv_json_get_key_count(buf, "pantavisor.json", tokv, tokc);
	if (!count || (count > 1)) {
		pv_log(WARN, "Invalid pantavisor.json count in state (%d)", count);
		goto out;
	}

	value = pv_json_get_value(buf, "pantavisor.json", tokv, tokc);
	if (!value) {
		pv_log(WARN, "Unable to get pantavisor.json value from state");
		goto out;
	}

	if (!parse_pantavisor(this, value, strlen(value))) {
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
		if (!strncmp("pantavisor.json", buf+(*k)->start, n) ||
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
		ext = strrchr(key, '.');
		if (ext && !strcmp(ext, ".json"))
			parse_platform(this, value, strlen(value));
		else
			pv_objects_add(this, key, value, pv_config_get_storage_mntpoint());

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

	pv_state_print(this);

	// remove platforms that have no loaded data
	pv_platforms_remove_not_installed(this);

out:
	if (key)
		free(key);
	if (value)
		free(value);
	if (tokv)
		free(tokv);

	return this;
}

char* multi1_parse_initrd_config_name(char *buf)
{
	return NULL;
}
