/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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

#define MODULE_NAME             "parser-embed1"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "addons.h"
#include "platforms.h"
#include "volumes.h"
#include "objects.h"
#include "jsons.h"
#include "json.h"
#include "pantavisor.h"
#include "parser.h"
#include "parser_bundle.h"
#include "group.h"
#include "condition.h"
#include "state.h"
#include "pvlogger.h"

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
	buf = memcpy(buf, value, n);

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	s->bsp.img.ut.fit = pv_json_get_value(buf, "fit", tokv, tokc);
	if (!s->bsp.img.ut.fit) {
		s->bsp.img.std.kernel = pv_json_get_value(buf, "linux", tokv, tokc);
		s->bsp.img.std.fdt = pv_json_get_value(buf, "fdt", tokv, tokc);
		s->bsp.img.std.initrd = pv_json_get_value(buf, "initrd", tokv, tokc);
	}
	s->bsp.firmware = pv_json_get_value(buf, "firmware", tokv, tokc);
	s->bsp.modules = pv_json_get_value(buf, "modules", tokv, tokc);

	if (s->bsp.firmware) {
		v = pv_volume_add(s, s->bsp.firmware);
		v->plat = NULL;
		v->type = VOL_LOOPIMG;
	}

	if (s->bsp.modules) {
		v = pv_volume_add(s, s->bsp.modules);
		v->plat = NULL;
		v->type = VOL_LOOPIMG;
	}

	if ((!s->bsp.img.std.kernel || !s->bsp.img.std.initrd) && !s->bsp.img.ut.fit) {
		pv_log(ERROR, "kernel or initrd not configured in bsp/run.json. Cannot continue.", strlen(buf), buf);
		ret = 0;
		goto out;
	}

	// get addons and create empty items
	key = jsmnutil_get_object_keys(buf, tokv);
	if (!key) {
		pv_log(ERROR, "addon list cannot be parsed");
		ret = 0;
		goto out;
	}

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

	ret = 1;

out:
	if (tokv)
		free(tokv);
	if (buf)
		free(buf);

	return ret;
}

static struct pv_condition* parse_condition(struct pv_state *s, char *value)
{
	char *key = NULL, *val = NULL, *plat = NULL;
	struct pv_condition *c = NULL;
	jsmntok_t *condv;
	int condc;

	pv_log(DEBUG, "condition %s", value);

	if (jsmnutil_parse_json(value, &condv, &condc) <= 0) {
		pv_log(ERROR, "wrong format condition");
		goto out;
	}

	key = pv_json_get_value(value, "key", condv, condc);
	if (!key) {
		pv_log(ERROR, "key not found in condition");
		goto out;
	}

	val = pv_json_get_value(value, "value", condv, condc);
	if (!val) {
		pv_log(ERROR, "value not found in condition");
		goto out;
	}

	plat = pv_json_get_value(value, "container", condv, condc);
	// accept all containers by default
	if (!plat)
		plat = strdup("*");

	c = pv_state_fetch_condition_value(s, plat, key, value);
	if (c) {
		pv_log(DEBUG, "condition found in state");
		goto out;
	}

	c = pv_condition_new(plat, key, val);
	if (!c) {
		pv_log(ERROR, "could not create a new condition");
		goto out;
	}

	pv_state_add_condition(s, c);

out:
	if (plat)
		free(plat);
	if (key)
		free(key);
	if (val)
		free(val);
	return c;
}

static int parse_platform_conditions(struct pv_state *s, struct pv_platform *p, char *value)
{
	struct pv_condition *c;
	char *str = NULL;
	int ret = 0, tokc;
	jsmntok_t *tokv = NULL, **t = NULL, **i = NULL;

	pv_log(DEBUG, "platform conditions %s", value);

	if (jsmnutil_parse_json(value, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format platform conditions");
		goto out;
	}

	t = jsmnutil_get_array_toks(value, tokv);
	i = t;
	while (*i) {
		str = pv_json_get_one_str(value, i);
		if (!str)
			break;

		c = parse_condition(s, str);
		if (!c)
			goto out;

		pv_platform_add_condition(p, c);

		free(str);
		str = NULL;

		i++;
	}

	ret = 1;

out:
	if (str)
		free(str);
	if (t)
		jsmnutil_tokv_free(t);
	if (tokv)
		free(tokv);

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
		return 0;

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	keys = jsmnutil_get_object_keys(buf, tokv);
	if (!keys) {
		pv_log(ERROR, "storage list cannot be parsed");
		return 0;
	}
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
		pt = pv_json_get_value(value, "persistence", tokv_t, tokc);

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

static int do_action_for_name(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = 
		(struct platform_bundle*) jka->opaque;

	if (!value)
		goto fail;

	*bundle->platform = pv_platform_add(bundle->s, value);

	if (! (*bundle->platform))
		goto fail;
	return 0;
fail:
	return -1;
}

static int do_action_for_type(struct json_key_action *jka,
					char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;
	(*bundle->platform)->type = strdup(value);
	return 0;
}

static int do_action_for_runlevel(struct json_key_action *jka,
					char *value)
{
	struct pv_group *g;
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;

	// runlevel is still valid in the state json to keep backwards compatibility, but internally it is substituted by groups
	if (!strcmp(value, "data") ||
		!strcmp(value, "root") ||
		!strcmp(value, "app") ||
		!strcmp(value, "platform")) {
		pv_log(DEBUG, "linking platform %s with group %s", (*bundle->platform)->name, value);

		g = pv_state_fetch_group(bundle->s, value);
		if (!g) {
			pv_log(ERROR, "could not find group %s", value);
			return -1;
		}
		(*bundle->platform)->group = g;
	} else {
		pv_log(WARN, "invalid runlevel value '%s' for platform '%s'", value, (*bundle->platform)->name);
	}

	return 0;
}

static int do_action_for_group(struct json_key_action *jka, char *value)
{
	struct pv_group *g;
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;

	pv_log(DEBUG, "linking platform %s with group %s", (*bundle->platform)->name, value);

	g = pv_state_fetch_group(bundle->s, value);
	if (!g) {
		pv_log(ERROR, "could not find group %s", value);
		return -1;
	}
	(*bundle->platform)->group = g;

	return 0;
}

static int do_action_for_roles_object(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;

	if (*bundle->platform)
		(*bundle->platform)->mgmt = false;

	return 0;
}

static int do_action_for_roles_array(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;
	bool value_alloced = false;
	int ret = -1;


	if (!value && (jka->type == JSMN_ARRAY)) {
		value = pv_json_get_one_str(jka->buf, &jka->tokv);
		value_alloced = true;
	}

	if (!(*bundle->platform) || !value)
		goto out;

	pv_log(DEBUG, "setting role %s to platform %s", value, (*bundle->platform)->name);
	if (!strcmp(value, "mgmt"))
		(*bundle->platform)->mgmt = true;
	else
		pv_log(WARN, "invalid role value '%s'", value);

	ret = 0;

out:
	if (value_alloced && value)
		free(value);
	return ret;
}

static int do_action_for_one_volume(struct json_key_action *jka,
					char *value)
{
	/*
	 * Opaque will contain the platform
	 * */
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;
	struct pv_volume *v = NULL;
	bool value_alloced = false;
	int ret = 0;

	/*
	 * for root-volume value will be provided.
	 * */
	if (!value && jka->type == JSMN_ARRAY) {
		value = pv_json_get_one_str(jka->buf, &jka->tokv);
		value_alloced = true;
	}

	if (!value) {
		ret = -1;
		goto fail;
	}

	if (!(*bundle->platform)) {
		ret = -1;
		goto fail;
	}
	v = pv_volume_add(bundle->s, value);
	if (!v) {
		ret = -1;
		goto fail;
	}
	v->plat = *bundle->platform;
	v->type = VOL_LOOPIMG;
fail:
	if (value_alloced && value)
		free(value);
	return ret;
}

static int do_action_for_one_log(struct json_key_action *jka,
					char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;
	struct pv_platform *platform = *bundle->platform;
	int ret = 0, i;
	struct pv_logger_config *config = NULL;
	const int key_count = 
		jsmnutil_object_key_count(jka->buf, jka->tokv);
	jsmntok_t **keys = jsmnutil_get_object_keys(jka->buf, jka->tokv);
	jsmntok_t **keys_i = keys;

	if (!key_count || !keys) {
		pv_log(ERROR, "logs cannot be parsed");
		ret = -1;
		goto free_config;
	}

	config = (struct pv_logger_config*)calloc(1, sizeof(*config));
	if (!config) {
		ret = -1;
		goto free_config;
	}

	config->pair = (const char ***)calloc(key_count + 1, sizeof(char*));
	if (!config->pair) {
		ret = -1;
		goto free_config;
	}
	/*
	 * Allocate 2D configuration array..
	 * config->pair[i][0] = key
	 * config->pair[i][1] = value
	 * */
	for ( i = 0; i < key_count + 1; i++) {
		config->pair[i] = (const char**)calloc(2, sizeof(char*));
		if (!config->pair[i]) {
			while (i) {
				i -= 1;
				free(config->pair[i]);
			}
			free(config->pair);
			ret = -1;
			goto free_config;
		}
	}
	/*
	 * Populate the values
	 * */
	i = 0;
	while (*keys_i && (i < key_count + 1)) {
		char *value = NULL;
		char *key = NULL;
		jsmntok_t *val_tok = *keys_i + 1;

		key = pv_json_get_one_str(jka->buf, keys_i);
		value = pv_json_get_one_str(jka->buf, &val_tok);
		
		pv_log(DEBUG, "Got log value as %s-%s", key, value);
		if (value) {
			config->pair[i][0] = key;
			config->pair[i][1] = value;
			i++;
		}else if (key) {
			free(key);
		}
		keys_i++;
	}
	if (keys)
		jsmnutil_tokv_free(keys);
	dl_list_init(&config->item_list);
	dl_list_add(&platform->logger_configs, &config->item_list);
	return 0;
free_config:
	if (keys)
		jsmnutil_tokv_free(keys);
	if (config)
		free(config);
	return ret;
}

static int do_action_for_storage(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;
	/*
	 * BUG_ON(value)
	 * */
	value = jka->buf;
	if (value)
		parse_storage(bundle->s, *bundle->platform, value);
	return 0;
}

static int do_action_for_conditions(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;

	if (!parse_platform_conditions(bundle->s, *bundle->platform, value)) {
		pv_log(ERROR, "could not parse platform conditions");
		return -1;
	}

	return 0;
}

static int parse_platform(struct pv_state *s, char *buf, int n)
{
	char *config = NULL, *shares = NULL;
	struct pv_platform *this;
	int ret = 0;
	struct platform_bundle bundle = {
		.s = s,
		.platform = &this,
	};

	struct json_key_action embed1_platform_key_action [] = {
		ADD_JKA_ENTRY("name", JSMN_STRING, &bundle, do_action_for_name, false),
		ADD_JKA_ENTRY("type", JSMN_STRING, &bundle, do_action_for_type, false),
		ADD_JKA_ENTRY("runlevel", JSMN_STRING, &bundle, do_action_for_runlevel, false),
		ADD_JKA_ENTRY("group", JSMN_STRING, &bundle, do_action_for_group, false),
		ADD_JKA_ENTRY("roles", JSMN_OBJECT, &bundle, do_action_for_roles_object, false),
		ADD_JKA_ENTRY("roles", JSMN_ARRAY, &bundle, do_action_for_roles_array, false),
		ADD_JKA_ENTRY("config", JSMN_STRING, &config, NULL, true),
		ADD_JKA_ENTRY("share", JSMN_STRING, &shares, NULL, true),
		ADD_JKA_ENTRY("root-volume", JSMN_STRING, &bundle, do_action_for_one_volume, false),
		ADD_JKA_ENTRY("volumes", JSMN_ARRAY, &bundle, do_action_for_one_volume, false),
		ADD_JKA_ENTRY("logs", JSMN_ARRAY, &bundle, do_action_for_one_log, false),
		ADD_JKA_ENTRY("storage", JSMN_OBJECT, &bundle, do_action_for_storage, false),
		ADD_JKA_ENTRY("conditions", JSMN_STRING, &bundle, do_action_for_conditions, false),
		ADD_JKA_NULL_ENTRY()
	};

	ret = start_json_parsing_with_action(buf, embed1_platform_key_action, JSMN_OBJECT);
	if (!this || ret)
		goto out;
	
	// free intermediates
	if (config) {
		this->configs = calloc(1, 2 * sizeof(char *));
		this->configs[1] = NULL;
		this->configs[0] = strdup(config);
		free(config);
		config = 0;
	}

	pv_platform_set_ready(this);
out:
	if (config)
		free(config);
	return ret;
}

static void embed1_link_object_json_platforms(struct pv_state *s)
{
	struct pv_json *j, *tmp_j;
	struct dl_list *new_jsons = &s->jsons;
	struct pv_object *o, *tmp_o;
	struct dl_list *new_objects = &s->objects;
	char *name, *dir;

	// link objects
	if (!new_objects)
		goto link_jsons;
	dl_list_for_each_safe(o, tmp_o, new_objects,
		struct pv_object, list) {
		name = strdup(o->name);
		dir = strtok(name, "/");
		if (!strcmp(dir, "_config"))
			dir = strtok(NULL, "/");
		o->plat = pv_state_fetch_platform(s, dir);
		free(name);
	}

link_jsons:
	if (!new_jsons)
		return;
	dl_list_for_each_safe(j, tmp_j, new_jsons,
		struct pv_json, list) {
		name = strdup(j->name);
		dir = strtok(name, "/");
		if (!strcmp(dir, "_config"))
			dir = strtok(NULL, "/");
		j->plat = pv_state_fetch_platform(s, dir);
		free(name);
	}
}

struct pv_state* embed1_parse(struct pv_state *this, const char *buf)
{
	int tokc, ret, n;
	char *key = 0, *value = 0, *ext = 0;
	jsmntok_t *tokv;
	jsmntok_t **k, **keys;

	// Parse full state json
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);

	keys = jsmnutil_get_object_keys(buf, tokv);
	if (!keys) {
		pv_log(ERROR, "json cannot be parsed");
		this = NULL;
		goto out;
	}
	k = keys;

	// platform head is pv->state->platforms
	while (*k) {
		n = (*k)->end - (*k)->start;

		// avoid pantavisor.json and #spec special keys
		if (!strncmp("#spec", buf+(*k)->start, n)) {
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
		// if the extension is run.json, we have a new platform
		if (ext && !strcmp(ext, "/run.json")) {
			pv_log(DEBUG, "parsing and adding json '%s'", key);
			if (parse_platform(this, value, strlen(value))) {
				this = NULL;
				goto out;
			}
			pv_jsons_add(this, key, value);
		// if the extension is either src.json or build.json, we ignore it
		} else if (ext && (!strcmp(ext, "/src.json") ||
					!strcmp(ext, "/build.json"))) {
			pv_log(DEBUG, "skipping '%s'", key);
		// if the extension is other .json, we add it to the list of jsons
		} else if ((ext = strrchr(key, '.')) && !strcmp(ext, ".json")) {
			pv_log(DEBUG, "adding json '%s'", key);
			pv_jsons_add(this, key, value);
		// everything else is added to the list of objects
		} else {
			pv_log(DEBUG, "adding object '%s'", key);
			pv_objects_add(this, key, value, pv_config_get_storage_mntpoint());
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

	embed1_link_object_json_platforms(this);

	pv_state_validate(this);

	pv_state_print(this);

out:
	if (key)
		free(key);
	if (value)
		free(value);
	if (tokv)
		free(tokv);

	return this;
}

static char* parse_config_name(char *value, int n)
{
	int tokc;
	char *buf;
	jsmntok_t *tokv;
	char* config_name = NULL;

	// take null terminate copy of item to parse
	buf = calloc(1, (n+1) * sizeof(char));
	buf = memcpy(buf, value, n);

	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0)
		return NULL;

	config_name = pv_json_get_value(buf, "initrd_config", tokv, tokc);

	if (tokv)
		free(tokv);
	if (buf)
		free(buf);

	return config_name;
}

char* embed1_parse_initrd_config_name(const char *buf)
{
	int tokc, count;
	jsmntok_t *tokv;
	char *value, *config_name = NULL;

	// Parse full state json
	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0)
		return NULL;

	count = pv_json_get_key_count(buf, "bsp/run.json", tokv, tokc);
	if (!count || (count > 1))
		return NULL;

	value = pv_json_get_value(buf, "bsp/run.json", tokv, tokc);
	if (!value)
		return NULL;

	config_name = parse_config_name(value, strlen(value));

	if (value)
		free(value);
	if (tokv)
		free(tokv);

	return config_name;
}
