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
#include "jsons.h"
#include "pantavisor.h"
#include "parser.h"
#include "parser_bundle.h"
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

	s->bsp.kernel = get_json_key_value(buf, "linux", tokv, tokc);
	s->bsp.fdt = get_json_key_value(buf, "fdt", tokv, tokc);
	s->bsp.initrd = get_json_key_value(buf, "initrd", tokv, tokc);
	s->bsp.firmware = get_json_key_value(buf, "firmware", tokv, tokc);
	s->bsp.modules = get_json_key_value(buf, "modules", tokv, tokc);

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

	if (!s->bsp.kernel || !s->bsp.initrd) {
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

static int do_json_key_action_object(struct json_key_action *jka)
{
	int  ret = 0;

	if (jka->action)
		ret = jka->action(jka, NULL);
	return ret;
}

static void do_json_key_action_save(struct json_key_action *jka, char *value)
{
	if (jka->opaque) {
		*jka->opaque = strdup(value);
	}
}

/*
 * For arrays, the callback provided will be called
 * for all tokens found in array. Caller can define
 * the json structure to operate on in a similar way
 * and may use start_json_parsing_with_action again,
 * provided the array is a object. Otherwise caller needs
 * to handle the keys passed using the jsmnutil_* functions.
 * */
static int do_json_key_action_array(struct json_key_action *jka)
{
	int i = 0, arr_count = 0, ret = 0;
	jsmntok_t **arr = NULL, **arr_i = NULL;
	jsmntok_t *array_token = jka->tokv;

	/*
	 * The only time it happens when
	 * json start is itself an array.
	 */
	if (jka->key != NULL)
		array_token += 1;
	arr_count = array_token->size;

	arr_i = arr = jsmnutil_get_array_toks(jka->buf, array_token);

	if (!arr_i) {
		ret = -1;
		goto out;
	}

	for ( i = 0; i < arr_count && !ret; i++, arr_i++) {
		jsmntok_t *prev_tok = jka->tokv;
		if (jka->action) {
			jka->tokv = *arr_i;/*This is the usable token*/
			/*
			 * Actions for arrays must be provided.
			 * The value is always NULL but action gets
			 * the next token which can be parsed by it.
			 * */
			ret = jka->action(jka, NULL);
		}
		jka->tokv = prev_tok;
	}
out:
	if (arr)
		jsmnutil_tokv_free(arr);
	return ret;
}

static int do_one_jka_action(struct json_key_action *jka)
{
	char *value = NULL;
	jsmntok_t* val_token = NULL;
	int ret = 0;
	int length = 0;
	char *buf = jka->buf;

	switch(jka->type) {
		case JSMN_STRING:
			val_token = jka->tokv + 1;
			value = json_get_one_str(buf, &val_token);
			if (jka->save)
				do_json_key_action_save(jka, value);

			if (jka->action)
				ret = jka->action(jka, value);
			free(value);
			break;

		case JSMN_ARRAY:
			ret = do_json_key_action_array(jka);
			break;

		case JSMN_OBJECT:
			//create a new buffer.
			length = (jka->tokv + 1)->end - (jka->tokv + 1)->start;
			value = (char*) calloc(1, sizeof(char) * (length + 1));
			if (value) {
				char *orig_buf = NULL;
				snprintf(value, length + 1, "%s",
						buf + (jka->tokv + 1)->start);
				orig_buf = jka->buf;
				jka->buf = value;
				ret = do_json_key_action_object(jka);
				free(value);
				jka->buf = orig_buf;
			}
			break;
		default:
			break;
	}
	return ret;
}

/*
 * check if key is present in keys.
 * returns the key from jsmntok_t **keys that matched.
 */
static jsmntok_t* do_lookup_json_key(jsmntok_t **keys, char *json_buf, char *key)
{
	bool found = false;
	jsmntok_t **keys_walker = NULL;

	if (!keys || !key)
		return NULL;
	keys_walker = keys;
	while(*keys_walker) {
		// copy key 
		char *curr_key = NULL;
		int length = 0;

		length = (*keys_walker)->end - (*keys_walker)->start;

		curr_key = (char*) calloc(1, sizeof(char) * (length + 1));
		if (!curr_key) {
			keys_walker++;
			continue;
		}
		snprintf(curr_key, length + 1, "%s",
				json_buf + (*keys_walker)->start);
		if (strncmp(curr_key, key, strlen(key)) == 0)
			found = true;
		free(curr_key);
		if (found)
			break;
		keys_walker++;
	}
	return found ? (*keys_walker) : NULL;
}

static int do_action_for_array(struct json_key_action *jka, char *value)
{
	/*
	 * real_jka is an array of other JKA's on which action
	 * needs to be performed.
	 */
	struct json_key_action *real_jka = (struct json_key_action*)jka->opaque;
	int ret = 0;
	jsmntok_t** keys;
	/*
	 * we only handle arrays of objects not nested
	 * arrays.
	 */
	keys = jsmnutil_get_object_keys(jka->buf, jka->tokv);
	if (!keys) {
		pv_log(ERROR, "array cannot be parsed");
		ret = -1;
		goto out;
	}
	while(real_jka->key && !ret) {
		real_jka->tokv = do_lookup_json_key(keys, jka->buf, real_jka->key);
		real_jka->tokc = jka->tokc;
		real_jka->buf = jka->buf;
		if (real_jka->tokv) {
			ret = do_one_jka_action(real_jka);
		}
		real_jka++;
	}
	jsmnutil_tokv_free(keys);
out:
	return ret;
}
int start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
					jsmntype_t type)
{
	return __start_json_parsing_with_action(buf, jka_arr, type, NULL, 0);
}

int __start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
						jsmntype_t type, 
						jsmntok_t *__tokv, int __tokc)
{
	jsmntok_t *tokv = NULL;
	int tokc, ret = 0;
	bool do_free = true;

	if (__tokv) {
		tokv = tokv;
		tokc = __tokc;
		do_free = false;
	}
	if (jka_arr) {
		jsmntok_t** keys;
		struct json_key_action *jka = jka_arr;
		
		if (!tokv) {
			ret = jsmnutil_parse_json(buf, &tokv, &tokc);
			if ( ret <= 0)
				goto out;
		}
		if (type == JSMN_ARRAY) {
			struct json_key_action __jka_arr = {
				.key = NULL,
				.action = do_action_for_array,
				.type = JSMN_ARRAY,
				.opaque = (void*)jka_arr,
				.buf = buf,
				.tokc = tokc,
				.tokv = tokv
			};
			ret = do_one_jka_action(&__jka_arr);
			jka->buf = NULL;
			jka->tokv = NULL;
			jka->tokc = 0;
			goto free_tokens;
		}

		if (type != JSMN_OBJECT) {
			ret = -1;
			goto free_tokens;
		}
		keys = jsmnutil_get_object_keys(buf, tokv);
		ret = 0;
		if (!keys) {
			pv_log(ERROR, "json cannot be parsed");
			ret = -1;
			goto free_tokens;
		}
		while ( !ret && jka->key ) {
			jka->tokc = tokc;
			jka->buf = buf;
			jka->tokv = do_lookup_json_key(keys, buf, jka->key);
			if (jka->tokv)
				ret = do_one_jka_action(jka);
			jka->tokv = NULL;
			jka->buf = NULL;
			jka++;
		}
		if (keys)
			jsmnutil_tokv_free(keys);
	}
free_tokens:
	if (tokv && do_free)
		free(tokv);
out:
	return ret;
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
	struct platform_bundle *bundle = (struct platform_bundle*) jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;

	if (!strcmp(value, "root"))
		(*bundle->platform)->runlevel = RUNLEVEL_ROOT;
	// runlevel PLATFORM is reserved for platforms without explicily configured runlevel
	else if (!strcmp(value, "app"))
		(*bundle->platform)->runlevel = RUNLEVEL_APP;
	else {
		pv_log(WARN, "invalid runlevel value '%s' for platform '%s'", value, (*bundle->platform)->name);
	}

	return 0;
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
		value = json_get_one_str(jka->buf, &jka->tokv);
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

		key = json_get_one_str(jka->buf, keys_i);
		value = json_get_one_str(jka->buf, &val_tok);
		
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

static int parse_platform(struct pv_state *s, char *buf, int n)
{
	char *config = NULL, *shares = NULL;
	struct pv_platform *this;
	int ret = 0;
	struct platform_bundle bundle = {
		.s = s,
		.platform = &this,
	};

	struct json_key_action system1_platform_key_action [] = {
		ADD_JKA_ENTRY("name", JSMN_STRING, &bundle, do_action_for_name, false),
		ADD_JKA_ENTRY("type", JSMN_STRING, &bundle, do_action_for_type, false),
		ADD_JKA_ENTRY("runlevel", JSMN_STRING, &bundle, do_action_for_runlevel, false),
		ADD_JKA_ENTRY("config", JSMN_STRING, &config, NULL, true),
		ADD_JKA_ENTRY("share", JSMN_STRING, &shares, NULL, true),
		ADD_JKA_ENTRY("root-volume", JSMN_STRING, &bundle, do_action_for_one_volume, false),
		ADD_JKA_ENTRY("volumes", JSMN_ARRAY, &bundle, do_action_for_one_volume, false),
		ADD_JKA_ENTRY("logs", JSMN_ARRAY, &bundle, do_action_for_one_log, false),
		ADD_JKA_ENTRY("storage", JSMN_OBJECT, &bundle, do_action_for_storage, false),
		ADD_JKA_NULL_ENTRY()
	};

	ret = start_json_parsing_with_action(buf, system1_platform_key_action, JSMN_OBJECT);
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

	this->status = PLAT_INSTALLED;
out:
	if (config)
		free(config);
	return ret;
}

static void system1_link_object_json_platforms(struct pv_state *s)
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
		if (!strcmp(dir, "_config")) {
			dir = strtok(NULL, "/");
			o->plat = pv_platform_get_by_name(s, dir);
			if (!o->plat) {
				pv_log(WARN, "discarding unassociated object '%s'", o->name);
				pv_objects_remove(o);
			}
		} else
			o->plat = pv_platform_get_by_name(s, dir);
		free(name);
	}

link_jsons:
	if (!new_jsons)
		return;
	dl_list_for_each_safe(j, tmp_j, new_jsons,
		struct pv_json, list) {
		name = strdup(j->name);
		dir = strtok(name, "/");
		if (!strcmp(dir, "_config")) {
			dir = strtok(NULL, "/");
			j->plat = pv_platform_get_by_name(s, dir);
			if (!j->plat) {
				pv_log(WARN, "discarding unassociated json '%s'", j->name);
				pv_jsons_remove(j);
			}
		} else
			j->plat = pv_platform_get_by_name(s, dir);
		free(name);
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
		this = NULL;
		goto out;
	}

	value = get_json_key_value(buf, "bsp/run.json", tokv, tokc);
	if (!value) {
		pv_log(WARN, "Unable to get bsp/run.json value from state");
		this = NULL;
		goto out;
	}

	pv_log(DEBUG, "adding json 'bsp/run.json'");
	pv_jsons_add(this, "bsp/run.json", value);

	this->rev = rev;

	if (!parse_bsp(this, value, strlen(value))) {
		this = NULL;
		goto out;
	}
	free(value);
	value = NULL;

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

	system1_link_object_json_platforms(this);

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
