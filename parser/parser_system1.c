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
#include "parser_bundle.h"

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

	pv_log(DEBUG, "calling %s buf =%s\n", __func__, buf);
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

static int do_json_key_action_object(struct json_key_action *jka)
{
	int  ret = 0;

	ret = jsmnutil_parse_json(jka->buf, &jka->tokv, &jka->tokc);
	if (ret <= 0) {
		ret = -1;
		goto free_tokens;
	}
	if (jka->action)
		ret = jka->action(jka, NULL);
free_tokens:
	if (jka->tokv)
		free(jka->tokv);
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
	jsmntok_t *array_token = jka->tokv + 1;

	arr_count = array_token->size;

	arr_i = arr = jsmnutil_get_array_toks(jka->buf, array_token);

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

static int start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
						jsmntype_t type)
{
	jsmntok_t *tokv;
	int tokc, ret = 0;

	if (jka_arr) {
		jsmntok_t** keys;
		jsmntok_t** keys_i;
		struct json_key_action *jka = jka_arr;
		
		ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	
		if ( ret <= 0)
			goto out;
		if (type != JSMN_OBJECT) {
			ret = -1;
			goto free_tokens;
		}

		keys = jsmnutil_get_object_keys(buf, tokv);
		keys_i = keys;
		ret = 0;
		while ( !ret && jka->key ) {
			bool found = false;
			int length = 0;
			char *key = NULL;
			
			keys = keys_i;
			jka->tokc = tokc;
			jka->buf = buf;

			while(*keys && !ret && !found) {
				length = (*keys)->end - (*keys)->start;

				// copy key 
				key = (char*) calloc(1,
						sizeof(char) * (length + 1));
				if (!key) {
					ret = -1;
					break;
				}
				snprintf(key, length + 1, "%s",
						buf + (*keys)->start);
				if (strncmp(jka->key, key,
							strlen(jka->key)) != 0)
					goto skip;

				jka->tokv = (*keys); /*tokv is the matched key*/
				found = true;
				ret = do_one_jka_action(jka);
skip:
				free(key);
				keys++;
			}
			jka->tokv = NULL;
			jka->buf = NULL;
			jka++;
		}
		if (keys_i)
			jsmnutil_tokv_free(keys_i);
	}
free_tokens:
	if (tokv)
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
	pv_log(DEBUG, "Added volume %s to platform %s\n",
			v->name, (*bundle->platform)->name);
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

	if (!key_count) {
		ret = 0;
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
		
		pv_log(DEBUG, "Got log value as %s-%s\n", key, value);
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

	this->json = strdup(buf);
	this->done = true;
out:
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
	pv_objects_remove_all(this);
}

void system1_print(struct pv_state *this)
{
	if (!this)
		return;

	// print
	struct pv_platform *p = this->platforms;
	struct pv_object *curr;
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
	
	pv_objects_iter_begin(this, curr) {
		pv_log(DEBUG, "object: \n");
		pv_log(DEBUG, "  name: '%s'\n", curr->name);
		pv_log(DEBUG, "  id: '%s'\n", curr->id);
	}
	pv_objects_iter_end;
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