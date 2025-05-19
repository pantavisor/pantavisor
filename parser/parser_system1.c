/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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
#include <errno.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <jsmn/jsmnutil.h>

#define MODULE_NAME "parser-system1"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#include "parser_system1.h"
#include "addons.h"
#include "platforms.h"
#include "volumes.h"
#include "disk/disk.h"
#include "objects.h"
#include "jsons.h"
#include "json.h"
#include "pantavisor.h"
#include "parser_bundle.h"
#include "group.h"
#include "drivers.h"
#include "state.h"
#include "pvlogger.h"
#include "paths.h"

#include "utils/str.h"
#include "utils/fs.h"

#define PV_NS_NETWORK 0x1
#define PV_NS_UTS 0x2
#define PV_NS_IPC 0x4

static int parse_one_driver(struct pv_state *s, char *buf)
{
	int i = 0, tokc, tokc_t, n, size, ret;
	char *key, *value, *str;
	char **modules;
	jsmntok_t *tokv, *tokv_t, *t;
	jsmntok_t **k, **keys;

	if (!buf)
		return 0;

	jsmnutil_parse_json(buf, &tokv, &tokc);

	keys = jsmnutil_get_object_keys(buf, tokv);
	if (!keys) {
		pv_log(ERROR, "driver entry cannot be parsed");
		return 0;
	}
	k = keys;

	while (*k) {
		n = (*k)->end - (*k)->start;

		// copy key
		key = malloc(n + 1);
		snprintf(key, n + 1, "%s", buf + (*k)->start);

		// copy modules array
		n = (*k + 1)->end - (*k + 1)->start;
		value = malloc(n + 1);
		snprintf(value, n + 1, "%s", buf + (*k + 1)->start);

		if (jsmnutil_parse_json(value, &tokv_t, &tokc_t) < 0) {
			free(value);
			free(key);
			pv_log(ERROR, "wrong format filter");
			ret = 0;
			goto out;
		}

		size = jsmnutil_array_count(value, tokv_t);
		if (size < 0) {
			pv_log(WARN, "wrong alias count, not including");
			free(value);
			free(key);
			free(tokv_t);
			k++;
			continue;
		}

		modules = calloc(size + 1, sizeof(char *));
		t = tokv_t + 1;
		i = 0;
		while ((str = pv_json_array_get_one_str(value, &size, &t))) {
			pv_log(DEBUG, "%s %d", str, i);
			modules[i] = strdup(str);
			free(str);
			i++;
		}

		// add drivers rentry
		pv_drivers_add(s, key, i, modules);

		if (modules) {
			char **mod_t = modules;
			while (*mod_t) {
				free(*mod_t);
				mod_t++;
			}
			free(modules);
			modules = 0;
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
		if (tokv_t) {
			free(tokv_t);
			tokv_t = NULL;
		}
		k++;
	}
	ret = 1;
out:
	if (tokv)
		free(tokv);
	jsmnutil_tokv_free(keys);

	return ret;
}

static bool driver_should_parse(char *key)
{
	const char *fitconfig = pv_config_get_str(PV_BOOTLOADER_FITCONFIG);

	pv_log(DEBUG, "fitconfig=%s", fitconfig);
	if (!strcmp(key, "all") ||
	    (fitconfig && !strcmp(key + strlen("fitconfig:"), fitconfig))) {
		pv_log(DEBUG, "parsing '%s'...", key);
		return true;
	}

	return false;
}

static int parse_bsp_drivers(struct pv_state *s, char *v, int len)
{
	int tokc, n;
	char *buf, *key, *value = NULL;
	jsmntok_t *tokv;
	jsmntok_t **k, **keys;

	// take null terminate copy of item to parse
	buf = calloc(len + 1, sizeof(char));

	if (!buf)
		return 0;

	buf = memcpy(buf, v, len);

	jsmnutil_parse_json(buf, &tokv, &tokc);

	keys = jsmnutil_get_object_keys(buf, tokv);
	if (!keys) {
		pv_log(ERROR, "drivers list cannot be parsed");
		free(buf);
		return 0;
	}
	k = keys;

	while (*k) {
		n = (*k)->end - (*k)->start;

		// check key for [all,dtb:*,overlay:*]
		key = malloc(n + 1);
		snprintf(key, n + 1, "%s", buf + (*k)->start);

		if (driver_should_parse(key)) {
			// copy value
			n = (*k + 1)->end - (*k + 1)->start;
			value = malloc(n + 1);
			snprintf(value, n + 1, "%s", buf + (*k + 1)->start);
			if (!parse_one_driver(s, value)) {
				pv_log(ERROR, "unable to parse drivers");
				free(key);
				free(value);
				free(buf);
				free(tokv);
				jsmnutil_tokv_free(keys);
				return 0;
			}
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

	if (buf)
		free(buf);
	if (tokv)
		free(tokv);

	return 1;
}

static pv_disk_format_t parse_disks_get_format(const char *str,
					       jsmntok_t *diskv, int diskc)
{
	char *format_str = pv_json_get_value(str, "format", diskv, diskc);
	pv_disk_format_t format = pv_disk_str_to_format(format_str);
	free(format_str);
	return format;
}

static pv_disk_t parse_disks_get_type(const char *str, jsmntok_t *diskv,
				      int diskc)
{
	char *type_str = pv_json_get_value(str, "type", diskv, diskc);
	pv_disk_t type = pv_disk_str_to_type(type_str);
	free(type_str);
	return type;
}

static bool parse_disks_get_default(const char *str, jsmntok_t *diskv,
				    int diskc)
{
	bool ret = false;
	char *default_str = pv_json_get_value(str, "default", diskv, diskc);

	if (default_str && !strcmp(default_str, "yes"))
		ret = true;

	free(default_str);

	return ret;
}

static int parse_disks(struct pv_state *s, char *value)
{
	int tokc, size, ret = 1;
	char *str = NULL;
	jsmntok_t *tokv, *t, *diskv = NULL;

	if (jsmnutil_parse_json(value, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format filter");
		goto out;
	}

	size = jsmnutil_array_count(value, tokv);
	if (size <= 0) {
		pv_log(ERROR, "empty disks array %s %d", value, size);
		goto out;
	}

	t = tokv + 1;
	while ((str = pv_json_array_get_one_str(value, &size, &t))) {
		struct pv_disk *d;
		int diskc;

		if (jsmnutil_parse_json(str, &diskv, &diskc) <= 0) {
			pv_log(ERROR, "Invalid disk entry");
			goto out;
		}

		d = pv_disk_add(&s->disks);
		if (!d) {
			pv_log(ERROR, "cannot add new disk");
			goto out;
		}

		d->name = pv_json_get_value(str, "name", diskv, diskc);
		d->path = pv_json_get_value(str, "path", diskv, diskc);
		d->mount_target =
			pv_json_get_value(str, "mount_target", diskv, diskc);
		d->mount_ops =
			pv_json_get_value(str, "mount_options", diskv, diskc);
		d->format_ops =
			pv_json_get_value(str, "format_options", diskv, diskc);
		d->provision =
			pv_json_get_value(str, "provision", diskv, diskc);
		d->provision_ops = pv_json_get_value(str, "provision_options",
						     diskv, diskc);
		d->uuid = pv_json_get_value(str, "uuid", diskv, diskc);
		d->type = parse_disks_get_type(str, diskv, diskc);

		if (d->type == DISK_UNKNOWN) {
			pv_log(ERROR, "cannot add new disk, type = UNKNOWN");
			goto out;
		}

		d->format = parse_disks_get_format(str, diskv, diskc);
		if ((d->type == DISK_SWAP || d->type == DISK_VOLUME) &&
		    d->format == DISK_FORMAT_UNKNOWN) {
			pv_log(ERROR, "cannot add new disk, format = UNKNOWN");
			goto out;
		}

		d->def = parse_disks_get_default(str, diskv, diskc);
		d->mounted = false;

		// you need to jump (in tokens) to the next array, so
		// this is the number of keys + values
		t = t + (jsmnutil_object_key_count(str, diskv) * 2);

		if (diskv) {
			free(diskv);
			diskv = NULL;
		}

		if (str) {
			free(str);
			str = NULL;
		}
	}

	ret = 0;

out:
	if (str)
		free(str);
	if (diskv)
		free(diskv);
	if (tokv)
		free(tokv);

	return ret;
}

static int parse_bsp(struct pv_state *s, char *value, int n)
{
	int ret = 0, tokc, size;
	char *str, *buf;
	struct pv_volume *v;
	jsmntok_t *tokv;
	jsmntok_t **key, **key_i;
	char modules_uts[PATH_MAX];
	struct utsname uts;

	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		return 1;

	// take null terminate copy of item to parse
	buf = calloc(n + 1, sizeof(char));
	buf = memcpy(buf, value, n);

	jsmnutil_parse_json(buf, &tokv, &tokc);

	s->bsp.config = pv_json_get_value(buf, "initrd_config", tokv, tokc);
	s->bsp.img.ut.fit = pv_json_get_value(buf, "fit", tokv, tokc);
	if (!s->bsp.img.ut.fit) {
		s->bsp.img.rpiab.bootimg =
			pv_json_get_value(buf, "rpiab", tokv, tokc);

		if (!s->bsp.img.rpiab.bootimg) {
			s->bsp.img.std.kernel =
				pv_json_get_value(buf, "linux", tokv, tokc);
			s->bsp.img.std.fdt =
				pv_json_get_value(buf, "fdt", tokv, tokc);
			s->bsp.img.std.initrd =
				pv_json_get_value(buf, "initrd", tokv, tokc);
		}
	}
	s->bsp.firmware = pv_json_get_value(buf, "firmware", tokv, tokc);

	uname(&uts);
	sprintf(modules_uts, "modules_%s", uts.release);

	s->bsp.modules = pv_json_get_value(buf, modules_uts, tokv, tokc);
	if (!s->bsp.modules)
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

	if ((!s->bsp.img.std.kernel || !s->bsp.img.std.initrd) &&
	    !s->bsp.img.ut.fit && !s->bsp.img.rpiab.bootimg) {
		pv_log(ERROR,
		       "kernel or initrd not configured in bsp/run.json");
		ret = 0;
		goto out;
	}

	if ((pv_config_get_bootloader_type() == BL_RPIAB) &&
	    !s->bsp.img.rpiab.bootimg) {
		pv_log(ERROR, "bootimg not configured but required by config");
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
		if (strncmp("addons", buf + (*key_i)->start,
			    strlen("addons"))) {
			key_i++;
			continue;
		}

		// parse array data
		jsmntok_t *k = (*key_i + 2);
		size = (*key_i + 1)->size;
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

static int parse_storage(struct pv_state *s, struct pv_platform *p, char *buf)
{
	int tokc, n;
	char *key, *value, *pt, *disk;
	jsmntok_t *tokv;
	jsmntok_t *tokv_t;
	jsmntok_t **k, **keys;

	if (!buf)
		return 0;

	jsmnutil_parse_json(buf, &tokv, &tokc);

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
		key = malloc(n + 1);
		snprintf(key, n + 1, "%s", buf + (*k)->start);

		// copy value
		n = (*k + 1)->end - (*k + 1)->start;
		value = malloc(n + 1);
		snprintf(value, n + 1, "%s", buf + (*k + 1)->start);

		jsmnutil_parse_json(value, &tokv_t, &tokc);
		pt = pv_json_get_value(value, "persistence", tokv_t, tokc);
		disk = pv_json_get_value(value, "disk", tokv_t, tokc);

		if (pt) {
			struct pv_volume *v =
				pv_volume_add_with_disk(s, key, disk);
			v->plat = p;
			if (!strcmp(pt, "permanent"))
				v->type = VOL_PERMANENT;
			else if (!strcmp(pt, "revision"))
				v->type = VOL_REVISION;
			else if (!strcmp(pt, "boot"))
				v->type = VOL_BOOT;
			else {
				pv_log(WARN,
				       "invalid persistence value '%s' for platform '%s', default to BOOT",
				       pt, p ? p->name : "(NULL)");
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
		if (tokv_t) {
			free(tokv_t);
			tokv_t = NULL;
		}
		if (disk) {
			free(disk);
			disk = NULL;
		}
		k++;
	}
	jsmnutil_tokv_free(keys);

	if (tokv)
		free(tokv);

	return 1;
}

static int platform_drivers_add(struct pv_platform *p, plat_driver_t type,
				char *buf)
{
	int tokc, size, ret = 0;
	char *str;
	jsmntok_t *tokv, *t;

	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format driver");
		goto out;
	}

	size = jsmnutil_array_count(buf, tokv);
	if (size <= 0)
		goto out;

	t = tokv + 1;
	while ((str = pv_json_array_get_one_str(buf, &size, &t))) {
		pv_platform_add_driver(p, type, str);
		free(str);
	}

	ret = 1;

out:
	if (tokv)
		free(tokv);

	return ret;
}

static int parse_platform_drivers(struct pv_state *s, struct pv_platform *p,
				  char *buf)
{
	int tokc, ret;
	char *value;
	jsmntok_t *tokv;

	if (!buf)
		return 0;

	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	if (ret < 0) {
		pv_log(ERROR, "platform drivers list cannot be parsed");
		return 0;
	}

	value = pv_json_get_value(buf, "required", tokv, tokc);
	if (value) {
		platform_drivers_add(p, DRIVER_REQUIRED, value);
		free(value);
		value = 0;
	}

	value = pv_json_get_value(buf, "optional", tokv, tokc);
	if (value) {
		platform_drivers_add(p, DRIVER_OPTIONAL, value);
		free(value);
		value = 0;
	}

	value = pv_json_get_value(buf, "manual", tokv, tokc);
	if (value) {
		platform_drivers_add(p, DRIVER_MANUAL, value);
		free(value);
		value = 0;
	}

	if (value)
		free(value);

	if (tokv)
		free(tokv);

	return 1;
}

static int do_json_key_action_object(struct json_key_action *jka)
{
	int ret = 0;

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

	for (i = 0; i < arr_count && !ret; i++, arr_i++) {
		jsmntok_t *prev_tok = jka->tokv;
		if (jka->action) {
			jka->tokv = *arr_i; /*This is the usable token*/
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
	jsmntok_t *val_token = NULL;
	int ret = 0;
	int length = 0;
	char *buf = jka->buf;

	switch (jka->type) {
	case JSMN_STRING:
		val_token = jka->tokv + 1;
		value = pv_json_get_one_str(buf, &val_token);
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
		value = calloc(length + 1, sizeof(char));
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
static jsmntok_t *do_lookup_json_key(jsmntok_t **keys, char *json_buf,
				     char *key)
{
	bool found = false;
	jsmntok_t **keys_walker = NULL;

	if (!keys || !key)
		return NULL;
	keys_walker = keys;
	while (*keys_walker) {
		// copy key
		char *curr_key = NULL;
		int length = 0;

		length = (*keys_walker)->end - (*keys_walker)->start;

		curr_key = calloc(length + 1, sizeof(char));
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
	struct json_key_action *real_jka =
		(struct json_key_action *)jka->opaque;
	int ret = 0;
	jsmntok_t **keys;
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
	while (real_jka->key && !ret) {
		real_jka->tokv =
			do_lookup_json_key(keys, jka->buf, real_jka->key);
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
				     jsmntype_t type, jsmntok_t *__tokv,
				     int __tokc)
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
		jsmntok_t **keys;
		struct json_key_action *jka = jka_arr;

		if (!tokv) {
			ret = jsmnutil_parse_json(buf, &tokv, &tokc);
			if (ret <= 0)
				goto out;
		}
		if (type == JSMN_ARRAY) {
			struct json_key_action __jka_arr = {
				.key = NULL,
				.action = do_action_for_array,
				.type = JSMN_ARRAY,
				.opaque = (void *)jka_arr,
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
		while (!ret && jka->key) {
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
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;

	if (!value)
		goto fail;

	*bundle->platform = pv_platform_add(bundle->s, value);

	if (!(*bundle->platform))
		goto fail;
	return 0;
fail:
	return -1;
}

static int do_action_for_type(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;
	(*bundle->platform)->type = strdup(value);
	return 0;
}

static int do_action_for_automodfw(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;

	if (!strcmp("no", value))
		(*bundle->platform)->automodfw = false;
	else
		(*bundle->platform)->automodfw = true;

	return 0;
}

static int do_action_for_runlevel(struct json_key_action *jka, char *value)
{
	struct pv_group *g;
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;

	pv_log(WARN, "using deprecated runlevel for platform '%s' as group",
	       (*bundle->platform)->name);

	// runlevel is still valid in the state json to keep backwards compatibility, but internally it is substituted by groups
	if (!strcmp(value, "data") || !strcmp(value, "root") ||
	    !strcmp(value, "app") || !strcmp(value, "platform")) {
		pv_log(DEBUG, "linking platform '%s' with group '%s'",
		       (*bundle->platform)->name, value);

		g = pv_state_fetch_group(bundle->s, value);
		if (!g) {
			pv_log(ERROR, "could not find group '%s'", value);
			return -1;
		}
		pv_group_add_platform(g, (*bundle->platform));
	} else {
		pv_log(WARN, "invalid runlevel value '%s' for platform '%s'",
		       value, (*bundle->platform)->name);
	}

	return 0;
}

static int do_action_for_group(struct json_key_action *jka, char *value)
{
	struct pv_group *g;
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;

	if (!(*bundle->platform) || !value)
		return -1;

	pv_log(DEBUG, "linking platform %s with group %s",
	       (*bundle->platform)->name, value);

	g = pv_state_fetch_group(bundle->s, value);
	if (!g) {
		pv_log(ERROR, "could not find group '%s'", value);
		return -1;
	}
	pv_group_add_platform(g, (*bundle->platform));

	return 0;
}

static restart_policy_t parse_restart_policy(char *value, size_t len)
{
	if (pv_str_matches(value, len, "system", strlen("system")))
		return RESTART_SYSTEM;
	else if (pv_str_matches(value, len, "container", strlen("container")))
		return RESTART_CONTAINER;

	pv_log(ERROR, "invalid restart policy '%s'", value);
	return RESTART_NONE;
}

static int do_action_for_restart_policy(struct json_key_action *jka,
					char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;
	restart_policy_t restart;

	if (!(*bundle->platform) || !value)
		return -1;

	restart = parse_restart_policy(value, strlen(value));
	if (restart == RESTART_NONE)
		return -1;

	pv_platform_set_restart_policy(*bundle->platform, restart);

	return 0;
}

static plat_status_t parse_status_goal(char *value, size_t len)
{
	if (pv_str_matches(value, len, "MOUNTED", strlen("MOUNTED")))
		return PLAT_MOUNTED;
	else if (pv_str_matches(value, len, "STARTED", strlen("STARTED")))
		return PLAT_STARTED;
	else if (pv_str_matches(value, len, "READY", strlen("READY")))
		return PLAT_READY;

	pv_log(ERROR, "invalid status goal '%s'", value);
	return PLAT_NONE;
}

static int do_action_for_status_goal(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;
	plat_status_t status;

	if (!(*bundle->platform) || !value)
		return -1;

	status = parse_status_goal(value, strlen(value));
	if (status == PLAT_NONE)
		return -1;

	pv_platform_set_status_goal(*bundle->platform, status);

	return 0;
}

static int do_action_for_roles_object(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;

	if (*bundle->platform)
		pv_platform_unset_role(*bundle->platform, PLAT_ROLE_MGMT);

	return 0;
}

static int do_action_for_roles_array(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;
	bool value_alloced = false;
	int ret = -1;

	if (!value && (jka->type == JSMN_ARRAY)) {
		value = pv_json_get_one_str(jka->buf, &jka->tokv);
		value_alloced = true;
	}

	if (!(*bundle->platform) || !value)
		goto out;

	pv_log(DEBUG, "setting role %s to platform %s", value,
	       (*bundle->platform)->name);
	if (!strcmp(value, "mgmt"))
		pv_platform_set_role(*bundle->platform, PLAT_ROLE_MGMT);
	// we allow "nobody" as a role, does not need further action
	else if (strcmp(value, "nobody"))
		pv_log(WARN, "invalid role value '%s'", value);

	ret = 0;

out:
	if (value_alloced && value)
		free(value);
	return ret;
}

static int do_action_for_one_volume(struct json_key_action *jka, char *value)
{
	/*
	 * Opaque will contain the platform
	 * */
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;
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

static int do_action_for_one_log(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;
	struct pv_platform *platform = *bundle->platform;
	int ret = 0, i;
	struct pv_logger_config *config = NULL;
	const int key_count = jsmnutil_object_key_count(jka->buf, jka->tokv);
	jsmntok_t **keys = jsmnutil_get_object_keys(jka->buf, jka->tokv);
	jsmntok_t **keys_i = keys;

	if (!key_count || !keys) {
		pv_log(ERROR, "logs cannot be parsed");
		ret = -1;
		goto free_config;
	}

	config = (struct pv_logger_config *)calloc(1, sizeof(*config));
	if (!config) {
		ret = -1;
		goto free_config;
	}

	config->pair = calloc(key_count + 1, sizeof(char **));
	if (!config->pair) {
		ret = -1;
		goto free_config;
	}
	/*
	 * Allocate 2D configuration array..
	 * config->pair[i][0] = key
	 * config->pair[i][1] = value
	 * */
	for (i = 0; i < key_count + 1; i++) {
		config->pair[i] = (const char **)calloc(2, sizeof(char *));
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
		} else if (key) {
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
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;
	/*
	 * BUG_ON(value)
	 * */
	value = jka->buf;
	if (value)
		parse_storage(bundle->s, *bundle->platform, value);
	return 0;
}

static int do_action_for_drivers(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;
	/*
	 * BUG_ON(value)
	 * */
	value = jka->buf;
	if (value)
		parse_platform_drivers(bundle->s, *bundle->platform, value);
	return 0;
}

static int do_action_for_export(struct json_key_action *jka, char *value)
{
	struct platform_bundle *bundle = (struct platform_bundle *)jka->opaque;
	struct pv_platform *platform = *bundle->platform;
	platform->export = true;
	return 0;
}

static int parse_platform(struct pv_state *s, char *buf, int n)
{
	char *config = NULL, *shares = NULL;
	struct pv_platform *this = NULL;
	int ret = 0;
	struct platform_bundle bundle = {
		.s = s,
		.platform = &this,
	};

	struct json_key_action system1_platform_key_action[] = {
		ADD_JKA_ENTRY("name", JSMN_STRING, &bundle, do_action_for_name,
			      false),
		ADD_JKA_ENTRY("type", JSMN_STRING, &bundle, do_action_for_type,
			      false),
		ADD_JKA_ENTRY("runlevel", JSMN_STRING, &bundle,
			      do_action_for_runlevel, false),
		ADD_JKA_ENTRY("automodfw", JSMN_STRING, &bundle,
			      do_action_for_automodfw, false),
		ADD_JKA_ENTRY("group", JSMN_STRING, &bundle,
			      do_action_for_group, false),
		ADD_JKA_ENTRY("restart_policy", JSMN_STRING, &bundle,
			      do_action_for_restart_policy, false),
		ADD_JKA_ENTRY("status_goal", JSMN_STRING, &bundle,
			      do_action_for_status_goal, false),
		ADD_JKA_ENTRY("roles", JSMN_OBJECT, &bundle,
			      do_action_for_roles_object, false),
		ADD_JKA_ENTRY("roles", JSMN_ARRAY, &bundle,
			      do_action_for_roles_array, false),
		ADD_JKA_ENTRY("config", JSMN_STRING, &config, NULL, true),
		ADD_JKA_ENTRY("share", JSMN_STRING, &shares, NULL, true),
		ADD_JKA_ENTRY("root-volume", JSMN_STRING, &bundle,
			      do_action_for_one_volume, false),
		ADD_JKA_ENTRY("volumes", JSMN_ARRAY, &bundle,
			      do_action_for_one_volume, false),
		ADD_JKA_ENTRY("logs", JSMN_ARRAY, &bundle,
			      do_action_for_one_log, false),
		ADD_JKA_ENTRY("storage", JSMN_OBJECT, &bundle,
			      do_action_for_storage, false),
		ADD_JKA_ENTRY("drivers", JSMN_OBJECT, &bundle,
			      do_action_for_drivers, false),
		ADD_JKA_ENTRY("exports", JSMN_ARRAY, &bundle,
			      do_action_for_export, false),
		ADD_JKA_NULL_ENTRY()
	};

	ret = start_json_parsing_with_action(buf, system1_platform_key_action,
					     JSMN_OBJECT);
	if (!this || ret)
		goto out;

	// free intermediates
	if (config) {
		this->configs = calloc(2, sizeof(char *));
		this->configs[1] = NULL;
		this->configs[0] = strdup(config);
		free(config);
		config = 0;
	}

	pv_platform_set_installed(this);
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
	dl_list_for_each_safe(o, tmp_o, new_objects, struct pv_object, list)
	{
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
	dl_list_for_each_safe(j, tmp_j, new_jsons, struct pv_json, list)
	{
		name = strdup(j->name);
		dir = strtok(name, "/");
		if (!strcmp(dir, "_config"))
			dir = strtok(NULL, "/");
		j->plat = pv_state_fetch_platform(s, dir);
		free(name);
	}
}

static struct pv_state *system1_parse_disks(struct pv_state *this,
					    const char *buf)
{
	int tokc, count;
	jsmntok_t *tokv;
	char *value = NULL;

	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0) {
		pv_log(ERROR, "cannot parse");
		goto out;
	}

	count = pv_json_get_key_count(buf, "disks.json", tokv, tokc);
	if (count == 1) {
		if (pv_json_get_key_count(buf, "device.json", tokv, tokc)) {
			pv_log(WARN,
			       "disks.json found but device.json was already parsed. Ignorning disks.json...");
			goto out;
		}

		value = pv_json_get_value(buf, "disks.json", tokv, tokc);
		if (!value) {
			pv_log(WARN,
			       "Unable to get disks.json value from state");
			this = NULL;
			goto out;
		}

		pv_log(DEBUG, "adding json 'disks.json'");
		pv_jsons_add(this, "disks.json", value);

		if (parse_disks(this, value)) {
			this = NULL;
			goto out;
		}

		free(value);
		value = NULL;
	}

out:
	if (tokv)
		free(tokv);
	if (value)
		free(value);

	return this;
}

static int parse_groups(struct pv_state *s, char *value)
{
	int tokc, size, ret = 1;
	char *str = NULL;
	char *tmp = NULL;
	jsmntok_t *tokv, *t;

	if (jsmnutil_parse_json(value, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format groups");
		goto out;
	}

	size = jsmnutil_array_count(value, tokv);
	if (size <= 0) {
		pv_log(ERROR, "empty groups array");
		goto out;
	}

	t = tokv + 1;
	while ((str = pv_json_array_get_one_str(value, &size, &t))) {
		struct pv_group *g;
		plat_status_t status = PLAT_STARTED;
		restart_policy_t restart = RESTART_CONTAINER;
		jsmntok_t *groupv;
		int groupc, sizec, timeout;

		if (jsmnutil_parse_json(str, &groupv, &groupc) <= 0) {
			pv_log(ERROR, "invalid group entry");
			goto out;
		}

		sizec = jsmnutil_object_key_count(str, groupv);
		if (sizec <= 0) {
			pv_log(ERROR, "empty group entry");
			goto out;
		}

		tmp = pv_json_get_value(str, "status_goal", groupv, groupc);
		if (tmp) {
			status = parse_status_goal(tmp, strlen(tmp));
			if (status == PLAT_NONE)
				goto out;
			free(tmp);
			tmp = NULL;
		}

		tmp = pv_json_get_value(str, "timeout", groupv, groupc);
		if (tmp) {
			errno = 0;
			timeout = strtol(tmp, NULL, 10);
			if (errno != 0 || timeout < 0) {
				pv_log(ERROR,
				       "group timeout malformed or beyond to the limits");
				goto out;
			}
			free(tmp);
			tmp = NULL;
		} else {
			timeout = pv_config_get_int(PV_UPDATER_GOALS_TIMEOUT);
			pv_log(DEBUG,
			       "timeout not configured. Using default value %d",
			       timeout);
		}

		tmp = pv_json_get_value(str, "restart_policy", groupv, groupc);
		if (tmp) {
			restart = parse_restart_policy(tmp, strlen(tmp));
			if (restart == RESTART_NONE)
				goto out;
			free(tmp);
			tmp = NULL;
		}

		tmp = pv_json_get_value(str, "name", groupv, groupc);
		if (!tmp) {
			pv_log(ERROR, "group does not have a name", str);
			goto out;
		}
		g = pv_group_new(tmp, timeout, status, restart);
		pv_state_add_group(s, g);
		free(tmp);
		tmp = NULL;

		free(groupv);
		groupv = NULL;

		free(str);
		str = NULL;

		// skip number of keys in group object plus their values
		t += (sizec * 2);
	}

	ret = 0;

out:
	if (str)
		free(str);
	if (tokv)
		free(tokv);
	if (tmp)
		free(tmp);

	return ret;
}

static struct pv_state *system1_parse_groups(struct pv_state *this,
					     const char *buf)
{
	int tokc, count;
	jsmntok_t *tokv;
	char *value = NULL;

	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0) {
		pv_log(ERROR, "cannot parse");
		this = NULL;
		goto out;
	}

	count = pv_json_get_key_count(buf, "groups.json", tokv, tokc);
	if (count == 1) {
		if (pv_json_get_key_count(buf, "device.json", tokv, tokc)) {
			pv_log(WARN,
			       "groups.json found but device.json was already parsed. Ignorning groups.json...");
			goto out;
		}

		value = pv_json_get_value(buf, "groups.json", tokv, tokc);
		if (!value) {
			pv_log(ERROR,
			       "unable to get groups.json value from state");
			this = NULL;
			goto out;
		}

		pv_log(DEBUG, "adding json 'groups.json'");
		pv_jsons_add(this, "groups.json", value);

		if (parse_groups(this, value)) {
			this = NULL;
			goto out;
		}

		free(value);
		value = NULL;
	} else if (!count) {
		char path[PATH_MAX];

		if (pv_json_get_key_count(buf, "device.json", tokv, tokc))
			goto out;

		pv_paths_etc_file(path, PATH_MAX, PV_DEFAULTS_GROUPS);
		pv_log(INFO,
		       "groups.json not found in state. Loading default groups.json from '%s'...",
		       path);

		value = pv_fs_file_load(path, 0);
		if (!value) {
			pv_log(ERROR,
			       "default groups.json could not be loaded");
			this = NULL;
			goto out;
		}

		if (parse_groups(this, value)) {
			this = NULL;
			goto out;
		}

		this->using_runlevels = true;

		free(value);
		value = NULL;
	}

out:
	if (tokv)
		free(tokv);
	if (value)
		free(value);

	return this;
}

static struct pv_state *system1_parse_bsp(struct pv_state *this,
					  const char *buf)
{
	int tokc, count;
	jsmntok_t *tokv = NULL;
	char *value = NULL;

	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0) {
		pv_log(ERROR, "cannot parse");
		goto out;
	}

	count = pv_json_get_key_count(buf, "bsp/run.json", tokv, tokc);
	if (count != 1) {
		pv_log(WARN, "bsp/run.json missing or duplicated");
		this = NULL;
		goto out;
	}

	value = pv_json_get_value(buf, "bsp/run.json", tokv, tokc);
	if (!value) {
		pv_log(WARN, "unable to get bsp/run.json value from state");
		this = NULL;
		goto out;
	}

	pv_log(DEBUG, "adding json 'bsp/run.json'");
	pv_jsons_add(this, "bsp/run.json", value);

	if (!parse_bsp(this, value, strlen(value))) {
		this = NULL;
		goto out;
	}
	free(value);
	value = NULL;

	count = pv_json_get_key_count(buf, "bsp/drivers.json", tokv, tokc);
	if (count == 1) {
		value = pv_json_get_value(buf, "bsp/drivers.json", tokv, tokc);
		if (!value) {
			pv_log(WARN,
			       "Unable to get drivers.json value from state");
			this = NULL;
			goto out;
		}

		pv_log(DEBUG, "adding json 'bsp/drivers.json'");
		pv_jsons_add(this, "bsp/drivers.json", value);

		if (!parse_bsp_drivers(this, value, strlen(value))) {
			this = NULL;
			goto out;
		}

		free(value);
		value = NULL;
	}

out:
	if (tokv)
		free(tokv);
	if (value)
		free(value);

	return this;
}

static struct pv_state *parse_device(struct pv_state *this, char *buf)
{
	int tokc;
	jsmntok_t *tokv;
	char *value = NULL;

	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0) {
		pv_log(ERROR, "cannot parse");
		goto out;
	}

	value = pv_json_get_value(buf, "groups", tokv, tokc);
	if (!value) {
		pv_log(WARN, "groups not defined in device.json");
		goto out;
	}
	if (parse_groups(this, value)) {
		pv_log(ERROR, "cannot parse groups in device.json");
		this = NULL;
		goto out;
	}
	free(value);

	value = pv_json_get_value(buf, "disks", tokv, tokc);
	if (!value) {
		pv_log(WARN, "disks not defined in device.json");
		goto out;
	}
	if (parse_disks(this, value)) {
		pv_log(ERROR, "cannot parse disks in device.json");
		this = NULL;
		goto out;
	}
	free(value);
	value = pv_json_get_value(buf, "disks_v2", tokv, tokc);
	if (value && parse_disks(this, value)) {
		pv_log(ERROR, "cannot parse disks_v2 in device.json");
		this = NULL;
		goto out;
	}
	free(value);

	value = pv_json_get_value(buf, "volumes", tokv, tokc);
	if (!value) {
		pv_log(WARN, "volumes not defined in device.json");
		goto out;
	}
	if (!parse_storage(this, NULL, value)) {
		pv_log(ERROR, "cannot parse storage in device.json");
		this = NULL;
		goto out;
	}

out:
	if (tokv)
		free(tokv);
	if (value)
		free(value);

	return this;
}

static struct pv_state *system1_parse_device(struct pv_state *this,
					     const char *buf)
{
	int tokc, count;
	jsmntok_t *tokv;
	char *value = NULL;

	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0) {
		pv_log(ERROR, "cannot parse");
		goto out;
	}

	count = pv_json_get_key_count(buf, "device.json", tokv, tokc);
	if (count == 1) {
		value = pv_json_get_value(buf, "device.json", tokv, tokc);
		if (!value) {
			pv_log(WARN,
			       "Unable to get device.json value from state");
			this = NULL;
			goto out;
		}

		pv_log(DEBUG, "adding json 'device.json': %s", value);
		pv_jsons_add(this, "device.json", value);

		if (!parse_device(this, value)) {
			this = NULL;
			goto out;
		}

		free(value);
		value = NULL;
	}

out:
	if (tokv)
		free(tokv);
	if (value)
		free(value);

	return this;
}

static struct pv_state *system1_parse_objects(struct pv_state *this,
					      const char *buf)
{
	jsmntok_t *tokv;
	jsmntok_t **k, **keys;
	char *value = NULL, *key = NULL, *ext = NULL;
	int tokc, n;

	if (jsmnutil_parse_json(buf, &tokv, &tokc) < 0) {
		pv_log(ERROR, "cannot parse");
		goto out;
	}

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

		// avoid already parsed keys
		if (!strncmp("bsp/run.json", buf + (*k)->start, n) ||
		    !strncmp("bsp/drivers.json", buf + (*k)->start, n) ||
		    !strncmp("disks.json", buf + (*k)->start, n) ||
		    !strncmp("groups.json", buf + (*k)->start, n) ||
		    !strncmp("device.json", buf + (*k)->start, n) ||
		    !strncmp("#spec", buf + (*k)->start, n)) {
			k++;
			continue;
		}

		// copy key
		key = malloc(n + 1);
		snprintf(key, n + 1, "%s", buf + (*k)->start);

		// copy value
		n = (*k + 1)->end - (*k + 1)->start;
		value = malloc(n + 1);
		snprintf(value, n + 1, "%s", buf + (*k + 1)->start);

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
				   !strcmp(ext, "/build.json") ||
				   pv_str_startswith("_sigs/", strlen("_sigs/"),
						     key))) {
			pv_log(DEBUG, "skipping '%s'", key);
			// if the extension is other .json, we add it to the list of jsons
		} else if ((ext = strrchr(key, '.')) && !strcmp(ext, ".json") &&
			   !pv_is_sha256_hex_string(value)) {
			pv_log(DEBUG, "adding json '%s'", key);
			pv_jsons_add(this, key, value);
			// everything else is added to the list of objects
		} else {
			pv_log(DEBUG, "adding object '%s'", key);
			pv_objects_add(this, key, value,
				       pv_config_get_str(PV_STORAGE_MNTTYPE));
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

out:
	if (tokv)
		free(tokv);
	if (value)
		free(value);
	if (key)
		free(key);

	return this;
}

static struct pv_state *system1_parse_validate(struct pv_state *this,
					       const char *buf)
{
	system1_link_object_json_platforms(this);

	if (pv_state_validate(this))
		return NULL;

	pv_state_print(this);

	return this;
}

struct pv_state *system1_parse(struct pv_state *this, const char *buf)
{
	if (!system1_parse_device(this, buf)) {
		pv_log(ERROR, "cannot parse device.json");
		this = NULL;
		goto out;
	}

	if (!system1_parse_disks(this, buf)) {
		pv_log(ERROR, "cannot parse disks");
		this = NULL;
		goto out;
	}

	if (!system1_parse_groups(this, buf)) {
		pv_log(ERROR, "cannot parse groups");
		this = NULL;
		goto out;
	}

	if (!system1_parse_bsp(this, buf)) {
		pv_log(ERROR, "cannot parse bsp");
		this = NULL;
		goto out;
	}

	if (!system1_parse_objects(this, buf)) {
		pv_log(ERROR, "cannot parse objects");
		this = NULL;
		goto out;
	}

	if (!system1_parse_validate(this, buf)) {
		pv_log(ERROR, "cannot validate json");
		this = NULL;
		goto out;
	}

out:
	return this;
}
