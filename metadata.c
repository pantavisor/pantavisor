/*
 * Copyright (c) 2018-2022 Pantacor Ltd.
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

#include <libgen.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <trest.h>

#include <sys/stat.h>
#include <sys/utsname.h>

#include <linux/limits.h>

#include <jsmn/jsmnutil.h>

#include "metadata.h"
#include "version.h"
#include "state.h"
#include "pantahub.h"
#include "init.h"
#include "str.h"
#include "paths.h"
#include "updater.h"
#include "utils/math.h"
#include "utils/system.h"
#include "utils/str.h"
#include "json.h"
#include "config.h"
#include "config_parser.h"
#include "storage.h"
#include "platforms.h"
#include "buffer.h"
#include "utils/math.h"
#include "utils/system.h"
#include "utils/fs.h"

#define MODULE_NAME             "metadata"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static const unsigned int METADATA_MAX_SIZE = 4096;

#define PV_USERMETA_ADD     (1<<0)
struct pv_meta {
	char *key;
	char *value;
	bool updated;
	struct dl_list list; // pv_meta
};

struct pv_devmeta_read{
	char *key;
	char *buf;
	int buflen;
	int (*reader)(struct pv_devmeta_read*);
};

static int pv_devmeta_buf_check(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (!buf || buflen <= 0)
		return -1;
	return 0;
}

static int pv_devmeta_read_version(struct pv_devmeta_read
						*pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;
	SNPRINTF_WTRUNC(buf, buflen,"%s",(char *) pv_build_version);
	return 0;
}

static int pv_devmeta_read_arch(struct pv_devmeta_read
						*pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;
	SNPRINTF_WTRUNC(buf, buflen, "%s/%s/%s", PV_ARCH, PV_BITS, get_endian() ? "EL" : "EB");
	return 0;
}

static int pv_devmeta_read_dtmodel(struct pv_devmeta_read
						*pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	int ret = -1;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	ret = get_dt_model(buf, buflen);
	if (ret < 0)
		memset(buf, 0, buflen);
	return 0;
}

static int pv_devmeta_read_cpumodel(struct pv_devmeta_read
						*pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	int ret = -1;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	ret = get_cpu_model(buf, buflen);
	if (ret < 0)
		memset(buf, 0, buflen);
	return 0;
}

static int pv_devmeta_uname(struct pv_devmeta_read *pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	struct utsname data = {0};
	int err = uname(&data);

	if (err) {
		pv_log(WARN, "Couldn't add uname data: %s (%d)", strerror(errno), errno);
		memset(buf, 0, buflen);
		return -1;
	}

	struct pv_json_ser js;
	pv_json_ser_init(&js, 512);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "kernel.name");
		pv_json_ser_string(&js, data.sysname);
		pv_json_ser_key(&js, "kernel.release");
		pv_json_ser_string(&js, data.release);
		pv_json_ser_key(&js, "kernel.version");
		pv_json_ser_string(&js, data.version);
		pv_json_ser_key(&js, "node.name");
		pv_json_ser_string(&js, data.nodename);
		pv_json_ser_key(&js, "machine");
		pv_json_ser_string(&js, data.machine);
		pv_json_ser_object_pop(&js);
	}

	char *js_str = pv_json_ser_str(&js);
	strncpy(buf, js_str, buflen);
	free(js_str);

	return 0;
}

static int pv_devmeta_read_revision(struct pv_devmeta_read
						*pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	struct pantavisor *pv = pv_get_instance();

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	SNPRINTF_WTRUNC(buf, buflen, "%s", pv->state->rev);
	return 0;
}

static int pv_devmeta_read_mode(struct pv_devmeta_read
						*pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	struct pantavisor *pv = pv_get_instance();

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	if (pv->remote_mode)
		SNPRINTF_WTRUNC(buf, buflen, "remote");
	else
		SNPRINTF_WTRUNC(buf, buflen, "local");
	return 0;
}

static int pv_devmeta_read_online(struct pv_devmeta_read
						*pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	struct pantavisor *pv = pv_get_instance();

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	if (pv->online)
		SNPRINTF_WTRUNC(buf, buflen, "1");
	else
		SNPRINTF_WTRUNC(buf, buflen, "0");
	return 0;
}

static int pv_devmeta_read_claimed(struct pv_devmeta_read
						*pv_devmeta_read)
{
	char *buf = pv_devmeta_read->buf;
	int buflen = pv_devmeta_read->buflen;
	struct pantavisor *pv = pv_get_instance();

	if (pv_devmeta_buf_check(pv_devmeta_read))
		return -1;

	if (pv->unclaimed)
		SNPRINTF_WTRUNC(buf, buflen, "0");
	else
		SNPRINTF_WTRUNC(buf, buflen, "1");
	return 0;
}

static struct pv_devmeta_read pv_devmeta_readkeys[] = {
	{
		.key = DEVMETA_KEY_PV_ARCH,
		.reader = pv_devmeta_read_arch
	},
	{	.key = DEVMETA_KEY_PV_VERSION,
		.reader = pv_devmeta_read_version
	},
	{	.key = DEVMETA_KEY_PV_DTMODEL,
		.reader = pv_devmeta_read_dtmodel
	},
	{	.key = DEVMETA_KEY_PV_CPUMODEL,
		.reader = pv_devmeta_read_cpumodel
	},
	{	.key = DEVMETA_KEY_PV_REVISION,
		.reader = pv_devmeta_read_revision
	},
	{	.key = DEVMETA_KEY_PV_MODE,
		.reader = pv_devmeta_read_mode
	},
	{	.key = DEVMETA_KEY_PH_ONLINE,
		.reader = pv_devmeta_read_online
	},
	{	.key = DEVMETA_KEY_PH_CLAIMED,
		.reader = pv_devmeta_read_claimed
	},
	{ .key = DEVMETA_KEY_PV_UNAME,
		.reader = pv_devmeta_uname
	}
};

static void pv_metadata_free(struct pv_meta *usermeta)
{
	if (usermeta->key)
		free(usermeta->key);
	if (usermeta->value)
		free(usermeta->value);

	free(usermeta);
}

static void pv_usermeta_remove(struct pv_metadata *metadata)
{
	struct pv_meta *curr, *tmp;
	struct dl_list *head = &metadata->usermeta;

	if (dl_list_empty(&metadata->usermeta))
		return;

	pv_log(DEBUG, "removing user meta list");

	dl_list_for_each_safe(curr, tmp, head,
		struct pv_meta, list) {
		dl_list_del(&curr->list);
		pv_metadata_free(curr);
	}
}

static void pv_devmeta_remove(struct pv_metadata *metadata)
{
	struct pv_meta *curr, *tmp;
	struct dl_list *head = &metadata->devmeta;

	if (dl_list_empty(&metadata->devmeta))
		return;

	pv_log(DEBUG, "removing devmeta list");

	dl_list_for_each_safe(curr, tmp, head,
		struct pv_meta, list) {
		dl_list_del(&curr->list);
		pv_metadata_free(curr);
	}
}

static struct pv_meta* pv_metadata_get_by_key(struct dl_list *head, const char *key)
{
	struct pv_meta *curr, *tmp;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_meta, list) {
		if (!strcmp(key, curr->key))
			return curr;
	}

	return NULL;
}

static int pv_metadata_add(struct dl_list *head, const char *key, const char *value)
{
	int ret = -1;
	struct pv_meta *curr;

	if (!head || !key || !value)
		goto out;

	// find and update value
	curr = pv_metadata_get_by_key(head, key);
	if (curr) {
		if (strcmp(curr->value, value) == 0) {
			ret = 0;
		} else {
			free(curr->value);
			curr->value = strdup(value);
			ret = 1;
		}
		goto out;
	}

	// add new key and value pair
	curr = calloc(1, sizeof(struct pv_meta));
	if (curr) {
		dl_list_init(&curr->list);
		curr->key = strdup(key);
		curr->value = strdup(value);
		if (curr->key && curr->value) {
			dl_list_add(head, &curr->list);
			ret = 1;
		} else {
			if (curr->key)
				free(curr->key);
			if (curr->value)
				free(curr->value);
			free(curr);
		}
	}

out:
	return ret;
}

int pv_metadata_add_usermeta(const char *key, const char *value)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_meta *curr;
	int ret = pv_metadata_add(&pv->metadata->usermeta, key, value);

	// set updated flags for all current existing pairs so they are not deleted
	if (ret >= 0) {
		curr = pv_metadata_get_by_key(&pv->metadata->usermeta, key);
		if (curr)
			curr->updated = true;
	}

	if (ret > 0) {
		pv_log(DEBUG, "user metadata key %s added or updated", key);
		pv_config_override_value(key, value);
		pv_storage_save_usermeta(key, value);
		return 0;
	}

	return -1;
}

int pv_metadata_rm_usermeta(const char *key)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_meta *meta;

	meta = pv_metadata_get_by_key(&pv->metadata->usermeta, key);

	if (meta) {
		dl_list_del(&meta->list);
		pv_storage_rm_usermeta(meta->key);
		pv_metadata_free(meta);
		return 0;
	}

	return -1;
}

static int pv_usermeta_parse(struct pantavisor *pv, char *buf)
{
	int ret = 0, tokc, n;
	jsmntok_t *tokv;
	jsmntok_t **keys, **key_i;
	char *um, *key, *value;

	// parse user metadata json
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	um = pv_json_get_value(buf, "user-meta", tokv, tokc);

	if (!um) {
		ret = -1;
		goto out;
	}

	if (tokv)
		free(tokv);

	ret = jsmnutil_parse_json(um, &tokv, &tokc);
	keys = jsmnutil_get_object_keys(um, tokv);

	key_i = keys;
	while (*key_i) {
		n = (*key_i)->end - (*key_i)->start;

		// copy key
		key = calloc(n + 1, sizeof(char));
		if (!key)
			break;

		strncpy(key, um+(*key_i)->start, n);

		// copy value
		n = (*key_i+1)->end - (*key_i+1)->start;
		value = calloc(n + 1, sizeof(char));
		if (!value)
			break;

		strncpy(value, um+(*key_i+1)->start, n);
		pv_str_unescape_to_ascii(value, n);

		// add or update metadata
		// primitives with value 'null' have value NULL
		if ((*key_i+1)->type != JSMN_PRIMITIVE || strcmp("null", value))
			pv_metadata_add_usermeta(key, value);

		// free intermediates
		if (key) {
			free(key);
			key = 0;
		}
		if (value) {
			free(value);
			value = 0;
		}

		key_i++;
	}

	jsmnutil_tokv_free(keys);

out:
	if (um)
		free(um);
	if (tokv)
		free(tokv);

	return ret;
}

static void usermeta_clear(struct pantavisor *pv)
{
	struct pv_meta *curr, *tmp;
	struct dl_list *head = NULL;

	if (!pv)
		return;
	if (!pv->metadata)
		return;

	head = &pv->metadata->usermeta;
	dl_list_for_each_safe(curr, tmp, head,
			struct pv_meta, list) {
		// clear the flag updated for next iteration
		if (curr->updated)
			curr->updated = false;
		// not updated means user meta is no longer in cloud
		else
			pv_metadata_rm_usermeta(curr->key);
	}
}

int pv_metadata_add_devmeta(const char *key, const char *value)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_meta *curr;
	int ret = pv_metadata_add(&pv->metadata->devmeta, key, value);

	if (ret > 0) {
		// set updated flag only for added or updated so they can be uploaded
		curr = pv_metadata_get_by_key(&pv->metadata->devmeta, key);
		if (curr)
			curr->updated = true;

		pv_log(DEBUG, "device metadata key %s added or updated", key);
		pv->metadata->devmeta_uploaded = false;
		pv_storage_save_devmeta(key, value);

		return 0;
	}

	return -1;
}

int pv_metadata_rm_devmeta(const char *key)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_meta *curr;

	curr = pv_metadata_get_by_key(&pv->metadata->devmeta, key);

	if (curr) {
		dl_list_del(&curr->list);
		pv_storage_rm_devmeta(curr->key);
		pv_metadata_free(curr);
		return 0;
	}

	return -1;
}

void pv_metadata_parse_devmeta(const char *buf)
{
	int ret = 0, tokc, n;
	jsmntok_t *tokv = NULL;
	jsmntok_t **key = NULL;
	char *metakey = NULL, *metavalue = NULL;

	// parse device metadata json
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	key = jsmnutil_get_object_keys(buf, tokv);

	if (!key)
		goto out;

	// parse key
	n = (*key)->end - (*key)->start;
	metakey = malloc(n+1);
	if (!metakey)
		goto out;

	SNPRINTF_WTRUNC(metakey, n+1, "%s", buf+(*key)->start);

	// parse value
	n = (*key+1)->end - (*key+1)->start;
	metavalue = malloc(n+1);
	if (!metavalue)
		goto out;

	SNPRINTF_WTRUNC(metavalue, n+1, "%s", buf+(*key+1)->start);

	pv_metadata_add_devmeta(metakey, metavalue);

out:
	if (metakey)
		free(metakey);
	if (metavalue)
		free(metavalue);

	jsmnutil_tokv_free(key);

	if (tokv)
		free(tokv);
}

int pv_metadata_init_devmeta(struct pantavisor *pv)
{
	char *buf = NULL;
	struct buffer *buffer = NULL;
	int i = 0, bufsize = 0;
	/*
	 * we can use one of the large buffer. Since
	 * this information won't be very large, it's safe
	 * to assume even the complete json would
	 * be small enough to fit inside this buffer.
	 */
	buffer = pv_buffer_get(true);
	if (!buffer) {
		pv_log(INFO, "couldn't allocate buffer to upload device info");
		return -1;
	}

	buf = buffer->buf;
	bufsize = buffer->size;

	// add system info to initial device metadata
	for (i = 0; i < ARRAY_LEN(pv_devmeta_readkeys); i++) {
		int ret = 0;

		pv_devmeta_readkeys[i].buf = buf;
		pv_devmeta_readkeys[i].buflen = bufsize;
		ret = pv_devmeta_readkeys[i].reader(&pv_devmeta_readkeys[i]);
		if (!ret)
			pv_metadata_add_devmeta(pv_devmeta_readkeys[i].key, buf);
	}
	pv_buffer_drop(buffer);
	pv->metadata->devmeta_uploaded = false;
	timer_start(&pv->metadata->devmeta_tm,
		pv_config_get_metadata_devmeta_interval(),
		0,
		RELATIV_TIMER);

	return 0;
}

int pv_metadata_upload_devmeta(struct pantavisor *pv)
{
	unsigned int len = 0;
	char *json = NULL;
	struct pv_meta *info = NULL, *tmp = NULL;
	struct dl_list *head = NULL;
	int json_avail = 0, ret = 0;
	struct buffer *buffer = NULL;

	struct timer_state st = timer_current_state(&pv->metadata->devmeta_tm);
	if (!st.fin)
		return 0;

	timer_start(&pv->metadata->devmeta_tm,
		pv_config_get_metadata_devmeta_interval(),
		0,
		RELATIV_TIMER);

	/*
	 * we can use one of the large buffer. Since
	 * this information won't be very large, it's safe
	 * to assume even the complete json would
	 * be small enough to fit inside this buffer.
	 */
	buffer = pv_buffer_get(true);
	if (!buffer) {
		pv_log(INFO, "couldn't allocate buffer to upload device info");
		return -1;
	}

	if (pv->metadata->devmeta_uploaded)
		goto out;

	json = buffer->buf;
	json_avail = buffer->size;
	json_avail -= sprintf(json, "{");
	len += 1;
	head = &pv->metadata->devmeta;
	dl_list_for_each_safe(info, tmp, head,
			struct pv_meta, list) {
		if (!info->updated)
			continue;

		char *key = pv_json_format(info->key, strlen(info->key));
		char *val = pv_json_format(info->value, strlen(info->value));

		if (key && val) {
			// if value is a regular string
			if (info->value[0] != '{') {
				int frag_len = strlen(key) + strlen(val) +
					// 2 pairs of quotes
					2 * 2 +
					// 1 colon and a ,
					1 + 1;
				if (json_avail > frag_len) {
					SNPRINTF_WTRUNC(json + len, json_avail,
							"\"%s\":\"%s\",",
							key, val);
					len += frag_len;
					json_avail -= frag_len;
				}
			// if value is a json
			} else {
				int frag_len = strlen(info->key) + strlen(info->value) +
					// 1 pair of quotes
					1 * 2 +
					// 1 colon and a ,
					1 + 1;
				if (json_avail > frag_len) {
					SNPRINTF_WTRUNC(json + len, json_avail,
							"\"%s\":%s,",
							info->key, info->value);
					len += frag_len;
					json_avail -= frag_len;
				}
			}
		}
		if (key)
			free(key);
		if (val)
			free(val);
	}
	/*
	 * replace , with closing brace.
	 */
	json[len - 1] = '}';
	pv_log(INFO, "uploading devmeta json '%s'", json);
	ret = pv_ph_upload_metadata(pv, json);
	if(!ret) {
		pv->metadata->devmeta_uploaded = true;

		dl_list_for_each_safe(info, tmp, head,
			struct pv_meta, list) {
			info->updated = false;
		}
	}
out:
	pv_buffer_drop(buffer);
	return 0;
}

/*
 * For iteration over config items.
 */
struct json_buf {
	char *buf;
	const char *factory_file;
	int len;
	int avail;
};
/*
 * opaque is the json buffer.
 */
static int on_factory_meta_iterate(char *key, char *value, void *opaque)
{
	struct json_buf *json_buf = (struct json_buf*) opaque;
	char abs_key[PATH_MAX + (PATH_MAX / 2)];
	char *formatted_key = NULL;
	char *formatted_val = NULL;
	int json_avail = json_buf->avail;
	int len = json_buf->len;
	bool written = false;
	char file[PATH_MAX];
	char *fname = NULL;

	strcpy(file, json_buf->factory_file);
	fname = basename(file);
	SNPRINTF_WTRUNC(abs_key, sizeof(abs_key), "factory/%s/%s", fname, key);
	formatted_key = pv_json_format(abs_key, strlen(abs_key));
	formatted_val = pv_json_format(value, strlen(value));

	if (formatted_key && formatted_val) {
		int frag_len = strlen(formatted_key) + strlen(formatted_val) +
			/* 2 pairs of quotes*/
			2 * 2 +
			/* 1 colon and a ,*/
			1 + 1;
		if (json_avail > frag_len) {
			SNPRINTF_WTRUNC(json_buf->buf + len, json_avail,
					"\"%s\":\"%s\",",
					formatted_key, formatted_val);
			len += frag_len;
			json_avail -= frag_len;
			json_buf->len = len;
			json_buf->avail = json_avail;
			written = true;
		}
	}
	if (formatted_key)
		free(formatted_key);
	if (formatted_val)
		free(formatted_val);
	return written ? 0 : -1;
}

static int __pv_metadata_factory_meta(struct pantavisor *pv, const char *factory_file)
{
	int ret = -1;
	DEFINE_DL_LIST(factory_kv_list);
	struct buffer *buffer = NULL;
	char *json_holder = NULL;
	int json_len = 0;
	int json_avail = 0;
	struct json_buf json_buf;

	if (!factory_file)
		goto out;
	ret = load_key_value_file(factory_file, &factory_kv_list);
	if (ret < 0)
		goto out;
	buffer = pv_buffer_get(true);
	if (!buffer)
		goto out;

	json_holder = buffer->buf;
	json_avail = buffer->size;
	json_avail -= sprintf(json_holder, "{");
	json_len += 1;

	json_buf.buf = json_holder;
	json_buf.len = json_len;
	json_buf.avail = json_avail;
	json_buf.factory_file = factory_file;
	config_iterate_items(&factory_kv_list,
			on_factory_meta_iterate, &json_buf);
	json_len = json_buf.len;
	/*
	 * replace last ,.
	 */
	json_holder[json_len - 1] = '}';

	ret = pv_ph_upload_metadata(pv, json_holder);
	pv_buffer_drop(buffer);
	pv_log(INFO, "metadata_json : %s", json_holder);
	config_clear_items(&factory_kv_list);
out:
	return ret;
}

int pv_metadata_factory_meta(struct pantavisor *pv)
{
	struct dirent **dirlist = NULL;
	int n = 0;
	char path[PATH_MAX];
	bool upload_failed = false;

	pv_paths_storage_factory_meta_key(path, PATH_MAX, "");
	n = scandir(path, &dirlist, NULL, alphasort);
	if (n < 0)
		pv_log(WARN, "%s: %s", path, strerror(errno));
	while (n > 0) {
		struct stat st;
		n--;
		if (!upload_failed) {
			pv_paths_storage_factory_meta_key(path, PATH_MAX, dirlist[n]->d_name);
			if (!stat(path, &st)) {
				if ((st.st_mode & S_IFMT) == S_IFREG) {
					int ret = -1;

					ret = __pv_metadata_factory_meta(pv, path);
					if (ret)
						upload_failed = true;
				}
			}
		}
		free(dirlist[n]);
	}
	if (dirlist)
		free(dirlist);
	if (!upload_failed) {
		int fd;
		pv_paths_storage_trail_pv_file(path, PATH_MAX, "0", METADONE_FNAME);
		fd = open(path, O_CREAT | O_SYNC);
		if (fd < 0)
			pv_log(ERROR, "Unable to open file %s", path);
		close(fd);
	}
	return upload_failed ? -1 : 0;
}

void pv_metadata_parse_usermeta(char *buf)
{
	struct pantavisor *pv = pv_get_instance();
	char *body = strdup(buf);

	pv_usermeta_parse(pv, body);

	if (body)
		free(body);

	usermeta_clear(pv);
}

char *pv_metadata_get_usermeta(char *key)
{
	struct pantavisor *pv = pv_get_instance();
	struct dl_list *head = &pv->metadata->usermeta;
	struct pv_meta *curr, *tmp;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_meta, list) {
		if (!strcmp(curr->key, key))
			return curr->value;
	}
	return NULL;
}

static void pv_metadata_load_usermeta()
{
	struct dl_list files; // pv_path
	struct pv_path *curr, *tmp;
	char path[PATH_MAX];
	char *value;

	dl_list_init(&files);
	pv_paths_pv_usrmeta_key(path, PATH_MAX, "");
	pv_storage_get_subdir(path, "", &files);

	if (dl_list_empty(&files))
		return;

	pv_log(DEBUG, "loading user meta from %s", path);

	dl_list_for_each_safe(curr, tmp, &files,
		struct pv_path, list) {

		if (!strncmp(curr->path, "..", strlen("..")) ||
			!strncmp(curr->path, ".", strlen(".")))
			continue;

		pv_paths_pv_usrmeta_key(path, PATH_MAX, curr->path);
		value = pv_fs_file_load(path, METADATA_MAX_SIZE);
		if (!value) {
			pv_log(ERROR, "could not load %s: %s", path, strerror(errno));
			continue;
		}

		pv_metadata_add_usermeta(curr->path, value);
		free(value);
	}

	pv_storage_free_subdir(&files);
}

static void pv_metadata_load_devmeta()
{
	struct dl_list files; // pv_path
	struct pv_path *curr, *tmp;
	char path[PATH_MAX];
	char *value;

	dl_list_init(&files);
	pv_paths_pv_devmeta_key(path, PATH_MAX, "");
	pv_storage_get_subdir(path, "", &files);

	if (dl_list_empty(&files))
		return;

	pv_log(DEBUG, "loading device meta from %s", path);

	dl_list_for_each_safe(curr, tmp, &files,
		struct pv_path, list) {

		if (!strncmp(curr->path, "..", strlen("..")) ||
			!strncmp(curr->path, ".", strlen(".")))
			continue;

		pv_paths_pv_devmeta_key(path, PATH_MAX, curr->path);
		value = pv_fs_file_load(path, METADATA_MAX_SIZE);
		if (!value) {
			pv_log(ERROR, "could not load %s: %s", path, strerror(errno));
			continue;
		}

		pv_metadata_add_devmeta(curr->path, value);
		free(value);
	}

	pv_storage_free_subdir(&files);
}

static int pv_metadata_init(struct pv_init *this)
{
	struct pantavisor *pv = pv_get_instance();

	pv->metadata = calloc(1, sizeof(struct pv_metadata));
	if (!pv->metadata)
		return -1;

	dl_list_init(&pv->metadata->usermeta);
	dl_list_init(&pv->metadata->devmeta);

	pv->metadata->devmeta_uploaded = true;

	pv_metadata_load_usermeta();
	pv_metadata_load_devmeta();

	return 0;
}

bool pv_metadata_factory_meta_done(struct pantavisor *pv)
{
	char path[PATH_MAX];
	struct stat st;

	/*
	 * Don't check for meta done for non-factory
	 * boot revision. It's possible that trails/0
	 * may not exist and the device would then be
	 * stuck getting any updates.
	 */
	if (strncmp(pv->state->rev, "0", strlen(pv->state->rev) + 1))
		return true;

	pv_paths_storage_trail_pv_file(path, PATH_MAX, "0", METADONE_FNAME);
	if (stat(path, &st))
		return false;
	return true;
}

static char* pv_metadata_get_meta_string(struct dl_list *meta_list)
{
	struct pv_meta *curr, *tmp;
	int len = 1, line_len;
	char *json = calloc(len, sizeof(char));

	// open json
	json[0]='{';

	if (dl_list_empty(meta_list)) {
		len++;
		goto out;
	}

	// add value,key pair to json
	dl_list_for_each_safe(curr, tmp, meta_list,
		struct pv_meta, list) {
		if (!curr->value)
			continue;

		if (curr->value[0] != '{') {
			// value is a plain string
			char *escaped = pv_json_format(curr->value, strlen(curr->value));
			if (!escaped)
				continue;
			line_len = strlen(curr->key) + strlen(escaped) + 6;
			json = realloc(json, len + line_len + 1);
			SNPRINTF_WTRUNC(&json[len], line_len + 1, "\"%s\":\"%s\",",
					curr->key, escaped);
			free(escaped);
		} else {
			// value is a json
			line_len = strlen(curr->key) + strlen(curr->value) + 4;
			json = realloc(json, len + line_len + 1);
			SNPRINTF_WTRUNC(&json[len], line_len + 1, "\"%s\":%s,",
					curr->key, curr->value);
		}
		len += line_len;
	}

out:
	len += 1;
	json = realloc(json, len);
	// close json
	json[len-2] = '}';
	json[len-1] = '\0';

	return json;
}

char* pv_metadata_get_user_meta_string()
{
	return pv_metadata_get_meta_string(&pv_get_instance()->metadata->usermeta);
}

char* pv_metadata_get_device_meta_string()
{
	return pv_metadata_get_meta_string(&pv_get_instance()->metadata->devmeta);
}

void pv_metadata_remove()
{
	struct pantavisor *pv = pv_get_instance();

	if(!pv->metadata)
		return;

	pv_log(DEBUG, "removing metadata");

	pv_usermeta_remove(pv->metadata);
	pv_devmeta_remove(pv->metadata);

	free(pv->metadata);
	pv->metadata = NULL;
}

struct pv_init pv_init_metadata = {
	.init_fn = pv_metadata_init,
	.flags = 0,
};
