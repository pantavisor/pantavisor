/*
 * Copyright (c) 2018 Pantacor Ltd.
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
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <libgen.h>

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#define MODULE_NAME             "device"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "loop.h"

#include "utils.h"
#include "pantavisor.h"
#include "pantahub.h"
#include "device.h"
#include "version.h"

#define FW_PATH		"/lib/firmware"

static bool info_uploaded = 0;
static bool info_parsed = 0;

static int pv_device_info_buf_check(struct pv_device_info_read *pv_device_info_read)
{
	char *buf = pv_device_info_read->buf;
	int buflen = pv_device_info_read->buflen;

	if (!buf || buflen <= 0)
		return -1;
	return 0;
}

static int pv_device_info_read_version(struct pv_device_info_read
						*pv_device_info_read)
{
	char *buf = pv_device_info_read->buf;
	int buflen = pv_device_info_read->buflen;

	if (pv_device_info_buf_check(pv_device_info_read))
		return -1;
	snprintf(buf, buflen,"%s",(char *) pv_build_version);
	return 0;
}

static int pv_device_info_read_arch(struct pv_device_info_read 
						*pv_device_info_read)
{
	char *buf = pv_device_info_read->buf;
	int buflen = pv_device_info_read->buflen;

	if (pv_device_info_buf_check(pv_device_info_read))
		return -1;
	snprintf(buf, buflen, "%s/%s/%s", PV_ARCH, PV_BITS, get_endian() ? "EL" : "EB");
	return 0;
}

static int pv_device_info_read_dtmodel(struct pv_device_info_read 
						*pv_device_info_read) 
{
	char *buf = pv_device_info_read->buf;
	int buflen = pv_device_info_read->buflen;
	int ret = -1;

	if (pv_device_info_buf_check(pv_device_info_read))
		return -1;

	ret = get_dt_model(buf, buflen);
	if (ret < 0)
		memset(buf, 0, buflen);
	return 0;
}

static int pv_device_info_read_cpumodel(struct pv_device_info_read
						*pv_device_info_read)
{
	char *buf = pv_device_info_read->buf;
	int buflen = pv_device_info_read->buflen;
	int ret = -1;

	if (pv_device_info_buf_check(pv_device_info_read))
		return -1;

	ret = get_cpu_model(buf, buflen);
	if (ret < 0)
		memset(buf, 0, buflen);
	return 0;
}

static int pv_device_info_read_revision(struct pv_device_info_read
						*pv_device_info_read)
{
	char *buf = pv_device_info_read->buf;
	int buflen = pv_device_info_read->buflen;
	struct pantavisor *pv = get_pv_instance();

	if (pv_device_info_buf_check(pv_device_info_read))
		return -1;

	snprintf(buf, buflen, "%d", pv->state->rev);
	return 0;
}

static struct pv_device_info_read pv_device_info_readkeys[] = {
	{
		.key = "pantavisor.arch",
		.reader = pv_device_info_read_arch
	},
	{	.key = "pantavisor.version",
		.reader = pv_device_info_read_version
	},
	{	.key = "pantavisor.dtmodel",
		.reader = pv_device_info_read_dtmodel
	},
	{	.key = "pantavisor.cpumodel",
		.reader = pv_device_info_read_cpumodel
	},
	{	.key = "pantavisor.revision",
		.reader = pv_device_info_read_revision
	}
};

static void usermeta_add_hint(struct pv_usermeta *m)
{
	int fd;
	char *path_base;
	char path[PATH_MAX];

	if (!m)
		return;

	sprintf(path, "/pv/user-meta/%s", m->key);
	path_base = strdup(path);

	dirname(path_base);
	if (strcmp("/pv/user-meta", path_base))
		mkdir_p(path_base, 0755);

	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
	if (!fd)
		goto out;

	write(fd, m->value, strlen(m->value));
	close(fd);

out:
	free(path_base);

	return;
}

static void usermeta_remove_hint(struct pv_usermeta *m)
{
	char path[PATH_MAX];

	if (!m)
		return;

	sprintf(path, "/pv/user-meta/%s", m->key);
	remove(path);
}


static void usermeta_free_one(struct pv_usermeta *usermeta)
{
	usermeta_remove_hint(usermeta);

	if (usermeta->key)
		free(usermeta->key);

	if (usermeta->value)
		free(usermeta->value);
	free(usermeta);
}

static void usermeta_remove(struct pv_device *d, char *key)
{
	struct pv_usermeta *curr, *tmp;
	struct dl_list *head = &d->metalist;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_usermeta, list) {
		usermeta_remove_hint(curr);
		usermeta_free_one(curr);
	}
}

struct pv_usermeta* pv_usermeta_get_by_key(struct pv_device *d, char *key)
{
	struct pv_usermeta *curr, *tmp;
	struct dl_list *head = &d->metalist;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_usermeta, list) {
		if (!strcmp(key, curr->key))
			return curr;
	}

	return NULL;
}

struct pv_usermeta* pv_usermeta_add(struct pv_device *d, char *key, char *value)
{
	int changed = 1;
	struct pv_usermeta *curr;

	if (!d || !key)
		return NULL;

	curr = pv_usermeta_get_by_key(d, key);
	if (curr) {
		if (strcmp(curr->value, value) == 0)
			changed = 0;
		if (changed) {
			free(curr->value);
			curr->value = strdup(value);
		}
		goto out;
	}

	// not found? add
	curr = calloc(1, sizeof(struct pv_usermeta));
	if (curr) {
		dl_list_init(&curr->list);
		curr->key = strdup(key);
		curr->value = strdup(value);
		dl_list_add(&d->metalist, &curr->list);
	}
out:
	if (curr)
		curr->flags |= PV_USERMETA_ADD;

	if (changed && curr)
		usermeta_add_hint(curr);
	return curr;
}

int pv_usermeta_parse(struct pantavisor *pv, char *buf)
{
	int ret = 0, tokc, n;
	jsmntok_t *tokv;
	jsmntok_t **keys, **key_i;
	char *um, *key, *value;

	// Parse full device json
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	um = get_json_key_value(buf, "user-meta", tokv, tokc);

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
		key = malloc(n+1);
		if (!key)
			break;

		snprintf(key, n+1, "%s", um+(*key_i)->start);

		// copy value
		n = (*key_i+1)->end - (*key_i+1)->start;
		value = malloc(n+1);
		if (!value)
			break;

		snprintf(value, n+1, "%s", um+(*key_i+1)->start);

		// add or update metadata
		pv_usermeta_add(pv->dev, key, value);

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
	if (tokv)
		free(tokv);

	return ret;
}

static void usermeta_clear(struct pantavisor *pv)
{
	struct pv_usermeta *curr, *tmp;
	struct dl_list *head = NULL;

	if (!pv)
		return;
	if (!pv->dev)
		return;

	head = &pv->dev->metalist;
	dl_list_for_each_safe(curr, tmp, head,
			struct pv_usermeta, list) {
		/*
		 * If ADD flag is set then clear it
		 * for the next check cycle.
		 */
		if (curr->flags & PV_USERMETA_ADD)
			curr->flags &= ~PV_USERMETA_ADD;
		else {
			dl_list_del(&curr->list);
			usermeta_free_one(curr);
		}
	}
}

struct pv_devinfo* pv_device_info_add(struct pv_device *dev, char *key, char *value)
{
	struct pv_devinfo *this = NULL;

	if (!key || !value)
		goto out;

	this = calloc(1, sizeof(struct pv_devinfo));
	if (!this)
		goto out;

	dl_list_init(&this->list);
	this->key = strdup(key);
	if (!this->key) {
		free(this);
		this = NULL;
		goto out;
	}

	this->value = strdup(value);
	if (!this->value) {
		free(this->key);
		free(this);
		this = NULL;
		goto out;
	}
	dl_list_add(&dev->infolist, &this->list);
out:
	if (!this) {
		pv_log(WARN, "Skipping device meta information [%s : %s]",
				(key ? key : "nil"),
				(value ? value : "nil"));
	}
	return this;
}

int pv_device_info_upload(struct pantavisor *pv)
{
	unsigned int len = 0;
	char *json = NULL, *buf = NULL;
	struct pv_devinfo *info = NULL, *tmp = NULL;
	struct dl_list *head = NULL;
	int json_avail = 0;
	int i = 0;
	int bufsize = 0;
	struct log_buffer *log_buffer = NULL;
	/*
	 * we can use one of the large log_buffer. Since
	 * this information won't be very large, it's safe
	 * to assume even the complete json would
	 * be small enough to fit inside this log_buffer.
	 */
	log_buffer = pv_log_get_buffer(true);
	if (!log_buffer) {
		pv_log(INFO, "couldn't allocate buffer to upload device info");
		return -1;
	}

	if (info_parsed)
		goto upload;

	dl_list_init(&pv->dev->infolist);

	buf = log_buffer->buf;
	bufsize = log_buffer->size;

	for (i = 0; i < ARRAY_LEN(pv_device_info_readkeys); i++) {
		int ret = 0;

		pv_device_info_readkeys[i].buf = buf;
		pv_device_info_readkeys[i].buflen = bufsize;
		ret = pv_device_info_readkeys[i].reader(&pv_device_info_readkeys[i]);
		if (!ret) {
			/*
			 * we managed to add at least one item in the list.
			 */
			if (pv_device_info_add(pv->dev, pv_device_info_readkeys[i].key, buf))
				info_parsed = true;
		}
	}
upload:
	if (info_uploaded)
		goto out;
	json = log_buffer->buf;
	json_avail = log_buffer->size;
	json_avail -= sprintf(json, "{");
	len += 1;
	head = &pv->dev->infolist;
	dl_list_for_each_safe(info, tmp, head,
			struct pv_devinfo, list) {
		char *key = format_json(info->key, strlen(info->key));
		char *val = format_json(info->value, strlen(info->value));

		if (key && val) {
			int frag_len = strlen(key) + strlen(val) +
				/* 2 pairs of quotes*/
				2 * 2 +
				/* 1 colon and a ,*/
				1 + 1;
			if (json_avail > frag_len) {
				snprintf(json + len, json_avail,
						"\"%s\":\"%s\",",
						info->key, info->value);
				len += frag_len;
				json_avail -= frag_len;
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
	pv_log(INFO, "device info json = %s", json);
	info_uploaded = !pv_ph_upload_metadata(pv, json);
out:
	pv_log_put_buffer(log_buffer);
	return 0;
}

int pv_device_update_usermeta(struct pantavisor *pv, char *buf)
{
	int ret;
	char *body, *esc;

	body = strdup(buf);
	esc = unescape_str_to_ascii(body, "\\n", '\n');
	ret = pv_usermeta_parse(pv, esc);
	free(esc);
	// clear old
	usermeta_clear(pv);
	return ret;
}

int pv_device_init(struct pantavisor *pv)
{
	if (!pv)
		return -1;
	if (!pv->config)
		return -1;

	pv->dev = calloc(1, sizeof(struct pv_device));
	pv->dev->id = strdup(pv->config->creds.id);
	dl_list_init(&pv->dev->metalist);

	mkdir_p("/pv/user-meta/", 0755);
	if (pv->config->metacachedir)
		mount_bind(pv->config->metacachedir, "/pv/user-meta");

	mkdir_p("/etc/dropbear/", 0755);
	if (pv->config->dropbearcachedir)
		mount_bind(pv->config->dropbearcachedir, "/etc/dropbear");

	return 0;
}

