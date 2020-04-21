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
		free(curr->value);
		curr->value = strdup(value);
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
	if (changed)
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
		dl_list_del(&curr->list);
		usermeta_free_one(curr);
	}
}

struct pv_devinfo* pv_device_info_add(struct pv_device *dev, char *key, char *value)
{
	struct pv_devinfo *this;

	if (!key || !value)
		return NULL;

	this = calloc(1, sizeof(struct pv_devinfo));
	if (!this)
		return NULL;

	dl_list_init(&this->list);
	this->key = strdup(key);
	this->value = strdup(value);
	dl_list_add(&dev->infolist, &this->list);

	return this;
}

static int _get_endian(void)
{
	unsigned long t = 0x00102040;
	return ((((char*)(&t))[0]) == 0x40);
}

static char* _get_dt_model(void)
{
	int fd;
	char *buf;
	struct stat st;

	if (stat("/proc/device-tree/model", &st))
		return NULL;

	buf = calloc(1, 256);
	if (!buf)
		return NULL;

	fd = open("/proc/device-tree/model", O_RDONLY);
	if (fd >= 0) {
		read(fd, buf, 256);
		close(fd);
	}

	return buf;
}

static char* _get_cpu_model(void)
{
	int fd = -1;
	struct stat st;
	char *model = NULL, *buf, *p, *m;

	if (stat("/proc/cpuinfo", &st))
		return NULL;

	buf = calloc(1, 4096);
	if (!buf)
		return NULL;

	fd = open("/proc/cpuinfo", O_RDONLY);
	if ((fd >= 0) && read(fd, buf, 4096)) {
		p = strstr(buf, PREFIX_MODEL);
		if (p) {
			m = p + sizeof(PREFIX_MODEL);
			p = strchr(m, '\n');
			if (!p) goto out;
			model = calloc(1, p-m+1);
			memcpy(model, m, p-m);
		}
	}

out:
	close(fd);
	free(buf);

	return model;
}

int pv_device_info_upload(struct pantavisor *pv)
{
	int len = 0;
	char *json, *buf, *t;
	struct pv_devinfo *info, *tmp;
	struct dl_list *head;

	if (info_parsed)
		goto upload;

	dl_list_init(&pv->dev->infolist);

	buf = calloc(1, BUF_CHUNK * sizeof(char));
	sprintf(buf, "%s/%s/%s", PV_ARCH, PV_BITS, _get_endian() ? "EL" : "EB");
	pv_device_info_add(pv->dev, "pantavisor.arch", buf);
	pv_device_info_add(pv->dev, "pantavisor.version", (char *) pv_build_version);
	if ((t = _get_dt_model())) {
		pv_device_info_add(pv->dev, "pantavisor.dtmodel", t);
		free(t);
	}
	if ((t = _get_cpu_model())) {
		pv_device_info_add(pv->dev, "pantavisor.cpumodel", t);
		free(t);
	}

	sprintf(buf, "%d", pv->state->rev);
	pv_device_info_add(pv->dev, "pantavisor.revision", buf);

upload:
	if (info_uploaded)
		goto out;

	json = calloc(1, BUF_CHUNK * sizeof(char));
	sprintf(json, "{");
	len += 1;
	head = &pv->dev->infolist;
	dl_list_for_each_safe(info, tmp, head,
			struct pv_devinfo, list) {
		sprintf(buf, "\"%s\":\"%s\",", info->key, info->value);
		strcat(json, buf);
		len += strlen(buf);
	}
	json[len-1] = '}';
	json[len] = '\0';
	if (buf)
		free(buf);

	info_uploaded = !pv_ph_upload_metadata(pv, json);

out:
	return 0;
}

int pv_device_update_usermeta(struct pantavisor *pv, char *buf)
{
	int ret;
	char *body, *esc;

	// clear old
	usermeta_clear(pv);

	body = strdup(buf);
	esc = unescape_str_to_ascii(body, "\\n", '\n');

	ret = pv_usermeta_parse(pv, esc);
	free(esc);

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

