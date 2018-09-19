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
#include "device.h"

#define FW_PATH		"/lib/firmware"

static void usermeta_add_hint(struct pv_usermeta *m)
{
	int fd;
	char path[PATH_MAX];

	if (!m)
		return;

	sprintf(path, "/pv/user-meta/%s", m->key);

	fd = open(path, O_CREAT | O_RDWR, 0644);
	if (!fd)
		return;

	write(fd, m->value, strlen(m->value));
	close(fd);
}

static void usermeta_remove_hint(struct pv_usermeta *m)
{
	char path[PATH_MAX];

	if (!m)
		return;

	sprintf(path, "/pv/user-meta/%s", m->key);
	remove(path);
}

static void usermeta_remove(struct pv_device *d, char *key)
{
	struct pv_usermeta *curr = d->usermeta;
	struct pv_usermeta *prev = NULL;

	while (curr) {
		if (!strcmp(curr->key, key)) {
			if (curr->key) {
				usermeta_remove_hint(curr);
				free(curr->key);
			}
			if (curr->value)
				free(curr->value);

			if (curr == d->usermeta)
				d->usermeta = curr->next;
			else
				prev->next = curr->next;

			free(curr);
			return;
		}
		prev = curr;
	}
}

struct pv_usermeta* pv_usermeta_get_by_key(struct pv_device *d, char *key)
{
	struct pv_usermeta* curr = d->usermeta;

	while (curr) {
		if (!strcmp(key, curr->key))
			return curr;
		curr = curr->next;
	}

	return NULL;
}

struct pv_usermeta* pv_usermeta_add(struct pv_device *d, char *key, char *value)
{
	struct pv_usermeta *curr, *add;

	if (!d || !key)
		return NULL;

	for (curr = d->usermeta; curr != NULL; curr = curr->next) {
		if (strcmp(curr->key, key) == 0) {
			free(curr->value);
			curr->value = strdup(value);
			goto out;
		}
	}

	// not found? add
	curr = calloc(1, sizeof(struct pv_usermeta));
	add = d->usermeta;

	while (add && add->next) {
		add = add->next;
	}

	if (!add) {
		d->usermeta = add = curr;
	} else {
		add->next = curr;
	}

	curr->key = strdup(key);
	curr->value = strdup(value);

out:
	add = d->usermeta;
	pv_log(DEBUG, "updated user-meta to:");
	while (add) {
		pv_log(DEBUG, "  user-meta['%s'] = '%s'", add->key, add->value);
		add = add->next;
	}

	usermeta_add_hint(curr);

	return curr;
}

static void usermeta_clear(struct pantavisor *pv)
{
	struct pv_usermeta *curr = 0, *prev = 0;

	if (!pv)
		return;
	if (!pv->dev)
		return;

	curr = pv->dev->usermeta;
	while (curr) {
		usermeta_remove_hint(curr);
		if (curr->key)
			free(curr->key);
		if (curr->value)
			free(curr->value);
		prev = curr;
		curr = curr->next;
		free(prev);
	}

	pv->dev->usermeta = NULL;
}

int pv_device_update_meta(struct pantavisor *pv, char *buf)
{
	usermeta_clear(pv);
	return pv_parse_usermeta(pv, buf);
}

int pv_device_init(struct pantavisor *pv)
{
	if (!pv)
		return -1;
	if (!pv->config)
		return -1;

	pv->dev = calloc(1, sizeof(struct pv_device));
	pv->dev->id = strdup(pv->config->creds.id);

	mkdir_p("/pv/user-meta/", 0644);

	return 0;
}
