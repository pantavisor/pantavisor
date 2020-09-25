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
#include <ctype.h>
#include <dirent.h>
#include <netdb.h>

#include <linux/limits.h>

#define MODULE_NAME			"objects"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"
#include "objects.h"
#include "state.h"

char** pv_objects_get_all_ids(struct pantavisor *pv)
{
	int i = 0, n, bufsize;
	struct dirent **dirs;
	char **ids = 0;
	char path[PATH_MAX];

	sprintf(path, "%s/objects/", pv->config->storage.mntpoint);
	n = scandir(path, &dirs, NULL, alphasort);
	if (n < 0)
		goto out;

	// allocate enough minus '.' and '..' + null term str
	bufsize = n-1;
	ids = calloc(1, bufsize * sizeof(char*));

	while (n--) {
		char *tmp = dirs[n]->d_name;
		if (!strcmp(tmp, ".") || !strcmp(tmp, ".."))
			continue;
		ids[i] = strdup(tmp);
		i++;
		free(dirs[n]);
	}

	// null terminate string array
	ids[bufsize-1] = 0;

	free(dirs);

out:
	return ids;
}

int pv_objects_id_in_step(struct pantavisor *pv, struct pv_state *s, char *id)
{
	struct pv_object *curr, *tmp;
	struct dl_list *head;

	if (!s)
		return 0;
	head = &s->objects;
	dl_list_for_each_safe(curr, tmp, head,
			struct pv_object, list) {
		if (!strcmp(curr->id, id))
			return 1;
	}
	return 0;
}

struct pv_object* pv_objects_add(struct pv_state *s, char *filename, char *id, char *c)
{
	struct pv_object *this = calloc(1, sizeof(struct pv_object));
	int size;

	if (this) {
		this->name = strdup(filename);
		this->id = strdup(id);

		size = sizeof(RELPATH_FMT) + strlen(c) +
			strlen(filename) + get_digit_count(s->rev);

		this->relpath = calloc(1, size * sizeof(char));
		if (this->relpath)
			sprintf(this->relpath , RELPATH_FMT, c, s->rev, filename);
		else
			goto free_object;

		size = sizeof(OBJPATH_FMT) + strlen(c) + strlen(id);

		this->objpath = calloc(1, size * sizeof(char));
		if (this->objpath)
			sprintf(this->objpath, OBJPATH_FMT, c, id);
		else
			goto free_object;
		dl_list_init(&this->list);
		dl_list_add(&s->objects, &this->list);
		return this;
free_object:
		pv_object_free(this);
	}
	return NULL;
}

struct pv_object* pv_objects_get_by_name(struct pv_state *s, char *name)
{
	struct pv_object *curr, *tmp;
	struct dl_list *head = &s->objects;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_object, list) {
		if (!strcmp(curr->name, name))
			return curr;
	}
	return NULL;
}

void pv_objects_remove(struct pv_state *s)
{
	struct pv_object *curr, *tmp;
	struct dl_list *head = &s->objects;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_object, list) {
		dl_list_del(&curr->list);
		pv_object_free(curr);
	}
}
