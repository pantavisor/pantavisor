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

#include "utils.h"
#include "objects.h"
#include "state.h"
#include "storage.h"

#define MODULE_NAME			"objects"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

char** pv_objects_get_all_ids(struct pantavisor *pv)
{
	int i = 0, n, bufsize;
	struct dirent **dirs;
	char **ids = 0;
	char path[PATH_MAX];

	sprintf(path, "%s/objects/", pv_config_get_storage_mntpoint());
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

int pv_objects_id_in_step(struct pv_state *s, char *id)
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

struct pv_object* pv_objects_add(struct pv_state *s, char *filename, char *id, char *mntpoint)
{
	struct pv_object *this = calloc(1, sizeof(struct pv_object));
	int size;

	if (this) {
		this->name = strdup(filename);
		this->id = strdup(id);

		// init relpath
		size = sizeof(RELPATH_FMT) + strlen(mntpoint) +
			strlen(filename) + strlen(s->rev);

		this->relpath = calloc(1, size * sizeof(char));
		if (this->relpath)
			sprintf(this->relpath , RELPATH_FMT, mntpoint, s->rev, filename);
		else
			goto free_object;

		// init objpath
		size = sizeof(OBJPATH_FMT) + strlen(mntpoint) + strlen(id);

		this->objpath = calloc(1, size * sizeof(char));
		if (this->objpath)
			sprintf(this->objpath, OBJPATH_FMT, mntpoint, id);
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

void pv_objects_remove(struct pv_object *o)
{
	dl_list_del(&o->list);
	pv_object_free(o);
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

void pv_objects_empty(struct pv_state *s)
{
	int num_obj = 0;
	struct pv_object *curr, *tmp;
	struct dl_list *head = &s->objects;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_object, list) {
		dl_list_del(&curr->list);
		pv_object_free(curr);
		num_obj++;
	}

	pv_log(INFO, "removed %d objects", num_obj);
}

char *pv_objects_get_list_string()
{
	struct dl_list objects; // pv_path
	char path[PATH_MAX];
	struct pv_path *curr, *tmp;
	int len = 1, line_len;
	char *json = calloc(1, len);
	unsigned int size_object;

	sprintf(path, "%s/objects/", pv_config_get_storage_mntpoint());

	dl_list_init(&objects);
	pv_storage_get_subdir(path, "", &objects);

	// open json
	json[0]='[';

	if (dl_list_empty(&objects)) {
		len++;
		goto out;
	}

	// add object info to json
	dl_list_for_each_safe(curr, tmp, &objects,
		struct pv_path, list) {

		if (!strncmp(curr->path, "..", strlen("..")) ||
			!strncmp(curr->path, ".", strlen(".")))
			continue;

		size_object = pv_storage_get_file_size(path, curr->path);
		if (size_object <= 0)
			continue;

		line_len = strlen(curr->path) + get_digit_count(size_object) + 26;
		json = realloc(json, len + line_len + 1);
		snprintf(&json[len], line_len + 1, "{\"sha256\": \"%s\", \"size\": \"%d\"},", curr->path, size_object);
		len += line_len;
	}

	pv_storage_free_subdir(&objects);
out:
	len += 1;
	json = realloc(json, len);
	// close json
	json[len-2] = ']';
	json[len-1] = '\0';

	return json;
}
