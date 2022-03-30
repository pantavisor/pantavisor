/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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

#include "objects.h"
#include "state.h"
#include "storage.h"
#include "paths.h"
#include "utils/math.h"
#include "utils/file.h"
#include "utils/math.h"
#include "utils/fs.h"
#include "utils/str.h"

#define MODULE_NAME			"objects"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

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
	char path[PATH_MAX];

	if (this) {
		this->name = strdup(filename);
		this->id = strdup(id);
		pv_paths_storage_trail_file(path, PATH_MAX, s->rev, filename);
		this->relpath = strdup(path);
		pv_paths_storage_object(path, PATH_MAX, id);
		this->objpath = strdup(path);
		dl_list_init(&this->list);
		dl_list_add(&s->objects, &this->list);
		return this;
	}
	return NULL;
}

void pv_objects_remove(struct pv_object *o)
{
	dl_list_del(&o->list);
	pv_object_free(o);
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

	pv_paths_storage_object(path, PATH_MAX, "");

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

		// if not sha256 string ... skip
		if (strlen(curr->path) != 64)
			continue;

		pv_paths_storage_object(path, PATH_MAX, curr->path);
		size_object = pv_file_get_size(path);
		if (size_object <= 0)
			continue;

		line_len = strlen(curr->path) + get_digit_count(size_object) + 26;
		json = realloc(json, len + line_len + 1);
		SNPRINTF_WTRUNC(&json[len], line_len + 1, "{\"sha256\": \"%s\", \"size\": \"%d\"},", curr->path, size_object);
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
