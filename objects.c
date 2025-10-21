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
#include <ctype.h>
#include <dirent.h>
#include <netdb.h>

#include <linux/limits.h>

#include "objects.h"
#include "state.h"
#include "storage.h"
#include "paths.h"
#include "utils/math.h"
#include "utils/fs.h"
#include "utils/math.h"
#include "utils/str.h"

#define MODULE_NAME "objects"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

int pv_objects_id_in_step(struct pv_state *s, char *id)
{
	struct pv_object *curr, *tmp;
	struct dl_list *head;

	if (!s)
		return 0;
	head = &s->objects;
	dl_list_for_each_safe(curr, tmp, head, struct pv_object, list)
	{
		if (!strcmp(curr->id, id))
			return 1;
	}
	return 0;
}

struct pv_object *pv_objects_add(struct pv_state *s, char *filename, char *id,
				 char *mntpoint)
{
	struct pv_object *this = calloc(1, sizeof(struct pv_object));

	if (pv_objects_fetch_object_id(&s->objects, id))
		return NULL;

	if (this) {
		this->name = strdup(filename);
		this->id = strdup(id);
		dl_list_init(&this->list);
		dl_list_add(&s->objects, &this->list);
		return this;
	}
	return NULL;
}

struct pv_object *pv_objects_fetch_object_id(struct dl_list *objects,
					     const char *id)
{
	struct pv_object *o, *tmp;

	if (!id)
		return NULL;

	// Iterate over all objects from state
	dl_list_for_each_safe(o, tmp, objects, struct pv_object, list)
	{
		if (pv_str_matches(o->id, strlen(o->id), id, strlen(id)))
			return o;
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

	dl_list_for_each_safe(curr, tmp, head, struct pv_object, list)
	{
		dl_list_del(&curr->list);
		pv_object_free(curr);
		num_obj++;
	}

	pv_log(INFO, "removed %d objects", num_obj);
}

char *pv_objects_get_list_string()
{
	char path[PATH_MAX];
	struct dl_list objects; // pv_path
	struct pv_path *curr, *tmp;
	off_t size;
	char size_str[64];

	pv_paths_storage_object(path, PATH_MAX, "");

	dl_list_init(&objects);
	pv_storage_get_subdir(path, "", &objects);

	struct pv_json_ser js;
	pv_json_ser_init(&js, 4096);

	pv_json_ser_array(&js);
	{
		dl_list_for_each_safe(curr, tmp, &objects, struct pv_path, list)
		{
			// if not sha256 string... skip
			if (strlen(curr->path) != 64)
				continue;

			pv_paths_storage_object(path, PATH_MAX, curr->path);
			size = pv_fs_path_get_size(path);
			if (size < 0)
				continue;
			SNPRINTF_WTRUNC(size_str, 64, "%jd", (intmax_t)size);

			pv_json_ser_object(&js);
			{
				pv_json_ser_key(&js, "sha256");
				pv_json_ser_string(&js, curr->path);
				pv_json_ser_key(&js, "size");
				pv_json_ser_string(&js, size_str);
				pv_json_ser_object_pop(&js);
			}
		}
		pv_json_ser_array_pop(&js);
	}

	pv_storage_free_subdir(&objects);
	return pv_json_ser_str(&js);
}
