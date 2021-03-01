/*
 * Copyright (c) 2020 Pantacor Ltd.
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

#include <stdlib.h>
#include <string.h>

#define MODULE_NAME			"jsons"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "jsons.h"

#include "state.h"

struct pv_json* pv_jsons_add(struct pv_state *s, char *name, char *value)
{
	struct pv_json *this = calloc(1, sizeof(struct pv_json));

	if (this) {
		this->name = strdup(name);
		this->value = strdup(value);

		dl_list_init(&this->list);
		dl_list_add(&s->jsons, &this->list);

		return this;
	}

	return NULL;
}

void pv_jsons_remove(struct pv_json *j)
{
	dl_list_del(&j->list);
	pv_json_free(j);
}

struct pv_json* pv_jsons_get_by_name(struct pv_state *s, char *name)
{
	struct pv_json *curr, *tmp;
	struct dl_list *head = &s->jsons;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_json, list) {
		if (!strcmp(curr->name, name))
			return curr;
	}
	return NULL;
}

void pv_json_free(struct pv_json *json)
{
	if (json->name)
		free(json->name);
	if (json->value)
		free(json->value);

	free(json);
}

void pv_jsons_empty(struct pv_state *s)
{
	int num_obj = 0;
	struct pv_json *curr, *tmp;
	struct dl_list *head = &s->jsons;

	dl_list_for_each_safe(curr, tmp, head,
			struct pv_json, list) {
		dl_list_del(&curr->list);
		pv_json_free(curr);
		num_obj++;
	}

	pv_log(INFO, "removed %d jsons", num_obj);
}
