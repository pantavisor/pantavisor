/*
 * Copyright (c) 2022 Pantacor Ltd.
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
#include <string.h>
#include <stdio.h>

#include "group.h"

#define MODULE_NAME             "group"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

struct pv_group* pv_group_new(char *name)
{
	struct pv_group *g;

	g = calloc(1, sizeof(struct pv_group));

	g->name = strdup(name);
	dl_list_init(&g->conditions);

	return g;
}

static void pv_group_empty_conditions(struct pv_group *g)
{
	int num_conditions = 0;
	struct pv_condition *c, *tmp;
	struct dl_list *conditions = &g->conditions;

	// Iterate over all conditions from group
	dl_list_for_each_safe(c, tmp, conditions,
		struct pv_condition, list) {
		dl_list_del(&c->list);
		pv_condition_free(c);
		num_conditions++;
	}

	pv_log(INFO, "removed %g conditions", num_conditions);
}

void pv_group_free(struct pv_group *g)
{
	pv_log(DEBUG, "removing group %s", g->name);

	if (g->name)
		free(g->name);
	pv_group_empty_conditions(g);
	free(g);
}

void pv_group_add_condition(struct pv_group *g, struct pv_condition *c)
{
	pv_log(DEBUG, "adding condition %s to group", c->key);

	dl_list_init(&c->list);
	dl_list_add_tail(&g->conditions, &c->list);
}

int pv_group_report_condition(struct pv_group *g, char *plat, char *key, char *value)
{
	int ret = -1;
	struct pv_condition *c, *tmp;

	dl_list_for_each_safe(c, tmp, &g->conditions,
			struct pv_condition, list) {
		if (!pv_condition_report(c, plat, key, value))
			ret = 0;
	}

	return ret;
}

char* pv_group_get_json(struct pv_group *g)
{
	int len, line_len;
	char *json, *line;
	struct pv_condition *c, *tmp;

	// open json
	len = strlen(g->name) + strlen("{\"name\":\"\",\"conditions\":[");
	json = calloc(1, (len + 1) * sizeof(char*));
	snprintf(json, len + 1, "{\"name\":\"%s\",\"conditions\":[", g->name);

	if (dl_list_empty(&g->conditions))
		goto close;

	dl_list_for_each_safe(c, tmp, &g->conditions,
			struct pv_condition, list) {
		line = pv_condition_get_json(c);
		line_len = strlen(line) + 1;
		json = realloc(json, len + line_len + 1);
		snprintf(&json[len], line_len + 1, "%s,", line);
		len += line_len;
		free(line);
	}

	// remove ,
	len -= 1;

close:
	// close json
	len += 3;
	json = realloc(json, len);
	json[len-3] = ']';
	json[len-2] = '}';
	json[len-1] = '\0';

	return json;
}
