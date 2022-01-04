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
