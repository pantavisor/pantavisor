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

#include "utils/json.h"
#include "utils/str.h"

#define MODULE_NAME "group"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct pv_group *pv_group_new(char *name)
{
	struct pv_group *g;

	g = calloc(1, sizeof(struct pv_group));
	if (g) {
		g->name = strdup(name);
		dl_list_init(&g->platform_refs);
	}

	return g;
}

static void pv_group_empty_platform_refs(struct pv_group *g)
{
	int num_platforms = 0;
	struct pv_platform_ref *pr, *tmp;
	struct dl_list *platform_refs = &g->platform_refs;

	// Iterate over all platform references from group
	dl_list_for_each_safe(pr, tmp, platform_refs, struct pv_platform_ref,
			      list)
	{
		dl_list_del(&pr->list);
		pv_platform_ref_free(pr);
		num_platforms++;
	}

	pv_log(INFO, "removed %d platform references", num_platforms);
}

void pv_group_free(struct pv_group *g)
{
	pv_log(DEBUG, "removing group %s", g->name);

	if (g->name)
		free(g->name);
	pv_group_empty_platform_refs(g);
	free(g);
}

bool pv_group_check_goals(struct pv_group *g, bool log_warn)
{
	struct pv_platform_ref *pr, *tmp;

	dl_list_for_each_safe(pr, tmp, &g->platform_refs,
			      struct pv_platform_ref, list)
	{
		if (!pv_platform_check_goal(pr->ref)) {
			if (log_warn)
				pv_log(WARN,
				       "platform '%s' from group '%s' goal not achieved",
				       pr->ref->name, g->name);
			return false;
		}
	}

	return true;
}

static struct pv_platform_ref *
pv_group_fetch_platform_ref(struct pv_group *g, struct pv_platform *p)
{
	struct pv_platform_ref *pr, *tmp;

	dl_list_for_each_safe(pr, tmp, &g->platform_refs,
			      struct pv_platform_ref, list)
	{
		if (pv_str_matches(p->name, strlen(p->name), pr->ref->name,
				   strlen(pr->ref->name)))
			return pr;
	}

	return NULL;
}

static void pv_group_rm_platform(struct pv_group *g, struct pv_platform *p)
{
	struct pv_platform_ref *pr;

	if (!p->group)
		return;

	pr = pv_group_fetch_platform_ref(g, p);

	pv_log(DEBUG, "removing platform '%s' reference from group '%s'",
	       p->name, g->name);

	dl_list_del(&pr->list);
	pv_platform_ref_free(pr);
}

void pv_group_add_platform(struct pv_group *g, struct pv_platform *p)
{
	struct pv_platform_ref *pr;

	pv_group_rm_platform(g, p);

	pv_log(DEBUG, "adding platform '%s' reference to group '%s'", p->name,
	       g->name);

	p->group = g;

	pr = pv_platform_ref_new(p);
	if (pr) {
		dl_list_init(&pr->list);
		dl_list_add_tail(&g->platform_refs, &pr->list);
	}
}

void pv_group_add_json(struct pv_json_ser *js, struct pv_group *g)
{
	struct pv_platform_ref *pr, *tmp;

	pv_json_ser_object(js);
	{
		pv_json_ser_key(js, "name");
		pv_json_ser_string(js, g->name);
		pv_json_ser_key(js, "status");
		pv_json_ser_array(js);
		{
			dl_list_for_each_safe(pr, tmp, &g->platform_refs,
					      struct pv_platform_ref, list)
			{
				pv_platform_add_goal_json(js, pr->ref);
			}

			pv_json_ser_array_pop(js);
		}

		pv_json_ser_object_pop(js);
	}
}
