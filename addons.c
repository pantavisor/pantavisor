/*
 * Copyright (c) 2018-2022 Pantacor Ltd.
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

#include "addons.h"
#include "loop.h"
#include "pantavisor.h"
#include "state.h"

#define MODULE_NAME "addon"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void pv_addon_free(struct pv_addon *a)
{
	if (!a)
		return;

	if (a->name)
		free(a->name);

	free(a);
}

void pv_addons_empty(struct pv_state *s)
{
	int num_addons = 0;
	struct pv_addon *a, *tmp;
	struct dl_list *addons = &s->addons;

	// Iterate over all plats from state
	dl_list_for_each_safe(a, tmp, addons, struct pv_addon, list)
	{
		pv_log(DEBUG, "removing addon %s", a->name);
		dl_list_del(&a->list);
		pv_addon_free(a);
		num_addons++;
	}

	pv_log(INFO, "removed %d addons", num_addons);
}

struct pv_addon *pv_addon_add(struct pv_state *s, char *name)
{
	struct pv_addon *a = calloc(1, sizeof(struct pv_addon));

	if (a) {
		a->name = name;
		dl_list_init(&a->list);
		dl_list_add_tail(&s->addons, &a->list);
	}

	return a;
}
