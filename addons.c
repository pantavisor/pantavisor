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

#define MODULE_NAME             "addon"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "addons.h"
#include "loop.h"
#include "utils.h"
#include "pantavisor.h"
#include "state.h"

#define FW_PATH		"/lib/firmware"

struct pv_addon* pv_addon_add(struct pv_state *s, char *name)
{
	struct pv_addon *this = calloc(1, sizeof(struct pv_addon));
	struct pv_addon *add = s->addons;

	while (add && add->next) {
		add = add->next;
	}

	if (!add) {
		s->addons = add = this;
	} else {
		add->next = this;
	}

	this->name = name;

	return this;
}

static void pv_addons_free_addon(struct pv_addon *a)
{
	if (!a)
		return;

	if (a->name)
		free(a->name);

	free(a);
}

void pv_addons_remove(struct pv_state *s)
{
	int num_addons = 0;
	struct pv_addon *a = NULL, *prev = NULL, *t = NULL;

	if (!s->addons)
		return;

	// Iterate over all plats from state
	a = s->addons;
	prev = s->addons;
	while (a) {
		pv_log(INFO, "removing addon %s", a->name);

		pv_addons_free_addon(a);			

		if (a == s->addons)
			s->addons = a->next;
		else
			prev->next = a->next;

		t = a;
		a = a->next;
		free(t);
		num_addons++;
	}

	pv_log(INFO, "removed '%d' addons", num_addons);

}
