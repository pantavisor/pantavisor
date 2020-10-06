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

#include "loop.h"

#include "utils.h"
#include "pantavisor.h"
#include "addons.h"

#define FW_PATH		"/lib/firmware"

struct pv_addon* pv_addon_get_by_name(struct pv_state *s, char *name)
{
	struct pv_addon* v = s->bsp->addons;

	while (v) {
		if (!strcmp(name, v->name))
			return v;
		v = v->next;
	}

	return NULL;
}

void pv_addon_remove(struct pv_state *s, char *name)
{
	struct pv_addon *v = s->bsp->addons;
	struct pv_addon *prev = NULL;

	while (v) {
		if (!strcmp(v->name, name)) {
			if (v->name)
				free(v->name);

			if (v == s->bsp->addons)
				s->bsp->addons = v->next;
			else
				prev->next = v->next;
			free(v);
			return;
		}
		prev = v;
	}
}

struct pv_addon* pv_addon_add(struct pv_state *s, char *name)
{
	struct pv_addon *this = calloc(1, sizeof(struct pv_addon));
	struct pv_addon *add = s->bsp->addons;

	while (add && add->next) {
		add = add->next;
	}

	if (!add) {
		s->bsp->addons = add = this;
	} else {
		add->next = this;
	}

	this->name = name;

	return this;
}

void pv_addon_free(struct pv_state *s)
{
	struct pv_addon *this = s->bsp->addons;
	while (this) {
		struct pv_addon *a = this;
		this = a->next;
		free(this);
	}
}
