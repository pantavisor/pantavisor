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

#ifndef PV_JSONS_H
#define PV_JSONS_H

#include "utils/list.h"
#include "state.h"

struct pv_json {
	char *name;
	char *value;
	struct pv_platform *plat;
	struct dl_list list;
};

struct pv_json* pv_jsons_add(struct pv_state *s, char *name, char *value);
void pv_jsons_remove(struct pv_json *j);
struct pv_json* pv_jsons_get_by_name(struct pv_state *s, char *name);
void pv_jsons_empty(struct pv_state *s);

void pv_jsons_free(struct pv_json *json);

bool pv_jsons_verify_signature(struct pv_state *s, const char *component);

#define pv_jsons_iter_begin(state, item) 	\
{\
	struct pv_json *item##__tmp;\
	struct dl_list *item##__head = &(state)->jsons;\
	dl_list_for_each_safe(item, item##__tmp, item##__head,\
			struct pv_json, list)

#define pv_jsons_iter_end }
#endif // PV_JSONS_H
