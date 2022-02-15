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
#ifndef PV_CONDITION_H
#define PV_CONDITION_H

#include <stdbool.h>

#include "utils/list.h"

struct pv_condition {
	char *plat;
	char *key;
	char *eval_value;
	char *curr_value;
	struct dl_list list; // pv_condition
};

struct pv_condition* pv_condition_new(const char *plat, const char *key, const char *eval_value);
void pv_condition_free(struct pv_condition *c);

void pv_condition_set_value(struct pv_condition *c, const char *curr_value);
bool pv_condition_check(struct pv_condition *c);

char *pv_condition_get_json(struct pv_condition *c);

struct pv_condition_ref {
	struct pv_condition *ref;
	struct dl_list list; // pv_condition_ref
};

struct pv_condition_ref* pv_condition_ref_new(struct pv_condition *c);
void pv_condition_ref_free(struct pv_condition_ref *cr);

struct pv_condition* pv_condition_get_ref(struct pv_condition_ref *cr);

#endif // PV_CONDITION_H
