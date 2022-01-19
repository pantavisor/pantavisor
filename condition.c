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

#include "condition.h"
#include "utils/str.h"

#define MODULE_NAME             "condition"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

struct pv_condition* pv_condition_new(char *key, char *eval_value)
{
	struct pv_condition *c;

	c = calloc(1, sizeof(struct pv_condition));
	if (c) {
		c->key = strdup(key);
		c->eval_value = strdup(eval_value);
		c->curr_value = strdup("");
	}

	return c;
}

void pv_condition_free(struct pv_condition *c)
{
	pv_log(DEBUG, "removing condition %s", c->key);

	if (c->key)
		free(c->key);
	if (c->eval_value)
		free(c->eval_value);
	if (c->curr_value)
		free(c->curr_value);
	free(c);
}

void pv_condition_set_value(struct pv_condition *c, char *curr_value)
{
	if (c->curr_value)
		free(c->curr_value);
	c->curr_value = strdup(curr_value);
}

bool pv_condition_check(struct pv_condition *c)
{
	return pv_str_matches(c->eval_value,
		strlen(c->eval_value),
		c->curr_value,
		strlen(c->curr_value));
}

char *pv_condition_get_json(struct pv_condition *c)
{
	int len;
	char *json;

	len = strlen(c->key) +
		strlen(c->eval_value) +
		strlen(c->curr_value) +
		strlen("{\"key\":\"\",\"eval_value\":\"\",\"curr_value\":\"\"}");
	json = calloc(1, (len + 1) * sizeof(char*));
	snprintf(json, len + 1, "{\"key\":\"%s\",\"eval_value\":\"%s\",\"curr_value\":\"%s\"}",
		c->key, c->eval_value, c->curr_value);

	return json;
}

struct pv_condition_ref* pv_condition_ref_new(struct pv_condition *c)
{
	struct pv_condition_ref *cr;

	cr = calloc(1, sizeof(struct pv_condition_ref));
	if (cr) {
		cr->ref = c;
	}

	return cr;
}

void pv_condition_ref_free(struct pv_condition_ref *cr)
{
	free(cr);
}
