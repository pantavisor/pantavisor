/*
 * Copyright (c) 2021 Pantacor Ltd.
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

#ifndef UTILS_PV_JSON_H_
#define UTILS_PV_JSON_H_

#include <jsmn/jsmnutil.h>
#include <stdbool.h>

#define JSONB_STATIC
#include "json-build/json-build.h"

int pv_json_get_key_count(const char *buf, const char *key, jsmntok_t *tok,
			  int tokc);
char *pv_json_get_one_str(const char *buf, jsmntok_t **tok);
char *pv_json_format(const char *buf, int len);
int pv_json_get_value_int(const char *buf, const char *key, jsmntok_t *tok,
			  int tokc);
char *pv_json_get_value(const char *buf, const char *key, jsmntok_t *tok,
			int tokc);
char *pv_json_array_get_one_str(const char *buf, int *n, jsmntok_t **tok);

struct pv_json_ser {
	jsonb b;
	int block_size;
	char *buf;
	int size;
};

void pv_json_ser_init(struct pv_json_ser *js, size_t size);

int pv_json_ser_object(struct pv_json_ser *js);
int pv_json_ser_object_pop(struct pv_json_ser *js);
int pv_json_ser_key(struct pv_json_ser *js, const char *key);
int pv_json_ser_array(struct pv_json_ser *js);
int pv_json_ser_array_pop(struct pv_json_ser *js);
int pv_json_ser_string(struct pv_json_ser *js, const char *value);
int pv_json_ser_bool(struct pv_json_ser *js, bool value);
int pv_json_ser_number(struct pv_json_ser *js, double value);

char *pv_json_ser_str(struct pv_json_ser *js);

#endif /* UTILS_PV_JSON_H_ */
