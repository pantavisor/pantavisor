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

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "json.h"

/*
 * private struct.
 */
struct json_format {
       char ch;
       int *off_dst;
       int *off_src;
       const char *src;
       char *dst;
       int (*format)(struct json_format *);
};


static char nibble_to_hexchar(char nibble_val) {

	if (nibble_val <= 9)
		return '0' + nibble_val;
	nibble_val -= 10;
	return 'A' + nibble_val;
}

static int modify_to_json(struct json_format *json_fmt)
{
	char nibble_val;

	json_fmt->dst[(*json_fmt->off_dst)++] = '\\';
	json_fmt->dst[(*json_fmt->off_dst)++] = 'u';
	json_fmt->dst[(*json_fmt->off_dst)++] = '0';
	json_fmt->dst[(*json_fmt->off_dst)++] = '0';
	/*
	 * get the higher order byte nibble.
	 */
	nibble_val = (json_fmt->ch & 0xff) >> 4;
	json_fmt->dst[(*json_fmt->off_dst)++] = nibble_to_hexchar(nibble_val);
	/*
	 * get the lower order byte nibble.
	 */
	nibble_val = (json_fmt->ch & 0x0f);
	json_fmt->dst[(*json_fmt->off_dst)++] = nibble_to_hexchar(nibble_val);

	return 0;
}

static bool char_is_json_special(char ch)
{
	/* From RFC 7159, section 7 Strings
	 * All Unicode characters may be placed within the
	 * quotation marks, except for the characters that must be escaped:
	 * quotation mark, reverse solidus, and the control characters (U+0000
	 * through U+001F).
	 */

	switch(ch) {
		case 0x00 ... 0x1f:
		case '\\':
		case '\"':
			return true;
		default:
			return false;
	}
}

int pv_json_get_key_count(char *buf, char *key, jsmntok_t *tok, int tokc)
{
	int count = 0;

	for (int i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen(key);

		if (n == m &&
		    tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			count += 1;
		}
	}

	return count;
}

char* pv_json_get_one_str(const char *buf, jsmntok_t **tok)
{
	int c;
	char *value = NULL;
	c = (*tok)->end - (*tok)->start;
	value = calloc(1, (c+1) * sizeof(char));
	if (value)
		strncpy(value, buf+(*tok)->start, c);
	return value;
}

char* pv_json_array_get_one_str(const char *buf, int *n, jsmntok_t **tok)
{
	char *value = NULL;

	if (*n == 0)
		return NULL;
	value = pv_json_get_one_str(buf, tok);
	if (value) {
		(*tok)++;
		(*n)--;
	}
	return value;
}

int pv_json_get_value_int(char *buf, char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int val = 0;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen (key);
		if (tok[i].type == JSMN_PRIMITIVE
		    && n == m
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			val = atoi(idval);
			free(idval);
			return val;
		} else if (t==1) {
			return val;
		}
	}
	return val;
}

char* pv_json_get_value(const char *buf, const char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen (key);
		if (n == m
		    && tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			return idval;
		} else if (t==1) {
			return NULL;
		}
	}
	return NULL;
}

char* pv_json_format(char *buf, int len)
{
	char *json_string = NULL;
	int idx = 0;
	int json_str_idx = 0;

	if (len > 0) //We make enough room for worst case.
		json_string = (char*) calloc(1, (len * 6) + 1); //Add 1 for '\0'.

	if (!json_string)
		goto out;
	while (len > idx) {
		if (char_is_json_special(buf[idx])) {
			struct json_format json_fmt = {
				.src = buf,
				.dst = json_string,
				.off_dst = &json_str_idx,
				.off_src = &idx,
				.ch = buf[idx],
				.format = modify_to_json
			};
			json_fmt.format(&json_fmt);
		} else
			json_string[json_str_idx++] = buf[idx];
		idx++;
	}
out:
	if (json_string) {
		char *shrinked = realloc(json_string, strlen(json_string) + 1);
		if (shrinked)
			json_string = shrinked;
	}
	return json_string;
}
