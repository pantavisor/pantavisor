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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MODULE_NAME             "parser-utils"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "pantavisor.h"
#include "pvlogger.h"
#include "volumes.h"
#include "utils.h"
#include "jsons.h"
#include "json.h"
#include "parser.h"
#include "parser_bundle.h"

int __start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
						jsmntype_t type, 
						jsmntok_t *__tokv, int __tokc)
{
	jsmntok_t *tokv = NULL;
	int tokc, ret = 0;
	bool do_free = true;

	if (__tokv) {
		tokv = tokv;
		tokc = __tokc;
		do_free = false;
	}
	if (jka_arr) {
		jsmntok_t** keys;
		struct json_key_action *jka = jka_arr;

		if (!tokv) {
			ret = jsmnutil_parse_json(buf, &tokv, &tokc);
			if ( ret <= 0)
				goto out;
		}
		if (type == JSMN_ARRAY) {
			struct json_key_action __jka_arr = {
				.key = NULL,
				.action = do_action_for_array,
				.type = JSMN_ARRAY,
				.opaque = (void*)jka_arr,
				.buf = buf,
				.tokc = tokc,
				.tokv = tokv
			};
			ret = do_one_jka_action(&__jka_arr);
			jka->buf = NULL;
			jka->tokv = NULL;
			jka->tokc = 0;
			goto free_tokens;
		}

		if (type != JSMN_OBJECT) {
			ret = -1;
			goto free_tokens;
		}
		keys = jsmnutil_get_object_keys(buf, tokv);
		ret = 0;
		if (!keys) {
			pv_log(ERROR, "json cannot be parsed");
			ret = -1;
			goto free_tokens;
		}
		while ( !ret && jka->key ) {
			jka->tokc = tokc;
			jka->buf = buf;
			jka->tokv = do_lookup_json_key(keys, buf, jka->key);
			if (jka->tokv)
				ret = do_one_jka_action(jka);
			jka->tokv = NULL;
			jka->buf = NULL;
			jka++;
		}
		if (keys)
			jsmnutil_tokv_free(keys);
	}
free_tokens:
	if (tokv && do_free)
		free(tokv);
out:
	return ret;
}

int start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
					jsmntype_t type)
{
	return __start_json_parsing_with_action(buf, jka_arr, type, NULL, 0);
}

int do_json_key_action_object(struct json_key_action *jka)
{
	int  ret = 0;

	if (jka->action)
		ret = jka->action(jka, NULL);
	return ret;
}

void do_json_key_action_save(struct json_key_action *jka, char *value)
{
	if (jka->opaque) {
		*jka->opaque = strdup(value);
	}
}

/*
 * For arrays, the callback provided will be called
 * for all tokens found in array. Caller can define
 * the json structure to operate on in a similar way
 * and may use start_json_parsing_with_action again,
 * provided the array is a object. Otherwise caller needs
 * to handle the keys passed using the jsmnutil_* functions.
 * */
int do_json_key_action_array(struct json_key_action *jka)
{
	int i = 0, arr_count = 0, ret = 0;
	jsmntok_t **arr = NULL, **arr_i = NULL;
	jsmntok_t *array_token = jka->tokv;

	/*
	 * The only time it happens when
	 * json start is itself an array.
	 */
	if (jka->key != NULL)
		array_token += 1;
	arr_count = array_token->size;

	arr_i = arr = jsmnutil_get_array_toks(jka->buf, array_token);

	if (!arr_i) {
		ret = -1;
		goto out;
	}

	for ( i = 0; i < arr_count && !ret; i++, arr_i++) {
		jsmntok_t *prev_tok = jka->tokv;
		if (jka->action) {
			jka->tokv = *arr_i;/*This is the usable token*/
			/*
			 * Actions for arrays must be provided.
			 * The value is always NULL but action gets
			 * the next token which can be parsed by it.
			 * */
			ret = jka->action(jka, NULL);
		}
		jka->tokv = prev_tok;
	}
out:
	if (arr)
		jsmnutil_tokv_free(arr);
	return ret;
}

int do_one_jka_action(struct json_key_action *jka)
{
	char *value = NULL;
	jsmntok_t* val_token = NULL;
	int ret = 0;
	int length = 0;
	char *buf = jka->buf;

	switch(jka->type) {
		case JSMN_STRING:
			val_token = jka->tokv + 1;
			value = pv_json_get_one_str(buf, &val_token);
			if (jka->save)
				do_json_key_action_save(jka, value);

			if (jka->action)
				ret = jka->action(jka, value);
			free(value);
			break;

		case JSMN_ARRAY:
			ret = do_json_key_action_array(jka);
			break;

		case JSMN_OBJECT:
			//create a new buffer.
			length = (jka->tokv + 1)->end - (jka->tokv + 1)->start;
			value = (char*) calloc(1, sizeof(char) * (length + 1));
			if (value) {
				char *orig_buf = NULL;
				snprintf(value, length + 1, "%s",
						buf + (jka->tokv + 1)->start);
				orig_buf = jka->buf;
				jka->buf = value;
				ret = do_json_key_action_object(jka);
				free(value);
				jka->buf = orig_buf;
			}
			break;
		default:
			break;
	}
	return ret;
}

/*
 * check if key is present in keys.
 * returns the key from jsmntok_t **keys that matched.
 */
jsmntok_t* do_lookup_json_key(jsmntok_t **keys, char *json_buf, char *key)
{
	bool found = false;
	jsmntok_t **keys_walker = NULL;

	if (!keys || !key)
		return NULL;
	keys_walker = keys;
	while(*keys_walker) {
		// copy key 
		char *curr_key = NULL;
		int length = 0;

		length = (*keys_walker)->end - (*keys_walker)->start;

		curr_key = (char*) calloc(1, sizeof(char) * (length + 1));
		if (!curr_key) {
			keys_walker++;
			continue;
		}
		snprintf(curr_key, length + 1, "%s",
				json_buf + (*keys_walker)->start);
		if (strncmp(curr_key, key, strlen(key)) == 0)
			found = true;
		free(curr_key);
		if (found)
			break;
		keys_walker++;
	}
	return found ? (*keys_walker) : NULL;
}

int do_action_for_array(struct json_key_action *jka, char *value)
{
	/*
	 * real_jka is an array of other JKA's on which action
	 * needs to be performed.
	 */
	struct json_key_action *real_jka = (struct json_key_action*)jka->opaque;
	int ret = 0;
	jsmntok_t** keys;
	/*
	 * we only handle arrays of objects not nested
	 * arrays.
	 */
	keys = jsmnutil_get_object_keys(jka->buf, jka->tokv);
	if (!keys) {
		pv_log(ERROR, "array cannot be parsed");
		ret = -1;
		goto out;
	}
	while(real_jka->key && !ret) {
		real_jka->tokv = do_lookup_json_key(keys, jka->buf, real_jka->key);
		real_jka->tokc = jka->tokc;
		real_jka->buf = jka->buf;
		if (real_jka->tokv) {
			ret = do_one_jka_action(real_jka);
		}
		real_jka++;
	}
	jsmnutil_tokv_free(keys);
out:
	return ret;
}
