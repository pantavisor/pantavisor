/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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

#ifndef __PARSER_BUNDLE_H__
#define __PARSER_BUNDLE_H__

#include "pantavisor.h"
#include "platforms.h"
#include "parser.h"

struct json_key_action {
	char *key;
	void **opaque;
	jsmntype_t type;
	bool save; /*Not applicable for array type*/
	/*
	 * Return 0 for success and non 0 for failure.
	 * */
	int (*action)(struct json_key_action *, char *value);
	/*
	 * Use for custom action or when using arrays within arrays.
	 * */
	jsmntok_t *tokv;
	int tokc;
	char *buf;
};

#define ADD_JKA_ENTRY(__key, __type, __opaque, __action, __save)               \
	{                                                                      \
		.key = __key, .type = __type, .opaque = (void *)__opaque,      \
		.action = __action, .save = __save                             \
	}

#define ADD_JKA_NULL_ENTRY()                                                   \
	{                                                                      \
		.key = NULL, .type = JSMN_UNDEFINED, .opaque = (void **)NULL,  \
		.action = NULL, .save = false                                  \
	}

struct platform_bundle {
	struct pv_state *s;
	struct pv_platform **platform;
};
int start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
				   jsmntype_t type);

int __start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
				     jsmntype_t type, jsmntok_t *__tokv,
				     int __tokc);
#endif /* __PARSER_BUNDLE_H__ */
