/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#ifndef PV_PARSER_UTILS_H
#define PV_PARSER_UTILS_H

int start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
					jsmntype_t type);
int __start_json_parsing_with_action(char *buf, struct json_key_action *jka_arr,
						jsmntype_t type, 
						jsmntok_t *__tokv, int __tokc);
int do_json_key_action_object(struct json_key_action *jka);
void do_json_key_action_save(struct json_key_action *jka, char *value);
int do_json_key_action_array(struct json_key_action *jka);
int do_one_jka_action(struct json_key_action *jka);
jsmntok_t* do_lookup_json_key(jsmntok_t **keys, char *json_buf, char *key);
int do_action_for_array(struct json_key_action *jka, char *value);

#endif
