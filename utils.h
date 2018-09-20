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
#ifndef PV_UTILS_H
#define PV_UTILS_H

#include <sys/types.h>

#include <jsmn/jsmnutil.h>

int mkdir_p(const char *dir, mode_t mode);

void syncdir(char *dir);
char *rand_string(int size);
int traverse_token (char *buf, jsmntok_t* tok, int t);
int get_digit_count(int number);
int get_json_key_value_int(char *buf, char *key, jsmntok_t* tok, int tokc);
char* get_json_key_value(char *buf, char *key, jsmntok_t* tok, int tokc);
char* json_array_get_one_str(char *buf, int *n, jsmntok_t **tok);
int json_get_key_count(char *buf, char *key, jsmntok_t *tok, int tokc);
char *unescape_str_to_ascii(char *buf, char *code, char c);

#endif
