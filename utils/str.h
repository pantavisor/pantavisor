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

#ifndef UTILS_PV_STRING_H_
#define UTILS_PV_STRING_H_

#include <string.h>
#include <stdbool.h>

char *pv_str_unescape_to_ascii(char *buf, char *code, char c);
char *pv_str_replace_char(char *str, int len, char which, char what);
char *pv_str_skip_prefix(char *str, const char *key);

static inline bool pv_str_startswith(const char* str1, int str1len, const char* str2)
{
	return !strncmp(str1, str2, str1len);
}

static inline bool pv_str_matches(const char* str1, int str1len, const char* str2, int str2len)
{
	return ((str1len == str2len) && !strncmp(str1, str2, str1len));
}

static inline bool pv_str_endswith(const char* str1, int str1len, const char* str2, int str2len)
{
	return ((str2len > str1len) && !strncmp(str1, &str2[str2len - str1len], str1len));
}

#endif /* UTILS_PV_STRING_H_ */
