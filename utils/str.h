/*
 * Copyright (c) 2021-2022 Pantacor Ltd.
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
#include <time.h>

// offers no return value, but prints to vlog. Requires pvlog.
#define SNPRINTF_WTRUNC(buf, size, ...)                                        \
	do {                                                                   \
		int out = snprintf((buf), (size_t)(size), __VA_ARGS__);        \
		if ((int)(size) <= out) {                                      \
			pv_log(WARN, "string %s with size %d truncated to %d", \
			       #buf, out, (int)size);                          \
		}                                                              \
	} while (0)

/*
 * This function returns string s1 if string s2 is an empty string, or
 * if s2 is not found in s1. If s2 is found in s1, the function
 * returns a new null-terminated string whose contents are identical
 * to s1, except that all occurrences of s2 in the original string s1
 * are, in the new string, replaced by the string s3. The caller owns
 * the new string.
 *
 * Strings s1, s2, and s3 must all be null-terminated strings. If any
 * of s1, s2, or s3 are NULL, the function returns NULL, indicating an
 * error condition. If any other error occurs, the function returns
 * NULL.
 *
 * This code is written pedantically, primarily so that asserts can be
 * used liberally. The code could certainly be optimized and/or made
 * less verbose, and I encourage you to do that if you use strstr in
 * your production code, once you're comfortable that it functions as
 * intended. Each assert makes plain an invariant condition that is
 * assumed to be true by the statement(s) that immediately follow the
 * assert.  Some of the asserts are trivially true, as written, but
 * they're included, nonetheless, in case you, in the process of
 * optimizing or adapting the code for your own purposes, make a
 * change that breaks an assumption made downstream by the original
 * code.
 */

char *pv_str_replace_str(const char *s1, const char *s2, const char *s3);
void pv_str_unescape_to_ascii(char *buf, int size);
char *pv_str_replace_char(char *str, int len, char which, char what);
char *pv_str_skip_prefix(char *str, const char *key);
int pv_str_count_list(char **list);
int pv_str_fmt_build(char **str, const char *fmt, ...);

/* prints seconds since beginning of epoch in buf */
size_t epochsecstring(char *buf, size_t len, time_t t);

static inline bool pv_str_startswith(const char *str1, int str1len,
				     const char *str2)
{
	return !strncmp(str1, str2, str1len);
}

static inline bool pv_str_startswith_case(const char *str1, size_t str1len, const char *str2)
{
	return !strncasecmp(str1, str2, str1len);
}

static inline bool pv_str_matches(const char *str1, const char *str2)
{
	int str1len = strlen(str1);
	int str2len = strlen(str2);

	return ((str1len == str2len) && !strncmp(str1, str2, str1len));
}

static inline bool pv_str_matches_len(const char *str1, int str1len,
				  const char *str2, int str2len)
{
	return ((str1len == str2len) && !strncmp(str1, str2, str1len));
}

static inline bool pv_str_matches_len_case(const char *str1, int str1len,
				       const char *str2, int str2len)
{
	return ((str1len == str2len) && !strncasecmp(str1, str2, str1len));
}

static inline bool pv_str_endswith(const char *str1, int str1len,
				   const char *str2, int str2len)
{
	return ((str2len > str1len) &&
		!strncmp(str1, &str2[str2len - str1len], str1len));
}

static inline bool pv_is_sha256_hex_string(const char *value)
{
	bool issha = false;
	if (!value)
		return false;

	if (strlen(value) == 64) {
		const char *v = NULL;
		for (v = value; *v; v++) {
			if ((*v >= '0' && *v <= '9') ||
			    (*v >= 'a' && *v <= 'f') ||
			    (*v >= 'A' && *v <= 'F')) {
				continue;
			}
			break;
		}
		// if we reached end of string, we are a valid sha
		if (!*v) {
			issha = true;
		}
	}
	return issha;
}

#endif /* UTILS_PV_STRING_H_ */
