/*
 * strrep.c - C substring replacement.
 *
 * Written in 2011 by Drew Hess <dhess-src@bothan.net>.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to
 * the public domain worldwide. This software is distributed without
 * any warranty.
 *
 * For the full statement of the dedication, see the Creative Commons
 * CC0 Public Domain Dedication at
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "str.h"

/*
 * This file includes a main() function so that the file can be
 * compiled into an executable, in order to run some simple test cases
 * on the included strrep() function. If you want to use strrep in
 * your own project, make sure you cut or comment out the main()
 * function below.
 */
 
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

char * pv_str_replace_str(const char *s1, const char *s2, const char *s3)
{
	if (!s1 || !s2 || !s3)
		return 0;
	size_t s1_len = strlen(s1);
	if (!s1_len)
		return (char *)strdup(s1);
	size_t s2_len = strlen(s2);
	if (!s2_len)
		return (char *)strdup(s1);

	/*
	 * Two-pass approach: figure out how much space to allocate for
	 * the new string, pre-allocate it, then perform replacement(s).
	 */

	size_t count = 0;
	const char *p = s1;
	assert(s2_len); /* otherwise, strstr(s1,s2) will return s1. */
	do {
		p = strstr(p, s2);
		if (p) {
			p += s2_len;
			++count;
		}
	} while (p);

	if (!count)
		return (char *)strdup(s1);

	/*
	 * The following size arithmetic is extremely cautious, to guard
	 * against size_t overflows.
	 */
	assert(s1_len >= count * s2_len);
	assert(count);
	size_t s1_without_s2_len = s1_len - count * s2_len;
	size_t s3_len = strlen(s3);
	size_t s1_with_s3_len = s1_without_s2_len + count * s3_len;
	if (s3_len &&
	    ((s1_with_s3_len <= s1_without_s2_len) || (s1_with_s3_len + 1 == 0)))
		/* Overflow. */
		return 0;
    
	char *s1_with_s3 = (char *)malloc(s1_with_s3_len + 1); /* w/ terminator */
	if (!s1_with_s3)
		/* ENOMEM, but no good way to signal it. */
		return 0;
    
	char *dst = s1_with_s3;
	const char *start_substr = s1;
	size_t i;
	for (i = 0; i != count; ++i) {
		const char *end_substr = strstr(start_substr, s2);
		assert(end_substr);
		size_t substr_len = end_substr - start_substr;
		memcpy(dst, start_substr, substr_len);
		dst += substr_len;
		memcpy(dst, s3, s3_len);
		dst += s3_len;
		start_substr = end_substr + s2_len;
	}

	/* copy remainder of s1, including trailing '\0' */
	size_t remains = s1_len - (start_substr - s1) + 1;
	assert(dst + remains == s1_with_s3 + s1_with_s3_len + 1);
	memcpy(dst, start_substr, remains);
	assert(strlen(s1_with_s3) == s1_with_s3_len);
	return s1_with_s3;
}
