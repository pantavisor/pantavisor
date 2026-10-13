/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#include "ubootab_header.h"

#define KEY_REV "fit_rev="
#define KEY_SIZE "fit_size="

int ubootab_header_format(char *buf, const char *rev, long long fit_size)
{
	int n;

	// a newline would end the value early, '=' or a space confuses env import
	if (!rev || !*rev || strpbrk(rev, "\n\r= ") ||
	    strlen(rev) >= UBOOTAB_REV_MAX || fit_size < 0)
		return -1;

	memset(buf, 0, UBOOTAB_HEADER_SIZE);
	n = snprintf(buf, UBOOTAB_HEADER_SIZE, KEY_REV "%s\n" KEY_SIZE "%lld\n",
		     rev, fit_size);

	return n < 0 || n >= UBOOTAB_HEADER_SIZE ? -1 : 0;
}

// copy the value of a "key=value" line into a NUL terminated string
static int line_value(const char *line, size_t len, const char *key, char *out,
		      size_t out_size)
{
	size_t klen = strlen(key);

	if (len < klen || strncmp(line, key, klen))
		return -1;
	len -= klen;
	if (len >= out_size)
		return -1;
	memcpy(out, line + klen, len);
	out[len] = '\0';

	return 0;
}

int ubootab_header_parse(const char *buf, size_t len,
			 struct ubootab_header *hdr)
{
	const char *end = memchr(buf, '\0', len);
	size_t text = end ? (size_t)(end - buf) : len;
	int found = -1;

	hdr->rev[0] = '\0';
	hdr->fit_size = -1;

	for (size_t pos = 0; pos < text;) {
		const char *nl = memchr(buf + pos, '\n', text - pos);
		size_t n = nl ? (size_t)(nl - buf) - pos : text - pos;
		char num[32];

		if (!line_value(buf + pos, n, KEY_REV, hdr->rev,
				sizeof(hdr->rev)) &&
		    *hdr->rev)
			found = 0;
		else if (!line_value(buf + pos, n, KEY_SIZE, num, sizeof(num)))
			hdr->fit_size = strtoll(num, NULL, 10);
		pos += n + 1;
	}

	return found;
}

int ubootab_header_has_rev(const struct ubootab_header *hdr, const char *rev)
{
	return hdr && rev && !strcmp(hdr->rev, rev);
}

int ubootab_pick_inactive(const struct ubootab_header *a,
			  const struct ubootab_header *b, const char *pv_rev)
{
	if (ubootab_header_has_rev(b, pv_rev) &&
	    !ubootab_header_has_rev(a, pv_rev))
		return 0;

	return 1;
}
