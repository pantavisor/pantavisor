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

#include <string.h>
#include <stdlib.h>
#include <mbedtls/base64.h>

#include "base64.h"

static char* pv_base64_padding_multi4(char *str)
{
	int old_len = strlen(str);
	int padding = old_len % 4;
	int new_len = old_len + padding;
	str = realloc(str, new_len);
	for (int i = 1; i <= padding; i++) {
		str[new_len-i] = '=';
	}
	return str;
}

int pv_base64_url_decode(const char *scr, char **dst, size_t *olen)
{
	size_t len, ilen;
	char *itmp = strdup(scr);
	*olen = 0;

	if (*dst)
		goto err;

	itmp = pv_base64_padding_multi4(itmp);

	ilen = strlen(itmp);
	len = ((4 * ilen / 3) + 3) & ~3;

	for (size_t i = 0; i < ilen; i++) {
		if (itmp[i] == '_')
			itmp[i] = '/';
		if (itmp[i] == '-')
			itmp[i] = '+';
	}

	*dst = calloc(1, len);
	if (!*dst)
		goto err;

	if (mbedtls_base64_decode((unsigned char*)*dst, len, olen, (unsigned char*)itmp, ilen))
		goto err;

	return 0;
err:
	if (*dst)
		free(*dst);
	return -1;
}

int pv_base64_url_encode(const char *scr, char **dst, size_t *olen)
{
	size_t len, ilen;
	*olen = 0;

	if (*dst)
		goto err;

	ilen = strlen(scr);
	len = ilen * 4 / 3 + 4;

	*dst = calloc(1, len);
	if (!*dst)
		goto err;

	if (mbedtls_base64_encode((unsigned char*)*dst, len, olen, (unsigned char*)scr, ilen))
		goto err;

	for (size_t i = 0; i < len; i++) {
		if ((*dst)[i] == '/')
			(*dst)[i] = '_';
		if ((*dst)[i] == '+')
			(*dst)[i] = '-';
	}

	return 0;
err:
	if(*dst)
		free(*dst);
	return -1;
}
