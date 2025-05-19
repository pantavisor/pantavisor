/*
 * Copyright (c) 2021-2023 Pantacor Ltd.
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

#define MODULE_NAME "base64"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static char *pv_base64_add_padding_multi4(char *str)
{
	int old_len = strlen(str), padding = 0, new_len;
	int i;
	switch (old_len % 4) {
	case 0:
		return str;
	case 2:
		padding = 2;
		break;
	case 3:
		padding = 1;
		break;
	default:
		pv_log(WARN, "wrong base64 encoded input");
		return str;
	}

	new_len = old_len + padding;
	str = realloc(str, new_len + 1);
	for (i = old_len; i < new_len; i++) {
		str[i] = '=';
	}
	str[i] = 0;

	return str;
}

static char *pv_base64_remove_padding_multi4(char *str)
{
	int len = strlen(str);
	for (int i = 0; i < len; i++) {
		if (str[i] == '=') {
			str[i] = '\0';
			break;
		}
	}

	return str;
}

int pv_base64_decode(const char *src, char **dst, size_t *olen)
{
	int res;
	size_t len, ilen;

	if (*dst)
		goto err;

	ilen = strlen(src);
	len = ((4 * ilen / 3) + 3) & ~3;

	if (len < 1)
		goto err;

	*dst = calloc(len, sizeof(char));
	if (!*dst)
		goto err;

	res = mbedtls_base64_decode((unsigned char *)*dst, len, olen,
				    (unsigned char *)src, ilen);
	if (res) {
		pv_log(ERROR, "cannot decode base64 with code %d '%s'", res,
		       src);
		goto err;
	}

	return 0;
err:
	if (*dst) {
		free(*dst);
		*dst = NULL;
	}
	return -1;
}

int pv_base64_url_decode(const char *src, char **dst, size_t *olen)
{
	size_t ilen;
	char *itmp = strdup(src);
	*olen = 0;

	if (*dst)
		goto err;

	itmp = pv_base64_add_padding_multi4(itmp);

	ilen = strlen(itmp);

	for (size_t i = 0; i < ilen; i++) {
		if (itmp[i] == '_')
			itmp[i] = '/';
		if (itmp[i] == '-')
			itmp[i] = '+';
	}

	if (pv_base64_decode(itmp, dst, olen))
		goto err;

	if (itmp)
		free(itmp);

	return 0;
err:
	if (itmp)
		free(itmp);
	if (*dst) {
		free(*dst);
		*dst = NULL;
	}
	return -1;
}

int pv_base64_url_encode(const char *src, char **dst, size_t *olen)
{
	int res;
	size_t len, ilen;
	*olen = 0;

	if (*dst)
		goto err;

	ilen = strlen(src);
	len = ilen * 4 / 3 + 4;

	*dst = calloc(len, sizeof(char));
	if (!*dst)
		goto err;

	res = mbedtls_base64_encode((unsigned char *)*dst, len, olen,
				    (unsigned char *)src, ilen);
	if (res) {
		pv_log(ERROR, "cannot encode base64 with code %d", res);
		goto err;
	}

	for (size_t i = 0; i < len; i++) {
		if ((*dst)[i] == '/')
			(*dst)[i] = '_';
		if ((*dst)[i] == '+')
			(*dst)[i] = '-';
	}

	*dst = pv_base64_remove_padding_multi4(*dst);

	return 0;
err:
	if (*dst) {
		free(*dst);
		*dst = NULL;
	}
	return -1;
}
