/*
 * Copyright (c) 2021-2025 Pantacor Ltd.
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

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "str.h"

char *pv_str_replace_char(char *str, int len, char which, char what)
{
	int char_at = 0;

	if (!str)
		return NULL;

	for (char_at = 0; char_at < len; char_at++) {
		if (str[char_at] == which)
			str[char_at] = what;
	}
	return str;
}

void pv_str_unescape_to_ascii(char *buf, int size)
{
	const char unescaped[] = { '"', '\\', 'b', 'f', 'n', 'r', 't' };
	const char replacement[] = { '"', '\\', '\b', '\f', '\n', '\r', '\t' };

	int i = -1;
	int j = 0;

	bool ok = true;
	do {
		ok = true;
		i = -1;
		j = 0;
		while (i < size) {
		next:
			++i;
			if (buf[i] == '\\') {
				for (size_t k = 0; k < sizeof(unescaped); ++k) {
					if (buf[i + 1] == unescaped[k]) {
						buf[j] = replacement[k];
						++i;
						++j;
						ok = false;
						goto next;
					}
				}
			}

			buf[j] = buf[i];
			++j;
		}
	} while (!ok);
	buf[j] = '\0';
}

char *pv_str_unescape_utf8_to_apvii(char *buf, char *code, char c)
{
	char *p = 0;
	char *new_str = 0;
	char *old;
	int pos = 0, replaced = 0;
	char *tmp;

	size_t len = strlen(buf) + strlen(code) + 1;
	tmp = calloc(strlen(buf) + strlen(code) + 1, sizeof(char));

	snprintf(tmp, len, "%s%s", buf, code);

	old = tmp;

	p = strstr(tmp, code);
	while (p) {
		*p = '\0';
		new_str = realloc(new_str, pos + strlen(tmp) + 2);
		snprintf(new_str + pos, strlen(tmp) + 2, "%s", tmp);
		pos = pos + strlen(tmp);
		new_str[pos] = c;
		pos += 1;
		new_str[pos] = '\0';
		replaced += 1;
		tmp = p + strlen(code);
		p = strstr(tmp, code);
	}

	if (new_str && new_str[strlen(new_str) - 1] == c)
		new_str[strlen(new_str) - 1] = '\0';

	if (old)
		free(old);
	if (buf)
		free(buf);

	return new_str;
}

int pv_str_count_list(char **list)
{
	int len = 0;

	while (*list) {
		len++;
		list++;
	}

	return len;
}

int pv_str_fmt_build(char **str, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	int len = vsnprintf(NULL, 0, fmt, args) + 1;
	if (len < 0)
		goto out;

	*str = calloc(len, sizeof(char));
	if (!*str)
		goto out;

	va_end(args);
	va_start(args, fmt);

	len = vsnprintf(*str, len, fmt, args);
	if (len < 0) {
		free(*str);
		*str = NULL;
		goto out;
	}
out:
	va_end(args);
	return len;
}

char *pv_str_skip_prefix(char *str, const char *key)
{
	if (!str || !key)
		return str;
	while (*key) {
		if (*key != *str)
			break;
		key++;
		str++;
	}
	return str;
}

size_t epochsecstring(char *buf, size_t len, time_t t)
{
	struct tm *tmp;
	size_t ret;
	if (!buf)
		return 0;

	tmp = localtime(&t);
	if (tmp == NULL)
		goto exit_error;

	ret = strftime(buf, len, "%s", tmp);

	if (ret == 0 || ret > len)
		goto exit_error;

	return ret;

exit_error:
	strncpy(buf, "TIME_ERROR", len);
	buf[len - 1] = 0;

	return 0;
}
