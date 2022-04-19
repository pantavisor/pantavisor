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

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include "str.h"

char *pv_str_replace_char(char *str, int len, char which, char what)
{
	int char_at = 0;

	if (!str)
		return NULL;

	for (char_at = 0; char_at < len; char_at++){
		if (str[char_at] == which)
			str[char_at] = what;
	}
	return str;
}

char *pv_str_unescape_to_ascii(char *buf, char *code, char c)
{
	char *p = 0;
	char *new = 0;
	char *old;
	int pos = 0, replaced = 0;
	char *tmp;

	tmp = malloc(strlen(buf) + strlen(code) + 1);
	strcpy(tmp, buf);
	strcat(tmp, code);
	old = tmp;

	p = strstr(tmp, code);
	while (p) {
		*p = '\0';
		new = realloc(new, pos + strlen(tmp) + 2);
		strcpy(new+pos, tmp);
		pos = pos + strlen(tmp);
		new[pos] = c;
		pos += 1;
		new[pos] = '\0';
		replaced += 1;
		tmp = p+strlen(code);
		p = strstr(tmp, code);
	}

	if (new[strlen(new)-1] == c)
		new[strlen(new)-1] = '\0';

	if (old)
		free(old);

	return new;
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
