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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

static int seeded = 0;

int mkdir_p(const char *dir, mode_t mode)
{
	const char *tmp = dir;
	const char *orig = dir;
	char *makeme;

	do {
		dir = tmp + strspn(tmp, "/");
		tmp = dir + strcspn(dir, "/");
		makeme = strndup(orig, dir - orig);
		if (*makeme) {
			if (mkdir(makeme, mode) && errno != EEXIST) {
				free(makeme);
				return -1;
			}
		}
		free(makeme);
	} while(tmp != dir);

	return 0;
}

void syncdir(char *file)
{
	int fd;
	char *dir;

	if (!file)
		return;

	dir = strdup(file);
	dirname(dir);

	fd = open(dir, O_RDONLY);
	if (fd)
		fsync(fd);

	if (dir)
		free(dir);

	close(fd);
}

char *rand_string(int size)
{
	char set[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK";
	char *str;
	time_t t;

	if (!seeded)
		srand(time(&t));

	str = malloc(sizeof(char) * (size + 1));

	for (int i = 0; i < size; i++) {
		int key = rand() % (sizeof(set) - 1);
		str[i] = set[key];
	}

	// null terminate string
	str[size] = '\0';

	return str;
}

int traverse_token (char *buf, jsmntok_t* tok, int t)
{
	int i;
	int c;
	c=t;
	for (i=0; i < tok[t].size; i++) {
		c = traverse_token (buf, tok, c+1);
	}
	return c;
}

int get_digit_count(int number)
{
	int c = 0;

	while (number) {
		number /= 10;
		c++;
	}
	c++;

	return c;
}

int get_json_key_value_int(char *buf, char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int val = 0;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen (key);
		if (tok[i].type == JSMN_PRIMITIVE
		    && n == m
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			val = atoi(idval);
			free(idval);
			return val;
		} else if (t==1) {
			return val;
		}
	}
	return val;
}

char* get_json_key_value(char *buf, char *key, jsmntok_t* tok, int tokc)
{
	int i;
	int t=-1;

	for(i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen (key);
		if (n == m
		    && tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			return idval;
		} else if (t==1) {
			return NULL;
		}
	}
	return NULL;
}

char* json_array_get_one_str(char *buf, int *n, jsmntok_t **tok)
{
	int c;
	char *value;

	if (*n == 0)
		return NULL;

	c = (*tok)->end - (*tok)->start;
	value = calloc(1, (c+1) * sizeof(char));
	strncpy(value, buf+(*tok)->start, c);
	(*tok)++;
	(*n)--;

	return value;
}

int json_get_key_count(char *buf, char *key, jsmntok_t *tok, int tokc)
{
	int count = 0;

	for (int i=0; i<tokc; i++) {
		int n = tok[i].end - tok[i].start;
		int m = strlen(key);

		if (n == m &&
		    tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			count += 1;
		}
	}

	return count;
}

char *unescape_str_to_ascii(char *buf, char *code, char c)
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
	if (buf)
		free(buf);

	return new;
}

char* skip_prefix(char *str, const char *key)
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
