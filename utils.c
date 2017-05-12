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
		if (tok[i].type == JSMN_PRIMITIVE
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
			printf ("ERROR: json does not have 'key' string\n");
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
		if (n && tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			t=1;
		} else if (t==1) {
			char *idval = malloc(n+1);
			idval[n] = 0;
			strncpy(idval, buf + tok[i].start, n);
			return idval;
		} else if (t==1) {
			printf ("ERROR: json does not have 'key' string\n");
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
		if (tok[i].type == JSMN_STRING
		    && !strncmp(buf + tok[i].start, key, n)) {
			count += 1;
		}
	}

	return count;
}
