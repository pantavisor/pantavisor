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

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "config_parser.h"
#include "file.h"

#define MODULE_NAME             "config_parser"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

struct config_item {
	char *key;
	char *value;
	struct config_item *next;
	struct dl_list list;
};

static struct config_item* _config_get_by_key(struct dl_list *list, char *key)
{
	struct config_item *curr = NULL, *tmp;
	if (key == NULL || dl_list_empty(list))
		return NULL;
	
	dl_list_for_each_safe(curr, tmp, list,
			struct config_item, list) {
		if (strcmp(curr->key, key) == 0)
			return curr;
	}
	// Value not found
	return NULL;
}

static struct config_item* _config_add_item(struct dl_list *list,
						char *key, char *value)
{
	struct config_item *this;

	// Check if it already exists in config and change value instead
	this = _config_get_by_key(list, key);
	if (this) {
		if (this->value)
			free(this->value);

		this->value = strdup(value);
		return this;
	}

	// New item
	this = (struct config_item *) malloc(sizeof(struct config_item));

	if (!this) {
		pv_log(ERROR, "unable to allocate config item");
		goto out;
	}

	// Check empty key
	if (strcmp(key, "") == 0) {
		goto out;
	}
	// Set key
	this->key = strdup(key);

	// Check for empty value
	if (value)
		this->value = strdup(value);
	else
		this->value = strdup(""); // Empty value
	if (this->key && this->value)
		dl_list_add_tail(list, &this->list);
	else {
		goto out;
	}
	return this;
out:
	if (this && this->key)
		free(this->key);
	if (this && this->value)
		free(this->value);
	free(this);
	return NULL;
}

static struct config_item* _config_replace_item(struct dl_list *list,
						char *key, char *value)
{
	struct config_item *curr = NULL;

	if (key == NULL || dl_list_empty(list))
		return NULL;

	curr = _config_get_by_key(list, key);
	if (curr) {
		char *tmp_val = strdup(value);

		if (tmp_val) {
			free(curr->value);
			curr->value = tmp_val;
		}
		return curr;
	}
	// not found? add it
	return _config_add_item(list, key, value);
}

int config_parse_cmdline(struct dl_list *list, char *hint)
{
	int fd, bytes;
	char *buf = NULL, *k = NULL, *nl = NULL;
	char *ptr_out = NULL, *ptr_in = NULL;
	char *token = NULL, *key = NULL, *value = NULL;

	// Get current step revision from cmdline
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -1;

	buf = calloc(1, sizeof(char) * (1024 + 1));
	if (!buf) {
		close(fd);
		return -1;
	}

	bytes = pv_file_read_nointr(fd, buf, sizeof(char)*1024);
	if (!bytes) {
		close(fd);
		return -1;
	}
	close(fd);
	token = strtok_r(buf, " ", &ptr_out);
	while (token) {
		if (strncmp(hint, token, strlen(hint)) == 0) {
			k = token + strlen(hint);
			key = strtok_r(k, "=", &ptr_in);
			value = strtok_r(NULL, "\0", &ptr_in);
			/*
			 * for things like XYZ= there would be nothing
			 * in the value as strtok returns only non-empty
			 * strings.
			 * */
			if (!value)
				value = ""; /*We keep the key but give it an empty value*/
			nl = strchr(value, '\n');
			if (nl) /* get rid of newline at end */
				*nl = '\0';
			_config_replace_item(list, key, value);
		}
		token = strtok_r(NULL, " ", &ptr_out);
	}
	free(buf);

	return 0;
}

int load_key_value_file(const char *path, struct dl_list *list)
{
	FILE *fp;
	char *buff = NULL, *__real_key = NULL;
	struct stat st;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	stat(path, &st);
	buff = calloc(1, st.st_size);
	if (!buff)
		goto out;

	while (fgets(buff, st.st_size+1, fp)) {
		// Remove newline from value (hacky)
		buff[strlen(buff)-1] = '\0';
		char *key = strstr(buff, "=");
		if (key) {
			char *value = key + 1;
			__real_key = (char*) calloc(1, key - buff + 1);
			if (__real_key) {
				sprintf(__real_key, "%.*s", (int)(key - buff), buff);
				_config_add_item(list, __real_key, value);
				free(__real_key);
			}
		}
	}
	free(buff);
out:
	fclose(fp);

	return 0;
}

char* config_get_value(struct dl_list *list, char *key)
{
	struct config_item *curr = _config_get_by_key(list, key);

	if (curr)
		return curr->value;
	// Value not found
	return NULL;
}

void config_iterate_items(struct dl_list *list, int (*action)(char *key, char *value, void *opaque), void *opaque)
{
	struct config_item *curr = NULL, *tmp;
	
	if (dl_list_empty(list))
		return;
	if (!action)
		return;
	dl_list_for_each_safe(curr, tmp, list,
			struct config_item, list) {
		if (action(curr->key, curr->value, opaque))
			break;
	}
}

void config_clear_items(struct dl_list *list)
{
	struct config_item *curr = NULL, *tmp;

	if (dl_list_empty(list))
		return;
	dl_list_for_each_safe(curr, tmp, list,
			struct config_item, list) {
		dl_list_del(&curr->list);
		free(curr->key);
		free(curr->value);
		free(curr);
	}
}
