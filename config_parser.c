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
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "config_parser.h"
#include "utils/str.h"
#include "utils/fs.h"

#define MODULE_NAME "config_parser"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct config_item {
	char *key;
	char *value;
	struct config_item *next;
	struct dl_list list;
};

static struct config_item *_config_get_by_key(struct dl_list *list, char *key)
{
	struct config_item *curr = NULL, *tmp;
	if (key == NULL || dl_list_empty(list))
		return NULL;

	dl_list_for_each_safe(curr, tmp, list, struct config_item, list)
	{
		if (pv_str_matches_case(curr->key, strlen(curr->key), key,
					strlen(key)))
			return curr;
	}
	// Value not found
	return NULL;
}

static struct config_item *_config_add_item(struct dl_list *list, char *key,
					    char *value)
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
	this = calloc(1, sizeof(struct config_item));

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

int config_parse_cmdline(struct dl_list *list, char *hint)
{
	struct pantavisor *pv = pv_get_instance();
	char *buf = NULL, *k = NULL, *nl = NULL;
	char *ptr_out = NULL, *ptr_in = NULL;
	char *token = NULL, *key = NULL, *value = NULL;

	buf = strdup(pv->cmdline);
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
			_config_add_item(list, key, value);
		}
		token = strtok_r(NULL, " ", &ptr_out);
	}
	free(buf);

	return 0;
}

extern char **environ;

int config_parse_env(struct dl_list *list)
{
	char **envs = environ;
	char *env, *ctx, *key, *value, *pv_prefix = "PV_", *ph_prefix = "PH_";
	size_t envlen, pv_prefixlen = strlen(pv_prefix),
		       ph_prefixlen = strlen(ph_prefix);
	;

	while (*envs) {
		env = strdup(*envs);
		envlen = strlen(env);

		if (envlen <= pv_prefixlen)
			goto next;

		if (!pv_str_startswith_case(pv_prefix, pv_prefixlen, env) &&
		    !pv_str_startswith_case(ph_prefix, ph_prefixlen, env))
			goto next;

		key = strtok_r(env, "=", &ctx);
		value = strtok_r(NULL, "\0", &ctx);

		// set empty string if no value
		if (!value)
			value = "";

		_config_add_item(list, key, value);
	next:
		free(env);
		envs++;
	}

	return 0;
}

int load_key_value_file(const char *path, struct dl_list *list)
{
	FILE *fp;
	int size = -1;
	char *buff = NULL, *__real_key = NULL;
	struct stat st;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	stat(path, &st);
	buff = calloc(st.st_size, sizeof(char));
	if (!buff)
		goto out;

	while (fgets(buff, st.st_size + 1, fp)) {
		// Remove newline from value (hacky)
		int len = strlen(buff);
		if (len > 0 && isspace((unsigned char)buff[len - 1]))
			buff[strlen(buff) - 1] = '\0';

		char *key = strstr(buff, "=");
		if (key) {
			char *value = key + 1;
			size = key - buff + 1;
			__real_key = calloc(size, sizeof(char));
			if (__real_key) {
				SNPRINTF_WTRUNC(__real_key, size, "%.*s",
						(int)(key - buff), buff);
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

char *config_get_value(struct dl_list *list, char *key)
{
	struct config_item *curr = _config_get_by_key(list, key);

	if (curr)
		return curr->value;
	// Value not found
	return NULL;
}

void config_iterate_items(struct dl_list *list,
			  int (*action)(const char *key, const char *value,
					void *opaque),
			  void *opaque)
{
	struct config_item *curr = NULL, *tmp;

	if (dl_list_empty(list))
		return;
	if (!action)
		return;
	dl_list_for_each_safe(curr, tmp, list, struct config_item, list)
	{
		if (action(curr->key, curr->value, opaque))
			break;
	}
}

void config_iterate_items_prefix(struct dl_list *list,
				 int (*action)(const char *key,
					       const char *value, void *opaque),
				 char *prefix, void *opaque)
{
	struct config_item *curr = NULL, *tmp;

	if (dl_list_empty(list))
		return;
	if (!action)
		return;

	int prefix_size = -1;
	if (prefix)
		prefix_size = strlen(prefix);

	dl_list_for_each_safe(curr, tmp, list, struct config_item, list)
	{
		if (prefix_size == -1 ||
		    !strncmp(curr->key, prefix, prefix_size))
			if (action(curr->key, curr->value, opaque))
				break;
	}
}

void config_clear_items(struct dl_list *list)
{
	struct config_item *curr = NULL, *tmp;

	if (dl_list_empty(list))
		return;
	dl_list_for_each_safe(curr, tmp, list, struct config_item, list)
	{
		dl_list_del(&curr->list);
		free(curr->key);
		free(curr->value);
		free(curr);
	}
}

static char *_parse_legacy_sysctl_key(const char *key)
{
	const char *start = key + strlen("sysctl");
	char *path =
		calloc(strlen("/proc/sys") + strlen(start) + 1, sizeof(char));
	if (!path)
		return NULL;

	sprintf(path, "%s", "/proc/sys");

	char *p = path + strlen("/proc/sys");

	for (int i = 0; i < (int)strlen(start); ++i)
		p[i] = start[i] == '.' ? '/' : start[i];

	return path;
}

static char *_parse_sysctl_key(const char *key)
{
	const char *base = "/proc/sys/";
	size_t baselen = strlen(base);

	const char *k = key + strlen("PV_SYSCTL_");

	char *path = calloc(baselen + strlen(k) + 1, sizeof(char));
	if (!path)
		return NULL;

	sprintf(path, "%s%s", base, k);

	char *p = path + baselen;
	while (*p) {
		if (*p == '_') {
			// temporary \0 to evaluate if it is a dir
			*p = '\0';
			if (pv_fs_path_is_directory(path))
				*p = '/';
			else
				*p = '_';
		} else
			*p = tolower(*p);
		p++;
	}

	return path;
}

char *pv_config_parser_sysctl_key(const char *key)
{
	size_t keylen = strlen(key);

	const char *lprefix = "sysctl";
	size_t lprefixlen = strlen(lprefix);
	if ((keylen > lprefixlen) &&
	    pv_str_startswith(lprefix, lprefixlen, key))
		return _parse_legacy_sysctl_key(key);

	const char *prefix = "PV_SYSCTL_";
	size_t prefixlen = strlen(prefix);
	if ((keylen > prefixlen) &&
	    pv_str_startswith_case(prefix, prefixlen, key))
		return _parse_sysctl_key(key);

	return NULL;
}
