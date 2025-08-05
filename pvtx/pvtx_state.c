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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pvtx_state.h"
#include "pvtx_jsmn_utils.h"
#include "utils/fs.h"
#include "pvtx_utils/base64.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/limits.h>

#define PVTX_STATE_EMPTY "{\"#spec\": \"pantavisor-service-system@1\"}"
#define PVTX_STATE_SIGS_STR "_sigs/"

struct pv_pvtx_state_data {
	bool has_sig;
	char **names;
	int names_len;
	char **sigs;
	char **sigs_data;
	int sigs_len;
	char *data;
	size_t data_len;
	jsmntok_t *tkn;
	int tkn_len;
};

struct pv_pvtx_state {
	struct pv_pvtx_state_data **std;
	int len;
	int cap;
};

static bool is_signature(const char *part)
{
	return !strncmp(part, PVTX_STATE_SIGS_STR, strlen(PVTX_STATE_SIGS_STR));
}

static const char *token_to_str(struct pv_pvtx_state_data *std, int idx,
				int *size)
{
	if (!std)
		return NULL;

	if (size)
		*size = std->tkn[idx].end - std->tkn[idx].start;

	return std->data + std->tkn[idx].start;
}

void pvtx_state_data_free(struct pv_pvtx_state_data *std)
{
	if (!std)
		return;
	if (std->data)
		free(std->data);
	if (std->tkn)
		free(std->tkn);
	if (std->names) {
		for (int i = 0; i < std->names_len; i++) {
			if (std->names[i])
				free(std->names[i]);
		}
		free(std->names);
	}

	free(std);
}

static int search_tkn(struct pv_pvtx_state_data *std, const char *name,
		      int from)
{
	if (from >= std->tkn_len)
		return -1;

	for (int i = from; i < std->tkn_len; ++i) {
		const char *str = token_to_str(std, i, NULL);
		if (!strncmp(str, name, strlen(name)))
			return i;
	}
	return -1;
}

static char **get_names_from_state(struct pv_pvtx_state_data *std, int *nlen)
{
	char **names = NULL;
	int names_len = 0;
	int idx = 0;
	while ((idx = search_tkn(std, "name", idx)) != -1) {
		names_len++;
		char **tmp = realloc(names, sizeof(char *) * names_len);
		if (!tmp)
			goto err;

		names = tmp;
		++idx;

		int len = 0;
		const char *ptr = token_to_str(std, idx, &len);

		names[names_len - 1] = calloc(len + 1, sizeof(char));
		if (!names[names_len - 1])
			goto err;

		memcpy(names[names_len - 1], ptr, len);
	}
	*nlen = names_len;
	return names;

err:
	if (names) {
		for (int i = 0; i < names_len; i++) {
			if (names[i])
				free(names[i]);
		}
		free(names);
	}
	*nlen = 0;
	return NULL;
}

static int set_signatures(struct pv_pvtx_state_data *std, char ***sigsx,
			  char ***sigs_datax)
{
	char **sigs = NULL;
	char **sigs_data = NULL;
	int sigs_len = 0;
	int sigs_data_len = 0;
	int idx = 0;

	while ((idx = search_tkn(std, PVTX_STATE_SIGS_STR, idx)) != -1) {
		int len = 0;
		const char *tok_str = token_to_str(std, idx, &len);

		char *ptr = calloc(len + 1, sizeof(char));
		if (!ptr)
			goto err;

		memcpy(ptr, tok_str, len);

		char **tmp = realloc(sigs, sizeof(char *) * sigs_len + 1);
		if (!tmp) {
			free(ptr);
			goto err;
		}

		sigs = tmp;
		sigs[sigs_len] = ptr;
		sigs_len++;
		++idx;

		char *data = NULL;
		int prot_idx = search_tkn(std, "protected", idx);
		if (prot_idx < 0) {
			goto set_data;
		}

		// check if match is inside of the current signature, if so,
		// we will get the unserialized data from the signature
		if (prot_idx > idx + 7) {
			goto set_data;
		}

		int prot_data = prot_idx + 1;

		jsmntok_t *t = &std->tkn[prot_data];
		size_t dec_len = 0;

		free(data);
		data = (char *)base64_url_decode(std->data + t->start,
						 t->end - t->start, &dec_len);
	set_data:
		tmp = realloc(sigs_data, sizeof(char *) * sigs_data_len + 1);
		if (!tmp)
			goto err;

		sigs_data = tmp;
		sigs_data[sigs_data_len] = data;
		sigs_data_len++;
	}
	*sigsx = sigs;
	*sigs_datax = sigs_data;
	// ssigs_len = sigs_len;
	return sigs_len;
err:
	if (sigs) {
		for (int i = 0; i < sigs_len; i++) {
			if (sigs[i])
				free(sigs[i]);
		}
		free(sigs);
	}
	return -1;
}

static int state_parse(struct pv_pvtx_state_data *std, const char *str,
		       size_t len)
{
	std->tkn = pv_pvtx_jsmn_parse_data(str, len, &std->tkn_len);
	if (!std->tkn)
		return -1;

	int idx_key = search_tkn(std, "#spec", 0);
	if (idx_key == -1)
		return -1;

	int idx_val = idx_key + 1;

	// this is to avoid to write them when pv_pvtx_state_to_str() is called
	std->tkn[idx_key].type = JSMN_UNDEFINED;
	std->tkn[idx_val].type = JSMN_UNDEFINED;

	int spec_len = 0;
	const char *spec = token_to_str(std, idx_val, &spec_len);

	if (strncmp(spec, PV_PVTX_STATE_CURRENT_SPEC, spec_len))
		return -1;

	std->names = get_names_from_state(std, &std->names_len);
	std->has_sig = search_tkn(std, PVTX_STATE_SIGS_STR, 0) > -1;

	std->sigs_len = set_signatures(std, &std->sigs, &std->sigs_data);

	return 0;
}

static struct pv_pvtx_state_data *pvtx_state_data_new(const char *str,
						      size_t len)
{
	if (!str)
		return NULL;

	struct pv_pvtx_state_data *std =
		calloc(1, sizeof(struct pv_pvtx_state_data));
	if (!std)
		return NULL;

	std->data = calloc(len + 1, sizeof(char));
	if (!std->data)
		goto err;

	memcpy(std->data, str, len);

	std->data_len = len;

	if (state_parse(std, str, len) != 0)
		goto err;

	return std;

err:
	pvtx_state_data_free(std);
	return NULL;
}

void pv_pvtx_state_free(struct pv_pvtx_state *st)
{
	if (!st)
		return;
	if (st->std) {
		for (int i = 0; i < st->len; i++)
			pvtx_state_data_free(st->std[i]);

		free(st->std);
	}

	free(st);
}

struct pv_pvtx_state *pv_pvtx_state_from_file(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	struct stat st = { 0 };
	if (fstat(fd, &st) != 0) {
		close(fd);
		return NULL;
	}

	// minimum possible json is [] or {}
	if (st.st_size < 2) {
		close(fd);
		return NULL;
	}

	char *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);

	if (!data)
		return NULL;

	struct pv_pvtx_state *state = pv_pvtx_state_from_str(data, st.st_size);
	munmap(data, st.st_size);

	return state;
}

struct pv_pvtx_state *pv_pvtx_state_from_str(const char *str, size_t len)
{
	struct pv_pvtx_state *st = calloc(1, sizeof(struct pv_pvtx_state));
	if (!st)
		return NULL;

	if (!str)
		goto err;

	struct pv_pvtx_state_data *std = pvtx_state_data_new(str, len);
	if (!std)
		goto err;

	st->std = calloc(1, sizeof(struct pv_pvtx_state_data *));
	if (!st->std)
		goto err;

	st->std[0] = std;
	st->len = 1;
	st->cap = 1;

	return st;

err:
	pvtx_state_data_free(std);
	pv_pvtx_state_free(st);
	return NULL;
}

int pv_pvtx_state_alloc(struct pv_pvtx_state *st, int cap)
{
	if (cap < st->cap)
		return -1;

	struct pv_pvtx_state_data **tmp =
		realloc(st->std, sizeof(struct pv_pvtx_state_data *) * cap);
	if (!tmp)
		return -1;

	st->std = tmp;
	st->cap = cap;

	return 0;
}

static int search_state_data(struct pv_pvtx_state *st, const char *name)
{
	for (int i = 0; i < st->len; i++) {
		struct pv_pvtx_state_data *std = st->std[i];

		for (int j = 0; j < std->names_len; j++) {
			char *n = std->names[j];
			if (!strncmp(n, name, strlen(n)))
				return i;
		}
	}
	return -1;
}

int pv_pvtx_state_add(struct pv_pvtx_state *dst, struct pv_pvtx_state *src)
{
	for (int i = 0; i < src->len; i++) {
		struct pv_pvtx_state_data *std = src->std[i];
		for (int j = 0; j < std->names_len; j++) {
			pv_pvtx_state_remove(dst, std->names[j]);
		}
	}

	if ((dst->cap - dst->len) < src->len) {
		int err = pv_pvtx_state_alloc(dst, dst->cap + src->len);
		if (err)
			return -1;
	}

	for (int i = 0; i < src->len; i++) {
		dst->std[dst->len] = src->std[i];
		dst->len++;

		src->std[i] = NULL;
		src->len--;
	}
	return 0;
}

static void remove_members(struct pv_pvtx_state_data *std, const char *exp)
{
	int i = 1;
	int no_top = 0;

	for (int i = 1; i < std->tkn_len; ++i) {
		if ((std->tkn[i].type != JSMN_STRING &&
		     std->tkn[i].type != JSMN_UNDEFINED) ||
		    no_top) {
			no_top--;
			goto next;
		}

		if (!strncmp(std->data + std->tkn[i].start, exp, strlen(exp)))
			std->tkn[i].type = JSMN_UNDEFINED;

	next:
		no_top += std->tkn[i].size;
	}
}

static int remove_part(struct pv_pvtx_state *st, const char *part)
{
	char exp[PATH_MAX] = { 0 };
	memccpy(exp, part, '\0', PATH_MAX);

	char name[NAME_MAX] = { 0 };
	if (is_signature(part)) {
		char ext[NAME_MAX] = { 0 };
		pv_fs_extension(part, ext);
		size_t sig_len = strlen(PVTX_STATE_SIGS_STR);
		memcpy(name, part + sig_len,
		       strlen(part) - sig_len - strlen(ext));
	} else {
		if (strchr(part, '/'))
			pv_fs_dirname(exp, name);
		else
			memccpy(name, exp, '\0', NAME_MAX);
	}

	int index = search_state_data(st, name);
	if (index < 0) {
		for (int i = 0; i < st->len; i++)
			remove_members(st->std[i], exp);
	} else {
		remove_members(st->std[index], exp);
	}

	return 0;
}

static bool has_more_signatories(struct pv_pvtx_state *st, const char *part)
{
	int count = 0;
	for (int i = 0; i < st->len; i++) {
		struct pv_pvtx_state_data *std = st->std[i];
		for (int j = 0; j < std->sigs_len; j++) {
			if (!strstr(std->sigs_data[j], part))
				continue;
			count++;
			if (count > 1) {
				return true;
			}
		}
	}
	return false;
}

static int remove_signed(struct pv_pvtx_state *st, const char *part)
{
	char sig_name[PATH_MAX] = { 0 };

	if (strstr(part, ".json"))
		snprintf(sig_name, PATH_MAX, "_sigs/%s", part);
	else
		snprintf(sig_name, PATH_MAX, "_sigs/%s.json", part);

	size_t sig_name_sz = strlen(sig_name);
	char *sig = NULL;
	for (int i = 0; i < st->len; i++) {
		struct pv_pvtx_state_data *std = st->std[i];
		for (int j = 0; j < std->sigs_len; j++) {
			if (!strncmp(sig_name, std->sigs[j], sig_name_sz)) {
				sig = std->sigs_data[j];
				break;
			}
		}
	}

	if (!sig)
		return 0;

	int tkn_len = 0;
	jsmntok_t *tkn = pv_pvtx_jsmn_parse_data(sig, strlen(sig), &tkn_len);

	for (int i = 0; i < tkn_len; i++) {
		if (strncmp(sig + tkn[i].start, "include", strlen("include")) &&
		    strncmp(sig + tkn[i].start, "exclude", strlen("exclude")))
			continue;

		int j = i + 2;
		while (tkn[j].size == 0) {
			char part_found[PATH_MAX] = { 0 };
			char *src = sig + tkn[j].start;
			int len = tkn[j].end - tkn[j].start;

			// this is to look for signatures which start with this
			// string and not a substring inside another signature.
			part_found[0] = '"';
			memcpy(part_found + 1, src, len);
			// remove the *'s because we use strncmp, so just
			// search until the char befor the first *
			char *p = strchr(part_found, '*');
			if (p)
				*p = '\0';

			if (!has_more_signatories(st, part_found))
				// +1 to "remove" the initial "
				remove_part(st, part_found + 1);
			j++;
		}
	}

	remove_part(st, sig_name);

	return 0;
}

// this function doesn't remove anything from the pvtx_state, we just set the
// parent token as JSMN_UNDEFINED this means that we don't print that token
// and neither his sub keys

int pv_pvtx_state_remove(struct pv_pvtx_state *st, const char *part)
{
	int ret = 0;
	if (is_signature(part)) {
		remove_signed(st, part + strlen(PVTX_STATE_SIGS_STR));
	} else {
		const char *name = strchr(part, '/');
		if (name)
			name++;
		else
			name = part;
		int index = search_state_data(st, name);
		if (index < 0)
			return -1;
		if (st->std[index]->has_sig) {
			remove_signed(st, name);
		} else {
			char conf_part[PATH_MAX] = { 0 };
			snprintf(conf_part, PATH_MAX, "_config/%s", name);
			ret = remove_part(st, name);
			if (ret != 0)
				return -1;

			ret = remove_part(st, conf_part);
		}
	}

	return ret;
}

static char *write_header(char *buf)
{
	char *p = buf;
	char *header = "{\"#spec\":\"";
	p = mempcpy(p, header, strlen(header));
	p = mempcpy(p, PV_PVTX_STATE_CURRENT_SPEC,
		    strlen(PV_PVTX_STATE_CURRENT_SPEC));
	return mempcpy(p, "\",", 2);
}

static char *write_signatures(char *p, struct pv_pvtx_state_data *std)
{
	for (int i = 0; i < std->tkn_len; ++i) {
		if (std->tkn[i].type == JSMN_UNDEFINED)
			continue;

		const char *tkn_name = token_to_str(std, i, NULL);
		if (is_signature(tkn_name)) {
			p = mempcpy(p, "\"", 1);
			int len = 0;
			const char *str = token_to_str(std, i, &len);
			p = mempcpy(p, str, len);
			p = mempcpy(p, "\":", 2);

			len = 0;
			str = token_to_str(std, i + 1, &len);

			p = mempcpy(p, str, len);
			p = mempcpy(p, ",", 1);
		}
	}
	return p;
}

static char *write_body(char *p, struct pv_pvtx_state_data *std, char **groups,
			char **disks, char **device)
{
	// starts in 1 to ignore the first element which is the global object
	int i = 1;
	while (i < std->tkn_len) {
		jsmntok_t *t = &std->tkn[i];

		if (t->type == JSMN_UNDEFINED) {
			// only keys are mark as JSMN_UNDEFINED, so
			// we need to eval next tkn, i.e the value
			++i;
			++t;
			goto next;
		}

		int len = 0;
		const char *name = token_to_str(std, i, &len);

		if (is_signature(name)) {
			// to skipt this we eval the value, to jump in
			// the appropiate way
			t++;
			i++;
			goto next;
		}

		if (!strncmp(name, "groups.json", len)) {
			t++;
			i++;
			if (*groups)
				free(*groups);
			*groups = strndup(std->data + t->start,
					  t->end - t->start);
			if (*device) {
				free(*device);
				*device = NULL;
			}
			goto next;
		}
		if (!strncmp(name, "disks.json", len)) {
			t++;
			i++;
			if (*disks)
				free(*disks);
			*disks = strndup(std->data + t->start,
					 t->end - t->start);
			if (*device) {
				free(*device);
				*device = NULL;
			}
			goto next;
		}

		if (!strncmp(name, "device.json", len)) {
			t++;
			i++;
			if (*device)
				free(*device);
			*device = strndup(std->data + t->start,
					  t->end - t->start);
			goto next;
		}

		if (t->type == JSMN_STRING) {
			p = mempcpy(p, "\"", 1);
			p = mempcpy(p, name, len);
			p = mempcpy(p, "\"", 1);
		} else {
			p = mempcpy(p, name, len);
		}

		if (pv_pvtx_jsmn_is_key(std->data, t))
			p = mempcpy(p, ":", 1);
		else
			p = mempcpy(p, ",", 1);

	next:
		if (t->type == JSMN_ARRAY || t->type == JSMN_OBJECT) {
			int childs = 1;
			do {
				childs += std->tkn[i].size;
				++i;
				// we reach the end of the json
				if (i == std->tkn_len)
					break;
				--childs;
			} while (childs > 0);
		} else {
			++i;
		}
	}
	return p;
}

char *write_string_body(char *dst, const char *key, const char *value)
{
	dst = mempcpy(dst, "\"", 1);
	dst = mempcpy(dst, key, strlen(key));
	dst = mempcpy(dst, "\"", 1);
	dst = mempcpy(dst, ":", 1);
	dst = mempcpy(dst, value, strlen(value));
	dst = mempcpy(dst, ",", 1);
	return dst;
}

char *pv_pvtx_state_to_str(struct pv_pvtx_state *st, size_t *len)
{
	if (!st) {
		if (len)
			*len = strlen(PVTX_STATE_EMPTY);
		return strdup(PVTX_STATE_EMPTY);
	}

	size_t mem_len = 0;
	for (int i = 0; i < st->len; ++i)
		mem_len += st->std[i]->data_len;

	if (mem_len == 0)
		return NULL;

	char *buf = calloc(mem_len * 2, sizeof(char));
	if (!buf)
		return NULL;

	char *p = write_header(buf);

	for (int i = 0; i < st->len; ++i)
		p = write_signatures(p, st->std[i]);

	char *groups = NULL;
	char *disks = NULL;
	char *device = NULL;
	for (int i = 0; i < st->len; ++i)
		p = write_body(p, st->std[i], &groups, &disks, &device);

	if (device) {
		p = write_string_body(p, "device.json", device);
	} else {
		if (groups)
			p = write_string_body(p, "groups.json", groups);

		if (disks)
			p = write_string_body(p, "disks.json", disks);
	}

	*(p - 1) = '}';
	*p = '\0';

	size_t json_len = p - buf;
	if (len)
		*len = json_len;

	return buf;
}