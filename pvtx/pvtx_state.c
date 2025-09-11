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
#include "pvtx_utils/base64.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define PVTX_STATE_SIGS_STR "_sigs/"
#define PVTX_STATE_CONF_STR "_config/"

struct pv_pvtx_array {
	union {
		int *i;
		jsmntok_t *t;
		char **str;
		void *v;
	} data;
	int size;
	bool has_str;
};

struct pv_pvtx_state_priv {
	struct pv_pvtx_array key;
	struct pv_pvtx_array tok;
	struct pv_pvtx_array pat;
};

void pvtx_array_free(struct pv_pvtx_array *arr)
{
	if (!arr)
		return;

	if (!arr->data.v)
		return;

	if (arr->has_str) {
		for (int i = 0; i < arr->size; i++)
			free(arr->data.str[i]);
	}

	free(arr->data.v);
}

int pvtx_array_add_int(struct pv_pvtx_array *arr, int n)
{
	int *tmp = realloc(arr->data.i, (arr->size + 1) * sizeof(int));
	if (!tmp)
		return -1;

	arr->data.i = tmp;
	arr->data.i[arr->size] = n;
	arr->size++;

	return 0;
}

int pvtx_array_add_str(struct pv_pvtx_array *arr, const char *str, int size)
{
	char *s = strndup(str, size);
	if (!s)
		return -1;

	char **tmp = realloc(arr->data.str, (arr->size + 1) * sizeof(char *));
	if (!tmp) {
		free(s);
		return -1;
	}

	arr->data.str = tmp;
	arr->data.str[arr->size] = s;
	arr->size++;
	arr->has_str = true;

	return 0;
}

void pv_pvtx_state_priv_free(struct pv_pvtx_state_priv *priv)
{
	if (!priv)
		return;

	priv->key.has_str = false;
	pvtx_array_free(&priv->key);

	priv->tok.has_str = false;
	pvtx_array_free(&priv->tok);

	priv->tok.has_str = true;
	pvtx_array_free(&priv->pat);

	free(priv);
}

void pv_pvtx_state_free(struct pv_pvtx_state *st)
{
	if (!st)
		return;

	if (st->priv)
		pv_pvtx_state_priv_free(st->priv);

	if (st->json)
		free(st->json);

	free(st);
}

static const char *token_to_str(struct pv_pvtx_state *st, int idx, int *len)
{
	if (!st || idx < 0 || idx > st->priv->tok.size)
		goto err;

	jsmntok_t *tok = &st->priv->tok.data.t[idx];

	if (!tok || tok->type == JSMN_UNDEFINED)
		goto err;

	if (len)
		*len = tok->end - tok->start;

	return st->json + tok->start;
err:
	if (len)
		*len = 0;
	return NULL;
}

static int get_decoded_sig(struct pv_pvtx_state *st, int idx, char **dec,
			   size_t *len)
{
	int json_len = 0;
	const char *json = token_to_str(st, idx + 1, &json_len);

	int tkn_len = 0;
	jsmntok_t *tok = pv_pvtx_jsmn_parse_data(json, json_len, &tkn_len);

	int enc_idx = 0;
	const char *key = "protected";
	size_t key_sz = strlen(key);

	jsmntok_t *sig_tok = NULL;
	for (int i = 0; i < tkn_len; i++) {
		if (!strncmp(json + tok[i].start, key, key_sz)) {
			sig_tok = &tok[i + 1];
			break;
		}
	}

	int ret = 0;
	if (!sig_tok)
		goto out;

	size_t dec_len = 0;
	*dec = (char *)base64_url_decode(
		json + sig_tok->start, sig_tok->end - sig_tok->start, &dec_len);

	if (!*dec) {
		ret = -1;
		goto out;
	}

	if (len)
		*len = dec_len;
out:
	free(tok);
	return ret;
}

static int add_patterns(struct pv_pvtx_array *arr, struct pv_pvtx_state *st,
			int idx)
{
	size_t dec_sz = 0;
	char *dec = NULL;
	int ret = get_decoded_sig(st, idx, &dec, &dec_sz);

	if (ret != 0)
		return -1;

	int tok_len = 0;
	jsmntok_t *tok = pv_pvtx_jsmn_parse_data(dec, dec_sz, &tok_len);

	for (int i = 0; i < tok_len; i++) {
		const char *str = dec + tok[i].start;

		if (strncmp(str, "include", strlen("include")) &&
		    strncmp(str, "exclude", strlen("exclude")))
			continue;

		// i    : signature
		// i + 1: the whole array
		// i + 2: the first element
		int j = i + 2;
		// array elements hasn't childs
		while (tok[j].size == 0) {
			char pat[PATH_MAX] = { 0 };
			memcpy(pat, dec + tok[j].start,
			       tok[j].end - tok[j].start);

			// discard * or **
			char *p = strchr(pat, '*');
			if (p)
				*p = '\0';

			pvtx_array_add_str(arr, pat, strlen(pat));
			j++;
		}
	}

	free(tok);
	free(dec);

	return 0;
}

static int next_key(struct pv_pvtx_state *st, int cur)
{
	jsmntok_t *tok = &st->priv->tok.data.t[cur];
	do {
		if (tok->type == JSMN_ARRAY || tok->type == JSMN_OBJECT) {
			int childs = 1;
			do {
				childs += tok->size;
				cur++;
				// we reach the end of the json
				if (cur == st->priv->tok.size)
					return -1;

				--childs;
				tok = &st->priv->tok.data.t[cur];
			} while (childs > 0);
		} else {
			cur++;
			if (cur == st->priv->tok.size)
				return -1;
			tok = &st->priv->tok.data.t[cur];
		}

	} while (tok->type == JSMN_UNDEFINED ||
		 !pv_pvtx_jsmn_is_key(st->json, tok));

	return cur;
}

static struct pv_pvtx_array get_keys(struct pv_pvtx_state *st)
{
	struct pv_pvtx_array arr = { 0 };

	int idx = 1;
	while ((idx = next_key(st, idx)) > 0)
		pvtx_array_add_int(&arr, idx);

	return arr;
}

static int get_all_patterns(struct pv_pvtx_state *st,
			    struct pv_pvtx_array *patterns,
			    struct pv_pvtx_error *err)
{
	struct pv_pvtx_array *keys = &st->priv->key;

	for (int i = 0; i < keys->size; i++) {
		int len = 0;
		const char *key_str = token_to_str(st, keys->data.i[i], &len);

		if (strncmp(key_str, PVTX_STATE_SIGS_STR,
			    strlen(PVTX_STATE_SIGS_STR)) != 0)
			continue;

		if (add_patterns(patterns, st, keys->data.i[i]) != 0) {
			if (!err)
				return -1;

			int name_len = 0;
			const char *name =
				token_to_str(st, keys->data.i[i], &name_len);
			PVTX_ERROR_SET(err, -1,
				       "couldn't decrypt %.*s signature",
				       name_len, name);

			return -1;
		}
	}
	return 0;
}

static struct pv_pvtx_state *pvtx_state_alloc()
{
	struct pv_pvtx_state *st = calloc(1, sizeof(struct pv_pvtx_state));
	if (!st)
		return NULL;

	st->priv = calloc(1, sizeof(struct pv_pvtx_state_priv));
	if (!st->priv)
		goto err;

	return st;
err:
	pv_pvtx_state_free(st);
	return NULL;
}

struct pv_pvtx_state *pv_pvtx_state_from_str(const char *str, size_t len,
					     struct pv_pvtx_error *err)
{
	struct pv_pvtx_state *st = pvtx_state_alloc();
	if (!st)
		goto error;

	struct pv_pvtx_state_priv *priv = st->priv;

	priv->tok.data.t = pv_pvtx_jsmn_parse_data(str, len, &priv->tok.size);
	if (!priv->tok.data.t) {
		if (err)
			PVTX_ERROR_SET(err, -1, "couldn't parse json data");
		goto error;
	}
	priv->tok.has_str = false;

	st->json = strndup(str, len);
	st->len = len;
	priv->key = get_keys(st);
	priv->key.has_str = false;
	st->priv = priv;

	if (get_all_patterns(st, &st->priv->pat, err) != 0)
		goto error;

	return st;
error:
	pv_pvtx_state_free(st);
	return NULL;
}

struct pv_pvtx_state *pv_pvtx_state_from_file(const char *path,
					      struct pv_pvtx_error *err)
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

	struct pv_pvtx_state *state =
		pv_pvtx_state_from_str(data, st.st_size, err);
	munmap(data, st.st_size);

	return state;
}

static char *write_header(char *buf)
{
	size_t len = strlen(PVTX_STATE_EMPTY) - 1;
	char *ptr = mempcpy(buf, PVTX_STATE_EMPTY, len);
	*ptr = ',';
	ptr++;
	return ptr;
}

static char *write_footer(char *buf)
{
	*(buf - 1) = '}';
	*buf = '\0';
	return buf;
}

static char *write_key(char *buf, struct pv_pvtx_state *st, int idx)
{
	int klen = 0;
	const char *key = token_to_str(st, idx, &klen);

	int vlen = 0;
	const char *val = token_to_str(st, idx + 1, &vlen);
	jsmntok_t *tkn = &st->priv->tok.data.t[idx + 1];

	char *ptr = buf;
	ptr = mempcpy(ptr, "\"", 1);
	ptr = mempcpy(ptr, key, klen);
	ptr = mempcpy(ptr, "\":", 2);

	if (tkn->type == JSMN_STRING)
		ptr = mempcpy(ptr, "\"", 1);

	ptr = mempcpy(ptr, val, vlen);

	if (tkn->type == JSMN_STRING)
		ptr = mempcpy(ptr, "\",", 2);
	else
		ptr = mempcpy(ptr, ",", 1);

	return ptr;
}

static void get_patterns(struct pv_pvtx_state *st, const char *part, int plen,
			 struct pv_pvtx_array *patterns)
{
	const char *part_ptr = part;
	int ptr_len = plen;
	if (*part == '_') {
		if (!strncmp(part_ptr, PVTX_STATE_CONF_STR,
			     strlen(PVTX_STATE_CONF_STR))) {
			part_ptr += strlen(PVTX_STATE_CONF_STR);
			ptr_len -= strlen(PVTX_STATE_CONF_STR);
		} else if (!strncmp(part_ptr, PVTX_STATE_SIGS_STR,
				    strlen(PVTX_STATE_SIGS_STR))) {
			part_ptr += strlen(PVTX_STATE_SIGS_STR);
			ptr_len -= strlen(PVTX_STATE_SIGS_STR);
		}
	}

	int sig_len = strlen(PVTX_STATE_SIGS_STR);
	pvtx_array_add_str(patterns, part, plen);

	struct pv_pvtx_array *key = &st->priv->key;
	for (int i = 0; i < key->size; i++) {
		int len = 0;
		const char *key_str = token_to_str(st, key->data.i[i], &len);
		if (strncmp(key_str, PVTX_STATE_SIGS_STR, sig_len) != 0)
			continue;

		len -= sig_len;
		if (len < 1)
			continue;
		key_str += sig_len;

		if (!strncmp(part_ptr, key_str, ptr_len)) {
			add_patterns(patterns, st, key->data.i[i]);
			break;
		}
	}
}

static void pvtx_state_move(struct pv_pvtx_state *dst,
			    struct pv_pvtx_state *src)
{
	pv_pvtx_state_priv_free(dst->priv);
	free(dst->json);

	dst->json = src->json;
	dst->len = src->len;
	dst->priv = src->priv;

	free(src);
}

static void state_from_keys(struct pv_pvtx_state *st,
			    struct pv_pvtx_array *rm_keys, char *buf)
{
	if (rm_keys->size == 0)
		return;

	char *ptr = write_header(buf);
	struct pv_pvtx_array *keys = &st->priv->key;

	for (int i = 0; i < keys->size; i++) {
		bool wr = true;
		for (int j = 0; j < rm_keys->size; j++) {
			if (keys->data.i[i] == rm_keys->data.i[j]) {
				wr = false;
				break;
			}
		}

		if (wr)
			ptr = write_key(ptr, st, keys->data.i[i]);
		else
			wr = true;
	}

	ptr = write_footer(ptr);
	pvtx_state_move(st, pv_pvtx_state_from_str(buf, ptr - buf, NULL));
}

static int match_pattern(struct pv_pvtx_state *st, struct pv_pvtx_array *pat,
			 const char *key)
{
	int count = 0;
	const char *cur_pat = NULL;
	for (int i = 0; i < pat->size; i++) {
		cur_pat = pat->data.str[i];
		if (!strncmp(key, cur_pat, strlen(cur_pat)))
			count++;
	}

	return count;
}

static void remove_keys(struct pv_pvtx_state *st, const char *part, int plen,
			struct pv_pvtx_array *keys_rm)
{
	struct pv_pvtx_array patterns = { 0 };
	get_patterns(st, part, plen, &patterns);

	struct pv_pvtx_array *keys = &st->priv->key;

	for (int i = 0; i < keys->size; i++) {
		int len = 0;
		const char *key_str = token_to_str(st, keys->data.i[i], &len);

		int n = match_pattern(st, &patterns, key_str);
		if (n < 1)
			continue;

		int m = match_pattern(st, &st->priv->pat, key_str);
		if (m > n)
			continue;

		pvtx_array_add_int(keys_rm, keys->data.i[i]);
	}

	pvtx_array_free(&patterns);
}

int get_next_key_str(struct pv_pvtx_state *st, int last, char *str)
{
	if (last >= st->priv->key.size) {
		str[0] = 0x7f;
		return -1;
	}

	int len = 0;
	const char *tmp = token_to_str(st, st->priv->key.data.i[last], &len);
	memccpy(str, tmp, '\0', len);
	return last;
}

static void merge_state(struct pv_pvtx_state *dst, struct pv_pvtx_state *src)
{
	struct pv_pvtx_array *dst_keys = &dst->priv->key;
	struct pv_pvtx_array *src_keys = &src->priv->key;

	char *buf = calloc((dst->len + src->len) * 1.5, sizeof(char));
	if (!buf)
		return;

	char *ptr = write_header(buf);

	char src_str[PATH_MAX] = { 0 };
	char dst_str[PATH_MAX] = { 0 };

	int src_idx = get_next_key_str(src, 0, src_str);
	int dst_idx = get_next_key_str(dst, 0, dst_str);

	while (src_idx != -1 || dst_idx != -1) {
		if (strcmp(src_str, dst_str) < 0) {
			ptr = write_key(ptr, src, src_keys->data.i[src_idx]);
			memset(src_str, 0, PATH_MAX);
			src_idx++;
			src_idx = get_next_key_str(src, src_idx, src_str);
		} else {
			ptr = write_key(ptr, dst, dst_keys->data.i[dst_idx]);
			memset(dst_str, 0, PATH_MAX);
			dst_idx++;
			dst_idx = get_next_key_str(dst, dst_idx, dst_str);
		}
	}

	ptr = write_footer(ptr);

	pvtx_state_move(dst, pv_pvtx_state_from_str(buf, ptr - buf, NULL));
	free(buf);
}

int pv_pvtx_state_add(struct pv_pvtx_state *dst, struct pv_pvtx_state *src)
{
	struct pv_pvtx_array *keys = &src->priv->key;
	struct pv_pvtx_array keys_rm = { 0 };

	for (int i = 0; i < keys->size; i++) {
		int len = 0;
		const char *key_str = token_to_str(src, keys->data.i[i], &len);

		remove_keys(dst, key_str, len, &keys_rm);
	}

	int ret = -1;

	char *buf = calloc(dst->len, sizeof(char));
	if (!buf)
		goto out;

	state_from_keys(dst, &keys_rm, buf);
	free(buf);

	merge_state(dst, src);
	ret = 0;
out:
	pvtx_array_free(&keys_rm);
	return ret;
}

int pv_pvtx_state_remove(struct pv_pvtx_state *st, const char *part)
{
	struct pv_pvtx_array rm_keys = { 0 };
	remove_keys(st, part, strlen(part), &rm_keys);

	int ret = -1;

	char *buf = calloc(st->len, sizeof(char));
	if (!buf)
		goto out;

	state_from_keys(st, &rm_keys, buf);
	free(buf);
	ret = 0;
out:
	pvtx_array_free(&rm_keys);

	return ret;
}