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
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <libgen.h>
#include <fnmatch.h>
#include <mbedtls/pk.h>
#include <mbedtls/md_internal.h>

#include "signature.h"
#include "utils/json.h"
#include "utils/str.h"
#include "utils/base64.h"

#define MODULE_NAME             "signature"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define SPEC_PVS2 "pvs@2"
#define TYP_PVS "PVS"

struct pv_signature_headers_pvs {
	char *include;
	char *exclude;
};

struct pv_signature_headers {
	char *alg;
	struct pv_signature_headers_pvs *pvs;
};

struct pv_signature {
	char *protected;
	char *signature;
};

struct pv_signature_pair {
	char *key;
	char *value;
	bool included;
	bool covered;
	struct dl_list list; // pv_signature_pair
};

static void pv_signature_free_headers_pvs(struct pv_signature_headers_pvs *pvs)
{
	if (!pvs)
		return;

	if (pvs->include)
		free(pvs->include);
	if (pvs->exclude)
		free(pvs->exclude);
}

static void pv_signature_free_headers(struct pv_signature_headers *headers)
{
	if (!headers)
		return;

	pv_signature_free_headers_pvs(headers->pvs);

	if (headers->alg)
		free(headers->alg);
}

static void pv_signature_free(struct pv_signature *signature)
{
	if (!signature)
		return;

	if (signature->protected)
		free(signature->protected);
	if (signature->signature)
		free(signature->signature);
}

static struct pv_signature* pv_signature_parse_pvs(const char *json)
{
	struct pv_signature* signature = NULL;
	int tokc;
	jsmntok_t *tokv = NULL;
	char *spec = NULL, *protected = NULL;

	signature = calloc(1, sizeof(struct pv_signature));
	if (!signature) {
		pv_log(ERROR, "could not alloc signature");
		goto out;
	}

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		goto out;
	}

	spec = pv_json_get_value(json, "#spec", tokv, tokc);
	if (!spec) {
		goto err;
	}

	if (!pv_str_matches(spec, strlen(spec), SPEC_PVS2, strlen(SPEC_PVS2))) {
		goto err;
	}

	signature->protected = pv_json_get_value(json, "protected", tokv, tokc);
	if (!signature->protected) {
		pv_log(ERROR, "no protected key found");
		goto err;
	}

	signature->signature = pv_json_get_value(json, "signature", tokv, tokc);
	if (!signature->signature) {
		pv_log(ERROR, "no signature key found");
		goto err;
	}

	goto out;

err:
	if (signature) {
		pv_signature_free(signature);
		signature = NULL;
	}

out:
	if (tokv)
		free(tokv);
	if (spec)
		free(spec);
	if (protected)
		free(protected);

	return signature;
}

static struct pv_signature_headers_pvs* pv_signature_parse_headers_pvs(const char *json)
{
	struct pv_signature_headers_pvs *headers_pvs = NULL;
	int tokc;
	jsmntok_t *tokv = NULL;

	headers_pvs = calloc(1, sizeof(struct pv_signature_headers_pvs));
	if (!headers_pvs) {
		pv_log(ERROR, "could not alloc headers pvs");
		goto out;
	}

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format headers pvs JSON");
		goto out;
	}

	headers_pvs->include = pv_json_get_value(json, "include", tokv, tokc);
	if (!headers_pvs->include) {
		pv_log(ERROR, "no include key found");
		goto err;
	}

	headers_pvs->exclude = pv_json_get_value(json, "exclude", tokv, tokc);
	if (!headers_pvs->exclude) {
		pv_log(ERROR, "no exclude key found");
		goto err;
	}

	goto out;

err:
	if (headers_pvs) {
		pv_signature_free_headers_pvs(headers_pvs);
		headers_pvs = NULL;
	}

out:
	if (tokv)
		free(tokv);

	return headers_pvs;
}

static struct pv_signature_headers* pv_signature_parse_protected(char *protected)
{
	struct pv_signature_headers *headers = NULL;
	char *json = NULL, *typ = NULL, *pvs = NULL;
	size_t olen;
	int tokc;
	jsmntok_t *tokv = NULL;

	headers = calloc(1, sizeof(struct pv_signature_headers));
	if (!headers) {
		pv_log(ERROR, "could not alloc signature headers");
		goto out;
	}

	if (pv_base64_url_decode(protected, &json, &olen)) {
		pv_log(ERROR, "protected value could not be decoded");
		goto err;
	}

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format headers JSON");
		goto err;
	}

	typ = pv_json_get_value(json, "typ", tokv, tokc);
	if (!typ) {
		pv_log(ERROR, "no typ key found");
		goto err;
	}

	if (!pv_str_matches(typ, strlen(typ), TYP_PVS, strlen(TYP_PVS))) {
		pv_log(ERROR, "wrong typ %s", typ);
		goto err;
	}

	pvs = pv_json_get_value(json, "pvs", tokv, tokc);
	if (!pvs) {
		pv_log(ERROR, "no pvr key found");
		goto err;
	}

	headers->pvs = pv_signature_parse_headers_pvs(pvs);

	headers->alg = pv_json_get_value(json, "alg", tokv, tokc);
	if (!headers->alg) {
		pv_log(ERROR, "no alg key found");
		goto err;
	}

	goto out;

err:
	if (headers) {
		pv_signature_free_headers(headers);
		headers = NULL;
	}

out:
	if (json)
		free(json);
	if (typ)
		free(typ);
	if (tokv)
		free(tokv);

	return headers;
}

static void pv_signature_free_pair(struct pv_signature_pair *file)
{
	if (!file)
		return;

	if (file->key)
		free(file->key);
	if (file->value)
		free(file->value);
}

static void pv_signature_free_pairs(struct dl_list *json_pairs)
{
	struct pv_signature_pair *f, *tmp;

	dl_list_for_each_safe(f, tmp, json_pairs,
			struct pv_signature_pair, list) {
		dl_list_del(&f->list);
		pv_signature_free_pair(f);
	}
}

static void pv_signature_include_files(const char *json,
									bool include,
									struct dl_list *json_pairs)
{
	char *str = NULL, *path = NULL;
	int tokc, size;
	jsmntok_t *tokv, *t;
	struct pv_signature_pair *pair, *tmp;

	if (include) {
		pv_log(DEBUG, "including %s", json);
	} else {
		pv_log(DEBUG, "excluding %s", json);
	}

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format filter");
		goto out;
	}

	size = jsmnutil_array_count(json, tokv);
	if (size <= 0) {
		pv_log(ERROR, "empty filter");
		goto out;
	}

	t = tokv+1;
	while ((str = pv_json_array_get_one_str(json, &size, &t))) {
		dl_list_for_each_safe(pair, tmp, json_pairs,
				struct pv_signature_pair, list) {
			if (!fnmatch(str, pair->key, 0)) {
				pair->included = include;
				pair->covered = true;
			}
		}

		if (str) {
			free(str);
			str = NULL;
		}
		if (path) {
			free(path);
			path = NULL;
		}
	}

out:
	if (tokv)
		free(tokv);
}

static void pv_signature_reset_included(struct dl_list *json_pairs)
{
	struct pv_signature_pair *pair, *tmp;

	dl_list_for_each_safe(pair, tmp, json_pairs,
			struct pv_signature_pair, list) {
		pair->included = false;
	}
}

static void pv_signature_filter_files(struct pv_signature_headers_pvs *pvs,
									struct dl_list *json_pairs)
{
	pv_signature_include_files(pvs->include, true, json_pairs);
	pv_signature_include_files(pvs->exclude, false, json_pairs);
}

static char* pv_signature_get_json_files(struct dl_list *json_pairs)
{
	char *out;
	int len, num_pairs, i = 0;
	struct pv_signature_pair *pair, *tmp;

	len = 2;
	out = calloc(1, len);
	if (!out)
		return out;

	strcpy(out, "{");

	num_pairs = dl_list_len(json_pairs);
	dl_list_for_each_safe(pair, tmp, json_pairs,
			struct pv_signature_pair, list) {
		if (!pair->included)
			continue;

		len += 1 + strlen(pair->key);
		out = realloc(out, len);
		strcat(out, "\"");
		strcat(out, pair->key);
		if (pair->value[0] != '{') {
			len += 4 + strlen(pair->value);
			out = realloc(out, len);
			strcat(out, "\":\"");
			strcat(out, pair->value);
			strcat(out, "\"");
		} else {
			len += 2 + strlen(pair->value);
			out = realloc(out, len);
			strcat(out, "\":");
			strcat(out, pair->value);
		}

		len += 1;
		out = realloc(out, len);
		strcat(out, ",");

		i++;
	}

	out[len - 2] = '}';
	out[len - 1] = '\0';

	return out;
}

static char* pv_signature_get_filtered_json(struct pv_signature_headers_pvs *pvs,
											struct dl_list *json_pairs)
{
	pv_signature_reset_included(json_pairs);
	pv_signature_filter_files(pvs, json_pairs);
	return pv_signature_get_json_files(json_pairs);
}

static bool pv_signature_verify_rs256(const char *payload, struct pv_signature *signature)
{
	bool ret = false;
	int res;
	char *payload_encoded = NULL, *files_encoded = NULL, *sig_decoded = NULL;
	unsigned char *hash = NULL;
	size_t olen;

	pv_log(DEBUG, "using RS256 algorithm");

	mbedtls_pk_context pk;

	mbedtls_pk_init(&pk);

	if (mbedtls_pk_parse_public_keyfile(&pk, "/etc/pantavisor/pvs/pub.pem")) {
		pv_log(ERROR, "cannot read public key");
		goto out;
	}

	if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
		pv_log(ERROR, "key is not a RSA key");
		goto out;
	}

	if (pv_base64_url_encode(payload, &files_encoded, &olen)) {
		pv_log(ERROR, "payload could not be encoded");
		goto out;
	}

	payload_encoded = calloc(1, strlen(files_encoded)+strlen(signature->protected)+2);
	strcpy(payload_encoded, signature->protected);
	strcat(payload_encoded, ".");
	strcat(payload_encoded, files_encoded);

	hash = calloc(1, 32);
	if (!hash) {
		pv_log(ERROR, "cannot allocate hash");
		goto out;
	}

	res = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (unsigned char*)payload_encoded, strlen(payload_encoded), hash);
	if (res) {
		pv_log(ERROR, "cannot create hash with code %d", res);
		goto out;
	}

	if (pv_base64_url_decode(signature->signature, &sig_decoded, &olen)) {
		pv_log(ERROR, "signature could not be decoded");
		goto out;
	}

	pv_log(DEBUG, "signature length is %d", olen);

	res = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, (unsigned char*)sig_decoded, olen);
	if (res) {
		pv_log(ERROR, "verification returned error code %d", res);
		goto out;
	}

	pv_log(ERROR, "signature OK");
	ret = true;

out:
	if (files_encoded)
		free(files_encoded);
	if (sig_decoded)
		free(sig_decoded);
	if (hash)
		free(hash);
	mbedtls_pk_free(&pk);
	return ret;
}

static void pv_signature_parse_json(const char *json, struct dl_list *json_pairs)
{
	int ret, tokc, n;
	jsmntok_t *tokv;
	jsmntok_t **k, **keys = NULL;
	struct pv_signature_pair *pair = NULL;

	ret = jsmnutil_parse_json(json, &tokv, &tokc);
	if (ret < 0) {
		pv_log(ERROR, "unable to parse state JSON");
		goto out;
	}

	keys = jsmnutil_get_object_keys(json, tokv);
	k = keys;

	// platform head is pv->state->platforms
	while (*k) {
		n = (*k)->end - (*k)->start;

		pair = calloc(1, sizeof(struct pv_signature_pair));
		if (!pair)
			goto out;

		// discard #spec
		if (pv_str_matches(json+(*k)->start, n, "#spec", strlen("#spec"))) {
			k++;
			continue;
		}

		// copy key
		pair->key = calloc(1, n+1);
		if (!pair->key)
			goto out;
		snprintf(pair->key, n+1, "%s", json+(*k)->start);

		// copy value
		n = (*k+1)->end - (*k+1)->start;
		pair->value = calloc(1, n+1);
		if (!pair->value)
			goto out;
		snprintf(pair->value, n+1, "%s", json+(*k+1)->start);

		dl_list_add_tail(json_pairs, &pair->list);

		k++;
	}

out:
	if (keys)
		jsmnutil_tokv_free(keys);
	if (tokv)
		free(tokv);
}

static bool pv_signature_verify_pvs(struct pv_signature *signature,
									struct dl_list *json_pairs)
{
	bool ret = false;
	struct pv_signature_headers *headers = NULL;
	char *payload = NULL;

	headers = pv_signature_parse_protected(signature->protected);
	if (!headers) {
		pv_log(ERROR, "could not parse protected JSON");
		goto out;
	}

	payload = pv_signature_get_filtered_json(headers->pvs, json_pairs);
	if (!payload) {
		pv_log(ERROR, "could not get signature payload");
		goto out;
	}

	pv_log(DEBUG, "filtered json '%s'", payload);

	if (pv_str_matches(headers->alg, strlen(headers->alg), "RS256", strlen("RS256"))) {
		ret = pv_signature_verify_rs256(payload, signature);
	} else {
		pv_log(ERROR, "unknown algorithm in protected JSON %s", headers->alg);
	}
out:
	if (headers)
		pv_signature_free_headers(headers);
	if (payload)
		free(payload);
	return ret;
}

static bool pv_signature_verify_pairs(struct dl_list *json_pairs)
{
	bool ret = false, found = false;
	struct pv_signature_pair *pair, *tmp;
	struct pv_signature *signature = NULL;

	dl_list_for_each_safe(pair, tmp, json_pairs,
		struct pv_signature_pair, list) {
		signature = pv_signature_parse_pvs(pair->value);
		if (signature) {
			found = true;
			pv_log(DEBUG, "%s found", pair->key);
			if (!pv_signature_verify_pvs(signature, json_pairs))
				goto out;

			pv_signature_free(signature);
			signature = NULL;
		}
	}

	if (!found)
		pv_log(DEBUG, "no JSON with %s specification found in revision", SPEC_PVS2);

	ret = true;

out:
	if (signature)
		pv_signature_free(signature);
	return ret;
}

static bool pv_signature_all_covered(struct dl_list *json_pairs)
{
	bool ret = true;
	struct pv_signature_pair *pair, *tmp;

	pv_log(DEBUG, "checking all state JSON items are covered by signatures");

	dl_list_for_each_safe(pair, tmp, json_pairs,
		struct pv_signature_pair, list) {
		// skip everything in the _sigs folder
		if (pv_str_startswith("_sigs/", strlen("_sigs/"), pair->key))
			continue;
		if(!pair->covered) {
			pv_log(ERROR, "%s is not covered by any signature", pair->key);
			ret = false;
		}
	}

	if (ret)
		pv_log(DEBUG, "state JSON coverage OK");

	return ret;
}

bool pv_signature_verify(const char *json)
{
	bool ret = false;
	struct dl_list json_pairs; // pv_signature_pair

	if (pv_config_get_secureboot_mode() == SB_DISABLED)
		return true;

	pv_log(DEBUG, "verifying signatures of state JSON");

	dl_list_init(&json_pairs);

	pv_signature_parse_json(json, &json_pairs);
	ret = pv_signature_verify_pairs(&json_pairs);

	if (ret &&
		(pv_config_get_secureboot_mode() == SB_STRICT) &&
		!pv_signature_all_covered(&json_pairs)) {
		pv_log(ERROR, "not all state elements were covered in secureboot strict mode");
		ret = false;
	}

	pv_signature_free_pairs(&json_pairs);
	return ret;
}