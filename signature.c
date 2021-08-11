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
#include <base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/md_internal.h>

#include "signature.h"
#include "storage.h"
#include "platforms.h"
#include "objects.h"
#include "jsons.h"
#include "utils/json.h"
#include "utils/str.h"

#define MODULE_NAME             "signature"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define SPEC_PVS1 "pvs@1"
#define TYP_PVS "PVS"

struct pv_signature_headers_pvs {
	char *part;
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

static void pv_signature_free_headers_pvs(struct pv_signature_headers_pvs *pvs)
{
	if (!pvs)
		return;

	if (pvs->part)
		free(pvs->part);
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
		pv_log(ERROR, "wrong format pvs.json");
		goto out;
	}

	spec = pv_json_get_value(json, "#spec", tokv, tokc);
	if (!spec) {
		pv_log(ERROR, "no #spec key found");
		goto err;
	}

	if (!pv_str_matches(spec, strlen(spec), SPEC_PVS1, strlen(SPEC_PVS1))) {
		pv_log(ERROR, "wrong spec %s", spec);
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
		pv_log(ERROR, "wrong format headers pvs json");
		goto out;
	}

	headers_pvs->part = pv_json_get_value(json, "part", tokv, tokc);
	if (!headers_pvs->part) {
		pv_log(ERROR, "no part key found");
		goto err;
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
		pv_log(ERROR, "wrong format headers json");
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

struct pv_signature_file {
	char *key;
	char *value;
	bool included;
	struct dl_list list; // pv_signature_file
};

static void pv_signature_free_file(struct pv_signature_file *file)
{
	if (!file)
		return;

	if (file->key)
		free(file->key);
	if (file->value)
		free(file->value);
}

static void pv_signature_free_files(struct dl_list *plat_files)
{
	struct pv_signature_file *f, *tmp;

	dl_list_for_each_safe(f, tmp, plat_files,
			struct pv_signature_file, list) {
		dl_list_del(&f->list);
		pv_signature_free_file(f);
	}
}

static void pv_signature_get_plat_files(const char *plat,
										struct pv_state *s,
										struct dl_list *plat_files)
{
	struct pv_signature_file *f;
	struct pv_platform *p;
	struct pv_json *j;

	p = pv_platform_get_by_name(s, plat);

	struct pv_object *o;
	pv_objects_iter_begin(s, o) {
		if (p && (p != o->plat))
			continue;

		f = calloc(1, sizeof(struct pv_signature_file));
		if (f) {
			f->key = strdup(o->name);
			f->value = strdup(o->id);
			dl_list_add(plat_files, &f->list);
		}
	}
	pv_objects_iter_end;

	pv_jsons_iter_begin(s, j) {
		if (p && (p != j->plat))
			continue;

		f = calloc(1, sizeof(struct pv_signature_file));
		if (f) {
			f->key = strdup(j->name);
			f->value = strdup(j->value);
			dl_list_add(plat_files, &f->list);
		}
	}
	pv_jsons_iter_end;
}

static void pv_signature_include_files(const char *component,
									const char *json,
									bool include,
									struct dl_list *plat_files)
{
	char *str = NULL, *path = NULL;
	int tokc, size, len;
	jsmntok_t *tokv, *t;
	struct pv_signature_file *f, *tmp;

	if (include) {
		pv_log(DEBUG, "incluiding %s from part %s", json, component);
	} else {
		pv_log(DEBUG, "excluiding %s from part %s", json, component);
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
		if (pv_str_matches("**", strlen("**"), str, strlen(str))) {
			// if ** is in include, set everything as included
			dl_list_for_each_safe(f, tmp, plat_files,
					struct pv_signature_file, list) {
				f->included = include;
			}
		} else {
			// search and set included key
			len = strlen("%s/%s") + strlen(component) + strlen(str);
			path = calloc(1, len);
			snprintf(path, len, "%s/%s", component, str);
			dl_list_for_each_safe(f, tmp, plat_files,
					struct pv_signature_file, list) {
				if (pv_str_matches(f->key, strlen(f->key), path, strlen(path))) {
					f->included = include;
					break;
				}
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

static void pv_signature_filter_files(struct pv_signature_headers_pvs *pvs,
									struct dl_list *plat_files)
{
	struct pv_signature_file *f, *tmp;

	pv_log(DEBUG, "there are %d files for the component before filtering",
		dl_list_len(plat_files));

	pv_signature_include_files(pvs->part, pvs->include, true, plat_files);
	pv_signature_include_files(pvs->part, pvs->exclude, false, plat_files);

	// now, remove everything that was not included
	dl_list_for_each_safe(f, tmp, plat_files,
			struct pv_signature_file, list) {
		if (!f->included) {
			dl_list_del(&f->list);
			pv_signature_free_file(f);
		}
	}

	pv_log(DEBUG, "there are %d files for the component after filtering",
		dl_list_len(plat_files));
}

static char* pv_signature_get_json_files(const char *json, struct dl_list *plat_files)
{
	char *out;
	int len, files;
	struct pv_signature_file *f, *tmp, *curr = NULL;

	len = strlen(json);
	out = calloc(1, len);
	if (!out)
		return out;

	strcpy(out, "{");

	files = dl_list_len(plat_files);
	for (int i = 0; i < files; i++) {
		dl_list_for_each_safe(f, tmp, plat_files,
				struct pv_signature_file, list) {
			if (!curr || (strcmp(curr->key, f->key) > 0))
				curr = f;
		}

		if (!curr)
			break;

		strcat(out, "\"");
		strcat(out, curr->key);
		if (curr->value[0] != '{') {
			strcat(out, "\":\"");
			strcat(out, curr->value);
			strcat(out, "\"");
		} else {
			strcat(out, "\":");
			strcat(out, curr->value);
		}

		if (i < files - 1)
			strcat(out, ",");

		dl_list_del(&curr->list);
		pv_signature_free_file(curr);

		curr = NULL;
	}

	strcat(out, "}");

	return out;
}

static char* pv_signature_get_filtered_json(struct pv_state *s,
											struct pv_signature_headers_pvs *pvs)
{
	struct dl_list plat_files;
	char *json;

	dl_list_init(&plat_files);

	pv_signature_get_plat_files(pvs->part, s, &plat_files);
	pv_signature_filter_files(pvs, &plat_files);
	json = pv_signature_get_json_files(s->json, &plat_files);

	pv_signature_free_files(&plat_files);

	return json;
}

static bool pv_signature_verify_rs256(const char *payload, struct pv_signature *signature)
{
	int res;
	char *payload_encoded = NULL, *files_encoded = NULL, *sig_decoded = NULL;
	unsigned char *hash = NULL;
	size_t olen;

	pv_log(DEBUG, "verifying signature using RS256 algorithm");

	mbedtls_pk_context pk;

	mbedtls_pk_init(&pk);

	if (mbedtls_pk_parse_public_keyfile(&pk, "/pub.pem")) {
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

	payload_encoded = calloc(1, strlen(payload)+strlen(signature->protected)+2);
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

	if (olen != 256) {
		pv_log(ERROR, "signature does not have the expected length of 256");
		goto out;
	}

	res = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, (unsigned char*)sig_decoded, 256);
	if (res) {
		pv_log(ERROR, "verification went wrong with code %d", res);
		goto out;
	}

out:
	if (files_encoded)
		free(files_encoded);
	if (sig_decoded)
		free(sig_decoded);
	if (hash)
		free(hash);
	mbedtls_pk_free(&pk);
	return false;
}

bool pv_signature_verify(struct pv_state *s, const char *name, const char *json)
{
	bool res = false;
	struct pv_signature *signature = NULL;
	struct pv_signature_headers *headers = NULL;
	char *payload = NULL;

	pv_log(DEBUG, "verifying signature of component %s", name);

	signature = pv_signature_parse_pvs(json);
	if (!signature) {
		pv_log(ERROR, "could not parse pvr.json");
		goto out;
	}

	headers = pv_signature_parse_protected(signature->protected);
	if (!headers) {
		pv_log(ERROR, "could not parse protected json");
		goto out;
	}

	if (!pv_str_matches(name, strlen(name), headers->pvs->part, strlen(headers->pvs->part))) {
		pv_log(ERROR, "protected part does not match with platform name");
		goto out;
	}

	payload = pv_signature_get_filtered_json(s, headers->pvs);
	if (!payload) {
		pv_log(ERROR, "could not get signature payload");
		goto out;
	}

	if (pv_str_matches(headers->alg, strlen(headers->alg), "RS256", strlen("RS256"))) {
		res = pv_signature_verify_rs256(payload, signature);
	} else {
		pv_log(WARN, "unknown algorithm in protected json %s", headers->alg);
	}

out:
	if (signature)
		pv_signature_free(signature);
	if (headers)
		pv_signature_free_headers(headers);
	if (payload)
		free(payload);

	return res;
}
