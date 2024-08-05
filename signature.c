/*
 * Copyright (c) 2021-2022 Pantacor Ltd.
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

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <libgen.h>
#include <fnmatch.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>

#include <jsmn/jsmnutil.h>

#include "signature.h"
#include "paths.h"
#include "utils/json.h"
#include "utils/str.h"
#include "utils/base64.h"

#define MODULE_NAME "signature"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define SPEC_PVS2 "pvs@2"
#define TYP_PVS "PVS"

struct pv_signature_headers_pvs {
	char *include;
	char *exclude;
};

struct pv_signature_headers {
	char *alg;
	char *x5c;
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
	bool oem_signable;
	struct dl_list list; // pv_signature_pair
};

struct pv_signature_cert_raw {
	char *content;
	struct dl_list list; // pv_signature_cert_raw
};

static void pv_signature_free_headers_pvs(struct pv_signature_headers_pvs *pvs)
{
	if (!pvs)
		return;

	if (pvs->include)
		free(pvs->include);
	if (pvs->exclude)
		free(pvs->exclude);

	free(pvs);
}

static void pv_signature_free_headers(struct pv_signature_headers *headers)
{
	if (!headers)
		return;

	pv_signature_free_headers_pvs(headers->pvs);

	if (headers->alg)
		free(headers->alg);
	if (headers->x5c)
		free(headers->x5c);

	free(headers);
}

static void pv_signature_free(struct pv_signature *signature)
{
	if (!signature)
		return;

	if (signature->protected)
		free(signature->protected);
	if (signature->signature)
		free(signature->signature);
	free(signature);
}
static void pv_signature_free_cert_raw(struct pv_signature_cert_raw *cert_raw)
{
	if (!cert_raw)
		return;

	if (cert_raw->content)
		free(cert_raw->content);
	free(cert_raw);
}

static void pv_signature_free_certs_raw(struct dl_list *certs_raw)
{
	struct pv_signature_cert_raw *c, *tmp;

	dl_list_for_each_safe(c, tmp, certs_raw, struct pv_signature_cert_raw,
			      list)
	{
		dl_list_del(&c->list);
		pv_signature_free_cert_raw(c);
	}
}

static struct pv_signature *pv_signature_parse_pvs(const char *json)
{
	struct pv_signature *signature = NULL;
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

static struct pv_signature_headers_pvs *
pv_signature_parse_headers_pvs(const char *json)
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

static struct pv_signature_headers *
pv_signature_parse_protected(char *protected)
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
		pv_log(ERROR, "protected value could not be decoded '%s'",
		       protected);
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

	headers->x5c = pv_json_get_value(json, "x5c", tokv, tokc);

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
	if (pvs)
		free(pvs);
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

	free(file);
}

static void pv_signature_free_pairs(struct dl_list *json_pairs)
{
	struct pv_signature_pair *f, *tmp;

	dl_list_for_each_safe(f, tmp, json_pairs, struct pv_signature_pair,
			      list)
	{
		dl_list_del(&f->list);
		pv_signature_free_pair(f);
	}
}

static void _include_json_pair(bool include, struct pv_signature_pair *pair)
{
	pair->included = include;
	pair->covered = true;
}

static void _filter_json(
	const char *json, bool include, struct dl_list *json_pairs,
	void (*action_json_pair)(bool include, struct pv_signature_pair *pair))
{
	char *str = NULL, *path = NULL, *path_buf = NULL;
	int tokc, size;
	jsmntok_t *tokv, *t;
	int fnflags;
	struct pv_signature_pair *pair, *tmp;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format filter");
		goto out;
	}

	size = jsmnutil_array_count(json, tokv);
	if (size <= 0) {
		pv_log(ERROR, "empty signature array");
		goto out;
	}

	t = tokv + 1;
	while ((str = pv_json_array_get_one_str(json, &size, &t))) {
		fnflags = FNM_PATHNAME;

		if (pv_str_matches("**", 2, str, strlen(str))) {
			path_buf = strdup("");
			path = path_buf;
			fnflags |= FNM_LEADING_DIR;
		} else if (pv_str_endswith("/**", strlen("/**"), str,
					   strlen(str))) {
			// if ** is in include, set path for fnmatch w/ FNM_LEADING_DIR
			path_buf = strdup(str);
			path = dirname(path_buf);
			fnflags |= FNM_LEADING_DIR;
		} else {
			// boaring dup
			path_buf = strdup(str);
			path = path_buf;
		}

		// if none of the above, include the pair that matches
		dl_list_for_each_safe(pair, tmp, json_pairs,
				      struct pv_signature_pair, list)
		{
			if (!fnmatch(path, pair->key, fnflags)) {
				action_json_pair(include, pair);
			}
		}

		if (str) {
			free(str);
			str = NULL;
		}
		if (path_buf) {
			free(path_buf);
			path = NULL;
		}
	}

out:
	if (str)
		free(str);
	if (tokv)
		free(tokv);
}

static void pv_signature_include_files(const char *json, bool include,
				       struct dl_list *json_pairs)
{
	if (include) {
		pv_log(DEBUG, "including '%s'", json);
	} else {
		pv_log(DEBUG, "excluding '%s'", json);
	}

	_filter_json(json, include, json_pairs, _include_json_pair);
}

static void _init_json_pairs(struct dl_list *json_pairs)
{
	struct pv_signature_pair *pair, *tmp;

	dl_list_for_each_safe(pair, tmp, json_pairs, struct pv_signature_pair,
			      list)
	{
		pair->included = false;
		pair->oem_signable = true;
	}
}

static void pv_signature_filter_files(struct pv_signature_headers_pvs *pvs,
				      struct dl_list *json_pairs)
{
	pv_signature_include_files(pvs->include, true, json_pairs);
	pv_signature_include_files(pvs->exclude, false, json_pairs);
}

static bool pv_signature_get_certs_raw(const char *x5c,
				       struct dl_list *certs_raw)
{
	bool ret = false;
	char *str = NULL;
	int tokc, size;
	jsmntok_t *tokv, *t;
	struct pv_signature_cert_raw *cert_raw;

	// x5c field is optional
	if (!x5c)
		return true;

	if (jsmnutil_parse_json(x5c, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format x5c");
		goto out;
	}

	size = jsmnutil_array_count(x5c, tokv);
	if (size <= 0) {
		pv_log(ERROR, "empty x5c");
		goto out;
	}

	pv_log(DEBUG, "x5c found containing %d certificates", size);

	t = tokv + 1;
	while ((str = pv_json_array_get_one_str(x5c, &size, &t))) {
		cert_raw = calloc(1, sizeof(struct pv_signature_cert_raw));
		if (!cert_raw)
			goto out;

		cert_raw->content = str;
		dl_list_add_tail(certs_raw, &cert_raw->list);
	}

	ret = true;

out:
	if (tokv)
		free(tokv);
	return ret;
}

static char **pv_signature_concatenate_json_pairs(struct dl_list *pairs,
						  int *len, int *n_pairs)
{
	*len = 0;
	int n = 0;
	char *tmpl = NULL;
	char **kv = calloc(dl_list_len(pairs), sizeof(char *));

	struct pv_signature_pair *it, *tmp;
	dl_list_for_each_safe(it, tmp, pairs, struct pv_signature_pair, list)
	{
		if (!it->included)
			continue;

		if (it->value[0] == '{' || it->value[0] == '[')
			tmpl = "\"%s\":%s";
		else
			tmpl = "\"%s\":\"%s\"";

		int l = snprintf(NULL, 0, tmpl, it->key, it->value);
		kv[n] = calloc(l + 1, sizeof(char));
		snprintf(kv[n], l + 1, tmpl, it->key, it->value);
		*len += l;
		++n;
	}

	*n_pairs = n;

	return kv;
}

static char *pv_signature_get_json_files(struct dl_list *json_pairs)
{
	int len = 0;
	int n_pairs = 0;
	char **kv =
		pv_signature_concatenate_json_pairs(json_pairs, &len, &n_pairs);

	// len + {} + commas + trailing 0
	char *js = calloc(len + 2 + n_pairs - 1 + 1, sizeof(char));
	if (!js)
		return NULL;

	size_t count = 1;
	strncpy(js, "{", count + 1);
	for (int i = 0; i < n_pairs; ++i) {
		snprintf(js + count, strlen(kv[i]) + 2, "%s,", kv[i]);
		count += strlen(kv[i]) + 1;
		free(kv[i]);
	}
	strncpy(js + count - 1, "}", 2);
	free(kv);

	return js;
}

static char *
pv_signature_get_filtered_json(struct pv_signature_headers_pvs *pvs,
			       struct dl_list *json_pairs)
{
	_init_json_pairs(json_pairs);
	pv_signature_filter_files(pvs, json_pairs);
	return pv_signature_get_json_files(json_pairs);
}

static int pv_signature_print_cert(void *data, mbedtls_x509_crt *crt, int depth,
				   uint32_t *flags)
{
	// this callback is intentianally empty
	// but it could be used to get info about the certs into the logs
	return 0;
}

static void _print_certs(struct mbedtls_x509_crt *certs)
{
	struct mbedtls_x509_crt *certs_i = certs;
	int i = 0;
	char serial[256], subject[256];

	do {
		i++;
		pv_log(INFO, "  %d:", i);
		mbedtls_x509_serial_gets(serial, 255, &certs_i->serial);
		pv_log(INFO, "    serial='%s'", serial);
		mbedtls_x509_dn_gets(subject, 255, &certs_i->subject);
		pv_log(INFO, "    subject='%s'", subject);
	} while ((certs_i = certs_i->next) != 0);
}

static int _parse_certs(struct dl_list *certs_raw,
			struct mbedtls_x509_crt *certs)
{
	struct pv_signature_cert_raw *cert_raw, *tmp;
	char *content = NULL;
	size_t olen;
	int res, ret = -1;

	pv_log(DEBUG, "parsing x509 certificates from x5c raw data");

	mbedtls_x509_crt_init(certs);

	dl_list_for_each_safe(cert_raw, tmp, certs_raw,
			      struct pv_signature_cert_raw, list)
	{
		if (pv_base64_decode(cert_raw->content, &content, &olen)) {
			pv_log(ERROR, "cert could not be decoded");
			goto out;
		}

		res = mbedtls_x509_crt_parse_der(
			certs, (const unsigned char *)content, olen);
		if (res) {
			pv_log(ERROR, "cert could not be parsed: %d", res);
			goto out;
		}

		if (content) {
			free(content);
			content = NULL;
		}
	}

	pv_log(INFO, "validation signature certificate chain:");
	_print_certs(certs);

	ret = 0;

out:
	if (content)
		free(content);

	return ret;
}

static int _get_cn(struct mbedtls_x509_crt *cert, char *cn, int len)
{
	mbedtls_x509_name *name = &cert->subject;

	do {
		const char *oid_name;
		if ((!mbedtls_oid_get_attr_short_name(&name->oid, &oid_name)) &&
		    (pv_str_matches("CN", strlen("CN"), oid_name,
				    strlen(oid_name)))) {
			SNPRINTF_WTRUNC(cn, len, "%.*s", name->val.len,
					name->val.p);
		}
	} while ((name = name->next) != 0);
}

static int _set_path_trust_crts(struct mbedtls_x509_crt *certs,
				bool oem_signable, char *path)
{
	config_index_t name = PV_SECUREBOOT_TRUSTSTORE;

	char *oem_name = pv_config_get_str(PV_OEM_NAME);
	if (oem_signable && oem_name) {
		char cert_cn[256];
		_get_cn(certs, cert_cn, 256);

		if (pv_str_matches(oem_name, strlen(oem_name), cert_cn,
				   strlen(cert_cn)))
			name = PV_SECUREBOOT_OEM_TRUSTORE;
	}

	pv_paths_secureboot_trust_crts(path, PATH_MAX, pv_config_get_str(name));
}

static int _load_trust_certs(const char *path, struct mbedtls_x509_crt *cacerts)
{
	int res, ret = -1;

	pv_log(DEBUG, "parsing x509 certificates from %s", path);

	mbedtls_x509_crt_init(cacerts);

	res = mbedtls_x509_crt_parse_file(cacerts, path);
	if (res) {
		pv_log(ERROR, "ca certs could not be parsed: %d", res);
		mbedtls_x509_crt_free(cacerts);
		return ret;
	}

	pv_log(INFO, "loaded truststore x509 certificate chain:");
	_print_certs(cacerts);

	ret = 0;

	return ret;
}

static int _parse_validate_certs(struct dl_list *certs_raw, bool oem_signable,
				 struct mbedtls_x509_crt *certs)
{
	int ret = -1;

	if (_parse_certs(certs_raw, certs)) {
		pv_log(ERROR, "could not parse raw certs");
		goto out;
	}

	char path[PATH_MAX];
	_set_path_trust_crts(certs, oem_signable, path);

	struct mbedtls_x509_crt cacerts;
	if (_load_trust_certs(path, &cacerts)) {
		pv_log(ERROR, "could not load trust certs");
		goto out;
	}

	unsigned int flags;
	int res;
	res = mbedtls_x509_crt_verify(certs, &cacerts, NULL, NULL, &flags,
				      pv_signature_print_cert, NULL);
	if (res) {
		pv_log(ERROR, "cert chain could not be verified %d", res);
		goto out;
	}

	ret = 0;
out:
	mbedtls_x509_crt_free(&cacerts);

	return ret;
}

static int pv_signature_load_pk(struct mbedtls_pk_context **pk)
{
	int ret = -1, res;
	char path[PATH_MAX];

	*pk = calloc(1, sizeof(struct mbedtls_pk_context));
	if (!*pk)
		goto out;

	mbedtls_pk_init(*pk);

	pv_paths_etc_file(path, PATH_MAX, PVS_PK_FNAME);
	pv_log(DEBUG, "parsing public key from %s", path);
	res = mbedtls_pk_parse_public_keyfile(*pk, path);
	if (res) {
		pv_log(ERROR, "cannot read public key %d", res);
		goto out;
	}

	ret = 0;
out:
	return ret;
}

static int pv_signature_validate_pk(struct mbedtls_pk_context *pk)
{
	int ret = -1;
	mbedtls_pk_type_t pktype;
	pktype = mbedtls_pk_get_type(pk);

	switch (pktype) {
	case MBEDTLS_PK_ECDSA:
		pv_log(DEBUG, "public key type is MBEDTLS_PK_ECDSA");
		break;
	case MBEDTLS_PK_ECKEY:
		pv_log(DEBUG, "public key type is MBEDTLS_PK_ECKEY");
		break;
	case MBEDTLS_PK_RSA:
		pv_log(DEBUG, "public key type is MBEDTLS_PK_RSA");
		break;
	default:
		pv_log(ERROR, "public key type is not supported: %d", pktype);
		goto out;
	}

	if (!mbedtls_pk_can_do(pk, pktype)) {
		pv_log(ERROR, "pvs public key is not supported");
		goto out;
	}

	pv_log(INFO, "pvs public key is supported");

	ret = 0;
out:
	return ret;
}

static bool pv_signature_verify_sha(const char *payload,
				    struct dl_list *certs_raw,
				    struct pv_signature *signature,
				    mbedtls_md_type_t mdtype, bool oem_signable)
{
	bool ret = false;
	int res;
	struct mbedtls_x509_crt certs;
	size_t olen, plen, elen, payload_len;
	char *payload_encoded = NULL, *files_encoded = NULL,
	     *sig_decoded = NULL;
	unsigned char *hash = NULL;
	struct mbedtls_pk_context *pk = NULL;

	pv_log(DEBUG, "using PVS verify with sha");

	if (!dl_list_empty(certs_raw)) {
		// if list is not empty, we verify with pub key from first cert
		if (_parse_validate_certs(certs_raw, oem_signable, &certs)) {
			pv_log(ERROR, "certs could not be parsed");
			goto out;
		}
		pk = &certs.pk;
	} else {
		// if not, we load it from disk
		if (pv_signature_load_pk(&pk)) {
			pv_log(ERROR, "public key could not be loaded");
			goto out;
		}
	}

	if (!pk) {
		pv_log(ERROR, "public key could not be initialized");
		goto out;
	}

	if (pv_signature_validate_pk(pk)) {
		pv_log(ERROR, "public key could not be validated");
		goto out;
	}

	if (pv_base64_url_encode(payload, &files_encoded, &olen)) {
		pv_log(ERROR, "payload could not be encoded");
		goto out;
	}

	if (!signature->protected)
		goto out;

	elen = strlen(files_encoded);
	plen = strlen(signature->protected);
	payload_len = elen + plen + 2;

	payload_encoded = calloc(payload_len, sizeof(char));

	strncpy(payload_encoded, signature->protected, payload_len);
	strncat(payload_encoded, ".", 2);
	strncat(payload_encoded, files_encoded, payload_len - plen + 2);

	hash = calloc(128, sizeof(unsigned char));
	if (!hash) {
		pv_log(ERROR, "cannot allocate hash");
		goto out;
	}

	res = mbedtls_md(mbedtls_md_info_from_type(mdtype),
			 (unsigned char *)payload_encoded,
			 strlen(payload_encoded), hash);
	if (res) {
		pv_log(ERROR,
		       "cannot create hash with code %d for payload '%s'", res,
		       payload_encoded);
		goto out;
	}

	if (pv_base64_url_decode(signature->signature, &sig_decoded, &olen)) {
		pv_log(ERROR, "signature could not be decoded '%s'",
		       signature->signature);
		goto out;
	}

	pv_log(DEBUG, "signature length is %d", olen);

	res = mbedtls_pk_verify(pk, mdtype, hash, 0,
				(unsigned char *)sig_decoded, olen);
	if (res) {
		pv_log(ERROR, "verification returned error code %d", res);
		goto out;
	}

	pv_log(DEBUG, "signature OK");
	ret = true;

out:
	if (payload_encoded)
		free(payload_encoded);
	if (files_encoded)
		free(files_encoded);
	if (sig_decoded)
		free(sig_decoded);
	if (hash)
		free(hash);
	if (!dl_list_empty(certs_raw))
		mbedtls_x509_crt_free(&certs);
	else
		mbedtls_pk_free(pk);
	return ret;
}

static void pv_signature_parse_json(const char *json,
				    struct dl_list *json_pairs)
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
	while (k && *k) {
		n = (*k)->end - (*k)->start;

		pair = calloc(1, sizeof(struct pv_signature_pair));
		if (!pair)
			goto out;

		// copy key
		pair->key = calloc(n + 1, sizeof(char));
		if (!pair->key) {
			pv_signature_free_pair(pair);
			goto out;
		}
		snprintf(pair->key, n + 1, "%s", json + (*k)->start);

		// copy value
		n = (*k + 1)->end - (*k + 1)->start;
		pair->value = calloc(n + 1, sizeof(char));
		if (!pair->value) {
			pv_signature_free_pair(pair);
			goto out;
		}

		snprintf(pair->value, n + 1, "%s", json + (*k + 1)->start);

		dl_list_add_tail(json_pairs, &pair->list);

		k++;
	}

out:
	if (keys)
		jsmnutil_tokv_free(keys);
	if (tokv)
		free(tokv);
}

void _unset_oem_signable_json_pair(bool include, struct pv_signature_pair *pair)
{
	pair->oem_signable = false;
}

#define OEM_NON_SIGNABLE_FMT "[\"bsp/**\",\"%s/**\"]"
#define OEM_NON_SIGNABLE_BSP "[\"bsp/**\"]"

static bool _is_oem_signable(struct dl_list *json_pairs)
{
	char json[256];
	char *oem_name = pv_config_get_str(PV_OEM_NAME);
	if (oem_name)
		SNPRINTF_WTRUNC(json, 256, OEM_NON_SIGNABLE_FMT, oem_name);
	else
		SNPRINTF_WTRUNC(json, 256, OEM_NON_SIGNABLE_BSP);
	pv_log(DEBUG, "filtering OEM-signable '%s'", json);

	_filter_json(json, false, json_pairs, _unset_oem_signable_json_pair);

	bool oem_signable = true;
	struct pv_signature_pair *pair, *tmp;
	dl_list_for_each_safe(pair, tmp, json_pairs, struct pv_signature_pair,
			      list)
	{
		if ((pair->included) && !(pair->oem_signable)) {
			oem_signable = false;
			pv_log(DEBUG, "detected '%s' as non OEM-signable",
			       pair->key);
		}
	}

	return oem_signable;
}

static bool pv_signature_verify_pvs(struct pv_signature *signature,
				    struct dl_list *json_pairs)
{
	bool ret = false;
	char *payload = NULL;
	struct pv_signature_headers *headers = NULL;
	struct dl_list certs_raw; // pv_signature_cert_raw
	mbedtls_md_type_t mdtype = MBEDTLS_MD_NONE;

	dl_list_init(&certs_raw);

	headers = pv_signature_parse_protected(signature->protected);
	if (!headers) {
		pv_log(ERROR, "could not parse protected JSON");
		goto out;
	}

	// parse x5c value into list of base64 encoded certificates
	if (!pv_signature_get_certs_raw(headers->x5c, &certs_raw)) {
		pv_log(ERROR, "could not parse certs");
		goto out;
	}

	payload = pv_signature_get_filtered_json(headers->pvs, json_pairs);
	if (!payload) {
		pv_log(ERROR, "could not get signature payload");
		goto out;
	}

	pv_log(DEBUG, "filtered json '%s'", payload);

	if (pv_str_matches(headers->alg, strlen(headers->alg), "RS256",
			   strlen("RS256")) ||
	    pv_str_matches(headers->alg, strlen(headers->alg), "ES256",
			   strlen("ES256"))) {
		mdtype = MBEDTLS_MD_SHA256;
	} else if (pv_str_matches(headers->alg, strlen(headers->alg), "ES384",
				  strlen("ES384"))) {
		mdtype = MBEDTLS_MD_SHA384;
	} else if (pv_str_matches(headers->alg, strlen(headers->alg), "ES512",
				  strlen("ES512"))) {
		mdtype = MBEDTLS_MD_SHA512;
	} else {
		pv_log(ERROR, "unknown algorithm in protected JSON %s",
		       headers->alg);
	}

	bool signable_oem = _is_oem_signable(json_pairs);

	if (mdtype > 0)
		ret = pv_signature_verify_sha(payload, &certs_raw, signature,
					      mdtype, signable_oem);
out:
	pv_signature_free_certs_raw(&certs_raw);
	if (headers)
		pv_signature_free_headers(headers);
	if (payload)
		free(payload);
	return ret;
}

static sign_state_res_t pv_signature_verify_pairs(struct dl_list *json_pairs)
{
	bool found = false;
	sign_state_res_t ret = SIGN_STATE_OK;
	struct pv_signature_pair *pair, *tmp;
	struct pv_signature *signature = NULL;

	dl_list_for_each_safe(pair, tmp, json_pairs, struct pv_signature_pair,
			      list)
	{
		signature = pv_signature_parse_pvs(pair->value);
		if (signature) {
			found = true;
			pv_log(DEBUG, "%s found", pair->key);
			if (!pv_signature_verify_pvs(signature, json_pairs)) {
				ret = SIGN_STATE_NOK_VALIDATION;
			}

			pv_signature_free(signature);
			signature = NULL;
		}
	}

	if (!found)
		pv_log(DEBUG, "no JSON with %s specification found in revision",
		       SPEC_PVS2);

	return ret;
}

static bool pv_signature_all_covered(struct dl_list *json_pairs)
{
	bool ret = true;
	struct pv_signature_pair *pair, *tmp;

	pv_log(DEBUG,
	       "checking all state JSON items are covered by signatures");

	dl_list_for_each_safe(pair, tmp, json_pairs, struct pv_signature_pair,
			      list)
	{
		// skip everything in the _sigs folder
		if (pv_str_startswith("_sigs/", strlen("_sigs/"), pair->key))
			continue;
		if (!pair->covered) {
			pv_log(ERROR, "%s is not covered by any signature",
			       pair->key);
			ret = false;
		}
	}

	if (ret)
		pv_log(DEBUG, "state JSON coverage OK");

	return ret;
}

sign_state_res_t pv_signature_verify(const char *json)
{
	struct dl_list json_pairs; // pv_signature_pair
	secureboot_mode_t mode = pv_config_get_secureboot_mode();

	if (!json)
		return SIGN_STATE_NOK_INTERNAL;

	if (mode == SB_DISABLED)
		return SIGN_STATE_OK;

	pv_log(DEBUG, "verifying signatures of state JSON");

	dl_list_init(&json_pairs);

	pv_signature_parse_json(json, &json_pairs);

	sign_state_res_t ret;
	ret = pv_signature_verify_pairs(&json_pairs);

	if ((ret == SIGN_STATE_OK) && (mode == SB_STRICT || mode == SB_AUDIT) &&
	    !pv_signature_all_covered(&json_pairs)) {
		pv_log(ERROR, "not all state elements were covered");
		ret = SIGN_STATE_NOK_UNCOVERED;
	}

	if ((ret == SIGN_STATE_NOK_UNCOVERED) && (mode == SB_AUDIT)) {
		ret = SIGN_STATE_OK;
		pv_log(WARN,
		       "in secureboot audit mode, so we will pass the bad signatures as good ones");
	}

	pv_signature_free_pairs(&json_pairs);
	return ret;
}

const char *pv_signature_sign_state_str(sign_state_res_t sres)
{
	switch (sres) {
	case SIGN_STATE_NOK_INTERNAL:
		return "Internal error";
	case SIGN_STATE_NOK_UNCOVERED:
		return "State not fully covered by signatures";
	case SIGN_STATE_NOK_VALIDATION:
		return "Signature validation failed";
	default:
		return "Unknown error";
	}

	return "Unknown error";
}
