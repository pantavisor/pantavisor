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
#include <base64.h>

#include "signature.h"
#include "storage.h"
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
	signature->protected = pv_str_padding_multi4(signature->protected, '=');

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
	int tokc;
	jsmntok_t *tokv = NULL;

	headers = calloc(1, sizeof(struct pv_signature_headers));
	if (!headers) {
		pv_log(ERROR, "could not alloc signature headers");
		goto out;
	}

	json = base64_decode (protected);
	if (!json) {
		pv_log(ERROR, "protected value could not be decoded");
		goto err;
	}

	pv_log(DEBUG, "decoded headers %s", json);

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

static void pv_signature_parse_globs(const char *json)
{
	char *str;
	int tokc, size;
	jsmntok_t *tokv, *t;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(ERROR, "wrong format include");
		goto out;
	}

	size = jsmnutil_array_count(json, tokv);
	if (size <= 0) {
		pv_log(ERROR, "empty include");
		goto out;
	}

	pv_log(DEBUG, "include globs:");
	t = tokv+1;
	while ((str = pv_json_array_get_one_str(json, &size, &t))) {
		pv_log(DEBUG, "%s", str);
		free(str);
	}

out:
	if (tokv)
		free(tokv);
}

static int pv_signature_fillup_globs(struct pv_signature_headers_pvs *pvs)
{
	pv_signature_parse_globs(pvs->include);
	pv_signature_parse_globs(pvs->exclude);

	// parse include
	// for glob in include
		// if glob is **
			// for glob in part
				// check glob not in globs
					// add glob to globs
		// else
			// check glob in part and not in globs
				// add glob to globs

	// parse exclude
	// for glob in exclude
		// if glob is **
			// remove everything from globs
			// return 0
		// else
			// check glob in globs
				// remove glob from globs

	return 0;
}

bool pv_signature_verify(struct pv_state *s, const char *name, const char *json)
{
	struct pv_signature *signature = NULL;
	struct pv_signature_headers *headers = NULL;

	pv_log(DEBUG, "verifying signature of component %s", name);

	signature = pv_signature_parse_pvs(json);
	if (!signature) {
		pv_log(ERROR, "could not parse pvr.json");
		goto out;
	}

	pv_log(DEBUG, "parsed pvs.json with protected %s", signature->protected);
	pv_log(DEBUG, "parsed pvs.json with signature %s", signature->signature);

	headers = pv_signature_parse_protected(signature->protected);
	if (!headers) {
		pv_log(ERROR, "could not parse protected json");
		goto out;
	}

	pv_log(DEBUG, "parsed protected with alg %s", headers->alg);
	pv_log(DEBUG, "parsed protected with part %s", headers->pvs->part);
	pv_log(DEBUG, "parsed protected with include %s", headers->pvs->include);
	pv_log(DEBUG, "parsed protected with exclude %s", headers->pvs->exclude);

	if (!pv_str_matches(name, strlen(name), headers->pvs->part, strlen(headers->pvs->part))) {
		pv_log(ERROR, "protected part does not match with platform name");
		goto out;
	}

	if (pv_signature_fillup_globs(headers->pvs) <= 0) {
		pv_log(ERROR, "could not get signature globs");
		goto out;
	}

	// calculate signature from list of globs, alg and pub key
	// verify signature

out:
	if (signature)
		pv_signature_free(signature);
	if (headers)
		pv_signature_free_headers(headers);

	return false;
}
