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
#include "utils/json.h"
#include "utils/str.h"

#define MODULE_NAME             "signature"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define SPEC_PVS1 "pvs@1"

struct pv_signature* pv_signature_parse(const char *json)
{
	struct pv_signature* signature = NULL;
	int tokc, len;
	jsmntok_t *tokv = NULL;
	char *spec = NULL, *protected = NULL;

	signature = calloc(1, sizeof(struct pv_signature));
	if (signature) {
		jsmnutil_parse_json(json, &tokv, &tokc);

		spec = pv_json_get_value(json, "#spec", tokv, tokc);
		if (!pv_str_matches(spec, strlen(spec), SPEC_PVS1, strlen(SPEC_PVS1))) {
			pv_log(ERROR, "wrong spec %s", spec);
			goto error;
		}

		protected = pv_json_get_value(json, "protected", tokv, tokc);
		if (!protected) {
			pv_log(ERROR, "no protected key found");
			goto error;
		}
		len = strlen(protected) + 1;

		signature->header = calloc(1, b64d_size(len));
		if (!signature->header) {
			pv_log(ERROR, "could not alloc header");
			goto error;
		}

		if (!b64_decode((unsigned char*)protected, len, (unsigned char*)signature->header)) {
			pv_log(ERROR, "protected value could not be decoded");
			goto error;
		}

		signature->value = pv_json_get_value(json, "signature", tokv, tokc);
		if (!signature->value) {
			pv_log(ERROR, "no signature key found");
			goto error;
		}
	} else
		pv_log(ERROR, "could not alloc signature");

	goto out;

error:
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

void pv_signature_free(struct pv_signature *signature)
{
	if (!signature)
		return;

	if (signature->header)
		free(signature->header);
	if (signature->value)
		free(signature->value);
}

bool pv_signature_verify(const struct pv_signature *signature)
{
	return true;
}
