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

#include <string.h>
#include <stdlib.h>

#include "phclient/creds.h"

#include "phclient/log.h"
#include "utils/json.h"
#include "utils/str.h"

void ph_creds_init(struct ph_creds *creds)
{
	if (!creds)
		return;

	memset(creds, 0, sizeof(*creds));
}

void ph_creds_free(struct ph_creds *creds)
{
	if (!creds)
		return;

	if (creds->host)
		free(creds->host);
	if (creds->id)
		free(creds->id);
	if (creds->type)
		free(creds->type);
	if (creds->prn)
		free(creds->prn);
	if (creds->secret)
		free(creds->secret);
	if (creds->proxy_host)
		free(creds->proxy_host);
}

static int _parse_config_entry(const char *json, struct ph_creds *creds)
{
	int tokc;
	jsmntok_t *tokv = NULL;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		ph_log(ERROR, "could not parse");
		goto err;
	}

	char *key = pv_json_get_value(json, "key", tokv, tokc);
	if (!key) {
		ph_log(WARN, "key not found");
		goto err;
	}

	char *value;
	if (pv_str_matches("PH_CREDS_HOST", key)) {
		creds->host = pv_json_get_value(json, "value", tokv, tokc);
	} else if (pv_str_matches("PH_CREDS_ID", key)) {
		creds->id = pv_json_get_value(json, "value", tokv, tokc);
	} else if (pv_str_matches("PH_CREDS_PORT", key)) {
		value = pv_json_get_value(json, "value", tokv, tokc);
		creds->port = atoi(value);
		free(value);
	} else if (pv_str_matches("PH_CREDS_TYPE", key)) {
		creds->type = pv_json_get_value(json, "value", tokv, tokc);
	} else if (pv_str_matches("PH_CREDS_PRN", key)) {
		creds->prn = pv_json_get_value(json, "value", tokv, tokc);
	} else if (pv_str_matches("PH_CREDS_SECRET", key)) {
		creds->secret = pv_json_get_value(json, "value", tokv, tokc);
	} else if (pv_str_matches("PH_CREDS_PROXY_HOST", key)) {
		creds->proxy_host =
			pv_json_get_value(json, "value", tokv, tokc);
	} else if (pv_str_matches("PH_CREDS_PROXY_PORT", key)) {
		value = pv_json_get_value(json, "value", tokv, tokc);
		creds->proxy_port = atoi(value);
		free(value);
	} else if (pv_str_matches("PH_CREDS_NOPROXYCONNECT", key)) {
		value = pv_json_get_value(json, "value", tokv, tokc);
		creds->noproxyconnect = atoi(value);
		free(value);
	}

	free(key);

	goto out;
err:
	if (key)
		free(key);
	if (tokv)
		free(tokv);

	return -1;
out:
	if (tokv)
		free(tokv);

	return 0;
}

int ph_creds_parse(const char *json, struct ph_creds *creds)
{
	if (!creds)
		return -1;

	int tokc, size;
	jsmntok_t *tokv = NULL, *t;
	char *str = NULL;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		ph_log(ERROR, "could not parse '%s'", json);
		goto err;
	}

	size = jsmnutil_array_count(json, tokv);
	if (size <= 0) {
		ph_log(ERROR, "empty config array");
		goto err;
	}

	t = tokv + 1;
	while ((str = pv_json_array_get_one_str(json, &size, &t))) {
		if (_parse_config_entry(str, creds) < 0) {
			ph_log(ERROR, "could not parse '%s'", str);
			goto err;
		}
		free(str);
		t += 6;
	}

	goto out;
err:
	if (str)
		free(str);
	if (tokv)
		free(tokv);
	ph_creds_free(creds);

	return -1;
out:
	if (tokv)
		free(tokv);

	return 0;
}

void ph_creds_print(struct ph_creds *creds)
{
	if (!creds)
		return;

	ph_log(DEBUG, "host: '%s'", creds->host);
	ph_log(DEBUG, "id: '%s'", creds->id);
	ph_log(DEBUG, "port: %d", creds->port);
	ph_log(DEBUG, "type: '%s'", creds->type);
	ph_log(DEBUG, "prn: '%s'", creds->prn);
	ph_log(DEBUG, "secret: '%s'", creds->secret);
	ph_log(DEBUG, "proxy_host: '%s'", creds->proxy_host);
	ph_log(DEBUG, "proxy_port: %d", creds->proxy_port);
	ph_log(DEBUG, "noproxyconnect: %d", creds->noproxyconnect);
}
