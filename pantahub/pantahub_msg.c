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

#include <stdlib.h>

#include <jsmn/jsmnutil.h>

#include "pantahub/pantahub_msg.h"

#include "utils/json.h"
#include "utils/str.h"

#define MODULE_NAME "pantahub_msg"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define AUTH_JSON_LEN 128

char *pv_pantahub_msg_ser_login_json(const char *user, const char *pass)
{
	if (!user || !pass)
		return NULL;

	struct pv_json_ser js;
	pv_json_ser_init(&js, AUTH_JSON_LEN);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "username");
		pv_json_ser_string(&js, user);
		pv_json_ser_key(&js, "password");
		pv_json_ser_string(&js, pass);
		pv_json_ser_object_pop(&js);
	}

	return pv_json_ser_str(&js);
}

char *pv_pantahub_msg_parse_session_token(const char *json)
{
	int tokc;
	jsmntok_t *tokv = NULL;
	char *token = NULL;

	if (!json)
		goto out;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		goto out;
	}

	token = pv_json_get_value(json, "token", tokv, tokc);

out:
	if (tokv)
		free(tokv);
	return token;
}

char *pv_pantahub_msg_parse_next_step(const char *json)
{
	int tokc, size;
	jsmntok_t *tokv = NULL, *t = NULL;
	char *state_json = NULL;

	if (!json)
		goto out;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(WARN, "bad formatted pending steps body JSON");
		goto out;
	}

	size = jsmnutil_array_count(json, tokv);
	if (size <= 0) {
		pv_log(DEBUG, "no pending revisions in Hub");
		goto out;
	}

	t = tokv + 1;
	state_json = pv_json_array_get_one_str(json, &size, &t);

out:
	if (tokv)
		free(tokv);
	return state_json;
}

int pv_pantahub_msg_parse_trails(const char *json)
{
	int ret = -1;
	int tokc, size;
	jsmntok_t *tokv = NULL;

	if (!json)
		goto out;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(WARN, "bad formatted trails body JSON");
		goto out;
	}

	size = jsmnutil_array_count(json, tokv);
	if (size <= 0) {
		pv_log(DEBUG, "no trails in Hub for this device");
		goto out;
	}

	ret = 0;
out:
	if (tokv)
		free(tokv);
	return ret;
}

void pv_pantahub_msg_parse_step(const char *json, struct pv_step *step)
{
	int tokc;
	jsmntok_t *tokv = NULL;
	char *rev = NULL;

	if (!json || !step)
		goto out;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(WARN, "bad formatted state JSON");
		goto out;
	}

	step->msg = pv_json_get_value(json, "commit-msg", tokv, tokc);
	step->progress = pv_json_get_value(json, "progress", tokv, tokc);
	step->rev = pv_json_get_value(json, "rev", tokv, tokc);
	step->state = pv_json_get_value(json, "state", tokv, tokc);

out:
	if (tokv)
		free(tokv);
}

void pv_pantahub_msg_print_step(struct pv_step *step)
{
	if (!step)
		return;

	pv_log(DEBUG, "next step received:");
	if (step->msg)
		pv_log(DEBUG, "  msg='%s'", step->msg);
	if (step->progress)
		pv_log(DEBUG, "  progress='%s'", step->progress);
	pv_log(DEBUG, "  rev='%s'", step->rev);
	if (step->state)
		pv_log(DEBUG, "  state='%s'", step->state);
}

void pv_pantahub_msg_clean_step(struct pv_step *step)
{
	if (!step)
		return;

	if (step->msg)
		free(step->msg);
	if (step->progress)
		free(step->progress);
	if (step->rev)
		free(step->rev);
	if (step->state)
		free(step->state);
}

void pv_pantahub_msg_parse_object_metadata(
	const char *json, struct pv_object_metadata *object_metadata)
{
	int tokc;
	jsmntok_t *tokv = NULL;
	char *size = NULL;

	if (!json || !object_metadata)
		goto out;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		pv_log(WARN, "bad formatted object metadata JSON");
		goto out;
	}

	object_metadata->sha256sum =
		pv_json_get_value(json, "sha256sum", tokv, tokc);

	size = pv_json_get_value(json, "size", tokv, tokc);
	if (size) {
		object_metadata->size = atoll(size);
		free(size);
	}

	object_metadata->geturl =
		pv_json_get_value(json, "signed-geturl", tokv, tokc);
	object_metadata->geturl = pv_str_unescape_utf8_to_apvii(
		object_metadata->geturl, "\\u0026", '&');

out:
	if (tokv)
		free(tokv);
}

void pv_pantahub_msg_print_object_metadata(
	struct pv_object_metadata *object_metadata)
{
	if (!object_metadata)
		return;

	pv_log(DEBUG, "object metadata received:");
	pv_log(DEBUG, "  size=%jd", object_metadata->size);
	if (object_metadata->sha256sum)
		pv_log(DEBUG, "  sha256sum='%s'", object_metadata->sha256sum);
	if (object_metadata->geturl)
		pv_log(DEBUG, "  signed-geturl='%s'", object_metadata->geturl);
}

void pv_pantahub_msg_clean_object_metadata(
	struct pv_object_metadata *object_metadata)
{
	if (!object_metadata)
		return;

	if (object_metadata->sha256sum)
		free(object_metadata->sha256sum);
	if (object_metadata->geturl)
		free(object_metadata->geturl);
}
