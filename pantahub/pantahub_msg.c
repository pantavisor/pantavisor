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

#include <jsmn/jsmnutil.h>

#include "pantahub/pantahub_msg.h"

#include "utils/json.h"

#define MODULE_NAME "pantahub_msg"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define AUTH_JSON_LEN 128

char *pv_pantahub_msg_ser_login_json(const char *user, const char *pass)
{
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

void pv_pantahub_msg_parse_step(const char *json, pv_step_t *step)
{
	int tokc;
	jsmntok_t *tokv = NULL;
	char *rev = NULL;

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

void pv_pantahub_msg_print_step(pv_step_t *step)
{
	pv_log(DEBUG, "next step received:");
	if (step->msg)
		pv_log(DEBUG, "  msg='%s'", step->msg);
	if (step->progress)
		pv_log(DEBUG, "  progress='%s'", step->progress);
	pv_log(DEBUG, "  rev='%s'", step->rev);
	if (step->state)
		pv_log(DEBUG, "  state='%s'", step->state);
}

void pv_pantahub_msg_clean_step(pv_step_t *step)
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
