/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>
#include <inttypes.h>

#include <thttp.h>
#include <mbedtls/sha256.h>

#include <jsmn/jsmnutil.h>

#include "trestclient.h"
#include "updater.h"
#include "paths.h"
#include "utils/fs.h"
#include "utils/str.h"
#include "objects.h"
#include "parser/parser.h"
#include "bootloader.h"
#include "pantahub.h"
#include "storage.h"
#include "wdt.h"
#include "init.h"
#include "bootloader.h"
#include "parser/parser_bundle.h"
#include "state.h"
#include "json.h"
#include "file.h"
#include "signature.h"

#define MODULE_NAME			"updater"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define VOLATILE_TMP_OBJ_PATH "/tmp/object-XXXXXX"
#define MMC_TMP_OBJ_FMT "%s.tmp"

typedef int (*token_iter_f) (void *d1, void *d2, char *buf, jsmntok_t* tok, int c);

void pv_update_free(struct pv_update *update)
{
	if (!update)
		return;

	pv_log(DEBUG, "removing update");

	if (update->endpoint)
		free(update->endpoint);
	if (update->pending) {
		pv_state_free(update->pending);
		update->pending = NULL;
	}
	if (update->progress_objects)
		free(update->progress_objects);

	if (update->total_update)
		free(update->total_update);

	free(update);
}

static void pv_update_remove(struct pantavisor *pv)
{
	// do not remove state if the one update is the same currently running
	if (pv->update->pending == pv->state)
		pv->update->pending = NULL;
	pv_update_free(pv->update);
	pv->update = NULL;
}

// takes an allocated buffer
static char *unescape_utf8_to_apvii(char *buf, char *code, char c)
{
	char *p = 0;
	char *new = 0;
	char *old;
	int pos = 0, replaced = 0;
	char *tmp;

	tmp = malloc(strlen(buf) + strlen(code) + 1);
	strcpy(tmp, buf);
	strcat(tmp, code);
	old = tmp;

	p = strstr(tmp, code);
	while (p) {
		*p = '\0';
		new = realloc(new, pos + strlen(tmp) + 2);
		strcpy(new+pos, tmp);
		pos = pos + strlen(tmp);
		new[pos] = c;
		pos += 1;
		new[pos] = '\0';
		replaced += 1;
		tmp = p+strlen(code);
		p = strstr(tmp, code);
	}

	if (new[strlen(new)-1] == c)
		new[strlen(new)-1] = '\0';

	if (old)
		free(old);
	if (buf)
		free(buf);

	return new;
}

static int trail_remote_init(struct pantavisor *pv)
{
	struct trail_remote *remote = NULL;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_ptr client = 0;
	char *endpoint_trail = NULL;
	int size = -1;

	if (pv->remote ||
		!pv_config_get_creds_id())
		return 0;

	client = pv_get_trest_client(pv, NULL);

	if (!client) {
		pv_log(INFO, "unable to create device client");
		goto err;
	}

	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "unable to auth device client");
		goto err;
	}

	remote = calloc(1, sizeof(struct trail_remote));
	remote->client = client;

	size = sizeof(DEVICE_TRAIL_ENDPOINT_FMT) + strlen(pv_config_get_creds_id());
	endpoint_trail = malloc(size * sizeof(char));
	if (!endpoint_trail)
		goto err;
	SNPRINTF_WTRUNC(endpoint_trail, size, DEVICE_TRAIL_ENDPOINT_FMT, pv_config_get_creds_id());

	size = strlen(endpoint_trail) + sizeof(DEVICE_TRAIL_ENDPOINT_QUEUED);

	remote->endpoint_trail_queued = (char*) calloc(sizeof (char), size);
	if (!remote->endpoint_trail_queued)
		goto err;
	SNPRINTF_WTRUNC(remote->endpoint_trail_queued,
			size,
			"%s%s",
			endpoint_trail, DEVICE_TRAIL_ENDPOINT_QUEUED);

	size = strlen(endpoint_trail) + sizeof(DEVICE_TRAIL_ENDPOINT_NEW);

	remote->endpoint_trail_new = (char*) calloc(sizeof (char), size);
	if (!remote->endpoint_trail_new)
		goto err;
	SNPRINTF_WTRUNC(remote->endpoint_trail_new, size, "%s%s", endpoint_trail, DEVICE_TRAIL_ENDPOINT_NEW);

	size = strlen(endpoint_trail) + sizeof(DEVICE_TRAIL_ENDPOINT_DOWNLOADING);
	remote->endpoint_trail_downloading = (char*)calloc(1, size);
	if (!remote->endpoint_trail_downloading)
		goto err;
	SNPRINTF_WTRUNC(remote->endpoint_trail_downloading, size, "%s%s", endpoint_trail, DEVICE_TRAIL_ENDPOINT_DOWNLOADING);

	size = strlen(endpoint_trail) + sizeof (DEVICE_TRAIL_ENDPOINT_INPROGRESS);
	remote->endpoint_trail_inprogress = (char*)calloc(1, size);
	if (!remote->endpoint_trail_inprogress)
		goto err;
	SNPRINTF_WTRUNC(remote->endpoint_trail_inprogress, size, "%s%s",
			endpoint_trail, DEVICE_TRAIL_ENDPOINT_INPROGRESS);

	pv->remote = remote;

	return 0;

err:
	if (client)
		free(client);
	if (remote)
		free(remote);
	if (endpoint_trail)
		free(endpoint_trail);

	return -1;
}

static void object_update_json(struct object_update *object_update,
		char *buffer, ssize_t buflen)
{
	buflen -= snprintf(buffer, buflen,
			"{\"object_name\":\"%s\""
			",\"object_id\":\"%s\""
			",\"total_size\":%"PRIu64
			",\"start_time\":%"PRIu64
			",\"current_time\":%"PRIu64
			",\"total_downloaded\":%"PRIu64
			"}"
			,
			object_update->object_name,
			object_update->object_id,
			object_update->total_size,
			object_update->start_time,
			object_update->current_time,
			object_update->total_downloaded
			);
}

static int trail_remote_set_status(struct pantavisor *pv, struct pv_update *update, enum update_state status, const char *msg)
{
	int ret = 0;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;
	char __json[1024];
	int json_size = sizeof (__json);
	char *json = __json;
	char message[128];
	char total_progress_json[512];

	if (!pv || !update) {
		pv_log(WARN, "uninitialized update");
		return -1;
	}

	// update the update state machine
	update->status = status;

	// create json according to status
	switch (status) {
	case UPDATE_QUEUED:
		// form message
		SNPRINTF_WTRUNC(message, sizeof (message), "Retried %d of %d",
				update->retries,
				pv_config_get_updater_revision_retries());

		// form request
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT_WITH_DATA,
				"QUEUED", message, 0, update->retries);

		break;
	case UPDATE_DOWNLOADED:
		SNPRINTF_WTRUNC(json, json_size,  DEVICE_STEP_STATUS_FMT,
				"INPROGRESS", "Update objects downloaded", 40);
		break;
	case UPDATE_INSTALLED:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"INPROGRESS", "Update installed", 80);
		break;
	case UPDATE_TRY:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"INPROGRESS", "Starting updated version", 95);
		break;
	case UPDATE_TRANSITION:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"INPROGRESS", "Transitioning to new revision without rebooting", 95);
		break;
	case UPDATE_REBOOT:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"INPROGRESS", "Rebooting", 95);
		break;
	case UPDATE_UPDATED:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"UPDATED", "Update finished, revision not set as rollback point", 100);
		break;
	case UPDATE_DONE:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"DONE", "Update finished, revision set as rollback point", 100);
		break;
	case UPDATE_NO_DOWNLOAD:
		if (!msg)
			msg = "Unable to download and/or install update";
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"WONTGO", msg, 0);
		break;
	case UPDATE_NO_SIGNATURE:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"WONTGO", "State signatures cannot be verified", 0);
		break;
	case UPDATE_NO_PARSE:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"WONTGO", "State cannot be parsed", 0);
		break;
	case UPDATE_RETRY_DOWNLOAD:
		pv_log(DEBUG, "download needs to be retried, retry count is %d", update->retries);
		// form message
		SNPRINTF_WTRUNC(message, sizeof (message),
				"Network unavailable while downloading, retry %d of %d",
				update->retries,
				pv_config_get_updater_revision_retries());
		// form request
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT_WITH_DATA,
			"QUEUED", message, 0, update->retries);
		// Clear what was downloaded.
		update->total_update->total_downloaded = 0;
		break;
	case UPDATE_TESTING_REBOOT:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"TESTING", "Awaiting to set rollback point if update is stable",
				95);
		break;
	case UPDATE_TESTING_NONREBOOT:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"TESTING", "Awaiting to see if update is stable", 95);
		break;
	case UPDATE_DOWNLOAD_PROGRESS:
		if (update->progress_objects) {
			// form message
			SNPRINTF_WTRUNC(message, sizeof (message), "Retry %d of %d",
					update->retries,
					pv_config_get_updater_revision_retries());
			// form retries string
			if (update->total_update) {
				object_update_json(update->total_update,
						total_progress_json, sizeof(total_progress_json));
			}
			char *buff = update->progress_objects;
			/*
			 * append the message to the end of
			 * progress_objects. Avoid another allocation,
			 * and cleanup progress_objects from the msg location.
			 */
			int len = strlen(buff);

			/*
			 * if there are no previous objects,
			 * we don't need to allocate buffer space.
			 */
			if (len) {
				json_size = PATH_MAX + update->progress_size;
				json = (char*)calloc(sizeof (char), json_size);
			}
			/*
			 * we must post the total
			 */
			if (!json) {
				json = __json;
				json_size = sizeof (__json);
			}
			/*
			 * just post the total and bail out.
			 */
			if (__json == json) {
				SNPRINTF_WTRUNC(json, json_size,
						DEVICE_STEP_STATUS_FMT_PROGRESS_DATA,
						"DOWNLOADING", message, 0, update->retries,
						total_progress_json,
						"");
				break;
			}
			if (msg) {
				if (len) {
					strcat(buff + len, ",");
					len += 1;
				}
				SNPRINTF_WTRUNC(buff + len,
						pv->update->progress_size - len, "%s", msg);
				len = (len > 0 ? len - 1 : len);
			}
			SNPRINTF_WTRUNC(json, json_size,
					DEVICE_STEP_STATUS_FMT_PROGRESS_DATA,
					"DOWNLOADING", message, 0, update->retries,
					total_progress_json,
					update->progress_objects);
			update->progress_objects[len] = '\0';
		}
		break;
	default:
		SNPRINTF_WTRUNC(json, json_size, DEVICE_STEP_STATUS_FMT,
				"ERROR", "Error during update", 0);
		break;
	}

	// store progress in trails
	if (update->pending && update->pending->rev)
		pv_storage_set_rev_progress(update->pending->rev, json);

	// do not report to cloud if that is not possible
	if ((update->pending && update->pending->local) ||
		!pv_get_instance()->remote_mode ||
		!pv->online ||
		trail_remote_init(pv))
		goto out;

	req = trest_make_request(THTTP_METHOD_PUT, update->endpoint, json);

	ret = -1;
	res = trest_do_json_request(pv->remote->client, req);
	if (!res) {
		pv_log(WARN, "HTTP request PUT %s could not be initialized", update->endpoint);
	} else if (!res->code &&
		res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request PUT %s could not auth (status=%d)", update->endpoint, res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "HTTP request PUT %s returned error (code=%d; body='%s')", update->endpoint, res->code, res->body);
	} else {
		pv_log(INFO, "remote state updated to %s", res->body);
		ret = 0;
	}

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	if (json != __json)
		free(json);

	return ret;
}

static int trail_get_steps_response(struct pantavisor *pv, char *endpoint, trest_response_ptr *response)
{
	trest_request_ptr req = NULL;
	trest_response_ptr res = NULL;
	struct trail_remote *remote = NULL;
	int ret = -1, size = 0;

	if (!endpoint || !pv)
		goto out;
	remote = pv->remote;
	req = trest_make_request(THTTP_METHOD_GET, endpoint, 0);

	res = trest_do_json_request(remote->client, req);
	if (!res) {
		pv_log(WARN, "HTTP request GET %s could not be initialized", endpoint);
	} else if (!res->code &&
		res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request GET %s could not auth (status=%d)", endpoint, res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "HTTP request GET %s returned error (code=%d; body='%s')", endpoint, res->code, res->body);
	} else {
		size = jsmnutil_array_count(res->body, res->json_tokv);
		if (!size) {
			ret = 0;
			goto out;
		}

		pv_log(DEBUG, "%d steps found", size);
		trest_request_free(req);
		*response = res;
		return 1;
	}
out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	return ret;
}

/*
 * the "data" field is structured as,
 * "data" : "value"
 * }
 */
struct jka_update_ctx {
	int *retries;
};

static int do_progress_action(struct json_key_action *jka, char *value)
{
	char *retry_count = NULL;
	int ret = 0;
	struct jka_update_ctx *ctx = (struct jka_update_ctx*) jka->opaque;
	struct json_key_action jka_arr[] = {
		ADD_JKA_ENTRY("data", JSMN_STRING, &retry_count, NULL, true),
		ADD_JKA_NULL_ENTRY()
	};

	ret = __start_json_parsing_with_action(jka->buf, jka_arr, JSMN_OBJECT, jka->tokv, jka->tokc);
	if (!ret) {
		if (retry_count) {
			pv_log(DEBUG, "retry_count = %s", retry_count);
			sscanf(retry_count, "%d", ctx->retries);
			free(retry_count);
		}
	}
	return ret;
}

static struct pv_update* pv_update_new(const char *id, const char *rev, bool local)
{
	struct pv_update *u;
	int size;

	if (!rev)
		return NULL;

	u = calloc(1, sizeof(struct pv_update));
	if (u) {
		u->total_update = (struct object_update*) calloc(1, sizeof(struct object_update));
		u->progress_size = PATH_MAX;
		u->progress_objects = (char*)calloc(1, u->progress_size);
		u->status = UPDATE_INIT;
		u->retries = 0;
		u->local = local;

		if (!id) {
			u->local = true;
			goto out;
		}

		size = sizeof (DEVICE_STEP_ENDPOINT_FMT)
					+ strlen(id)
					+ strlen(rev);
		u->endpoint = malloc(sizeof (char) * size);
		SNPRINTF_WTRUNC(u->endpoint, size, DEVICE_STEP_ENDPOINT_FMT, id, rev);
	}

out:
	return u;
}

static int trail_get_new_steps(struct pantavisor *pv)
{
	bool wrong_revision = false;
	int ret = 0;
	char *state = 0, *rev = 0;
	struct trail_remote *remote = pv->remote;
	trest_response_ptr res = NULL;
	jsmntok_t *tokv = 0;
	int retries = 0;
	struct jka_update_ctx update_ctx = {
		.retries = &retries
	};
	struct json_key_action jka[] = {
		ADD_JKA_ENTRY("progress", JSMN_OBJECT, &update_ctx,
				do_progress_action, false),
		ADD_JKA_NULL_ENTRY()
	};
	struct pv_update *update;

	if (!remote)
		return 0;

	// if update is going on, just check for NEW updates so test json can be parsed
	if (pv->update)
		goto new_update;

	// check for INPROGRESS updates
	ret = trail_get_steps_response(pv, remote->endpoint_trail_inprogress, &res);
	if (ret > 0) {
		pv_log(DEBUG, "found INPROGRESS revision");
		wrong_revision = true;
		goto process_response;
	} else if (ret < 0) {
		goto out;
	}

	// check for DOWNLOADING updates
	ret = trail_get_steps_response(pv, remote->endpoint_trail_downloading, &res);
	if (ret > 0) {
		pv_log(DEBUG, "found DOWNLOADING revision");
		goto process_response;
	} else if (ret < 0) {
		goto out;
	}

	// check for QUEUED updates
	ret = trail_get_steps_response(pv, remote->endpoint_trail_queued, &res);
	if (ret > 0) {
		pv_log(DEBUG, "found QUEUED revision");
		goto process_response;
	} else if (ret < 0) {
		goto out;
	}

new_update:
	// check for NEW updates
	ret = trail_get_steps_response(pv, remote->endpoint_trail_new, &res);
	if (ret > 0) {
		pv_log(DEBUG, "found NEW revision");
		goto process_response;
	} else if (ret < 0) {
		goto out;
	}

process_response:
	ret = 0;
	// if we have no response, we go out normally
	if (!res)
		goto out;

	// parse revision id
	rev = pv_json_get_value(res->body, "rev",
			res->json_tokv, res->json_tokc);

	// this could mean either the server is returning a malformed response or json parser is not working properly
	if (!rev) {
		pv_log(ERROR, "rev not found in endpoint response, ignoring...");
		goto out;
	}

	pv_log(DEBUG, "parse rev %s...", rev);

	// create temp update to be able to report the revision state
	update = pv_update_new(pv_config_get_creds_id(), rev, false);
	if (!update)
		goto out;

	if (atoi(rev) < atoi(pv->state->rev)) {
		pv_log(WARN, "stale rev %s found on remote", rev);
		wrong_revision = true;
		goto send_feedback;
	}

	// get raw revision state and parse retry
	state = pv_json_get_value(res->body, "state",
			res->json_tokv, res->json_tokc);
	if (start_json_parsing_with_action(res->body, jka, JSMN_ARRAY) ||
		!state) {
		pv_log(WARN, "failed to parse the rest of the response");
		trail_remote_set_status(pv, update, UPDATE_NO_PARSE, NULL);
		pv_update_free(update);
		goto out;
	}

send_feedback:

	// report stale revision
	if (wrong_revision) {
		trail_remote_set_status(pv, update, UPDATE_FAILED, NULL);
		pv_update_free(update);
		goto out;
	}

	// increment and report revision retry max reached
	if (retries > pv_config_get_updater_revision_retries()) {
		pv_log(WARN, "max retries reached in rev %s", rev);
		trail_remote_set_status(pv, update, UPDATE_NO_DOWNLOAD, NULL);
		pv_update_free(update);
		goto out;
	}

	// retry number recovered from endpoint response
	update->retries = retries;
	// if everything went well until this point, put revision to queue
	trail_remote_set_status(pv, update, UPDATE_QUEUED, NULL);

	// parse state
	if (!pv_signature_verify(state)) {
		pv_log(WARN, "invalid state signature");
		trail_remote_set_status(pv, update, UPDATE_NO_SIGNATURE, NULL);
		pv_update_free(update);
		goto out;
	}
	update->pending = pv_parser_get_state(state, rev);
	if (!update->pending) {
		pv_log(WARN, "invalid state from rev %s", rev);
		trail_remote_set_status(pv, update, UPDATE_NO_PARSE, NULL);
		pv_update_free(update);
		goto out;
	}

	// set newly processed update if no update is going on
	if (!pv->update) {
		pv->update = update;
		ret = 1;
	} else
		pv_update_free(update);

out:
	if (rev)
		free(rev);
	if (state)
		free(state);
	if (tokv)
		free(tokv);
	if (res)
		trest_response_free(res);
	return ret;
}

static int trail_is_available(struct trail_remote *r)
{
	trest_request_ptr req;
	trest_response_ptr res;
	int size = -1;

	if (!r)
		return size;

	req = trest_make_request(THTTP_METHOD_GET, "/trails/", 0);

	res = trest_do_json_request(r->client, req);
	if (!res) {
		pv_log(WARN, "GET /trails/ could not be initialized");
	} else if (!res->code &&
		res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "GET /trails/ could not auth (status=%d)", res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "GET /trails/ returned error (code=%d; body='%s')", res->code, res->body);
	} else {
	    size = jsmnutil_array_count(res->body, res->json_tokv);
	    if (size)
			pv_log(DEBUG, "trail found, using remote");
	}

	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return size;
}

static void __trail_log_resp_err(char *buf, jsmntok_t *tokv, int tokc)
{
	char *error = NULL, *msg = NULL, *__code = NULL;
	int code = 0;
	/*
	 * Error response looks like
	 * {
	 *  "error": <String>
	 *  "msg": <String> <Maybe empty>
	 *  "code": <int> <Maybe empty>
	 * }
	 */
	error = pv_json_get_value(buf,
			"error",
			tokv,
			tokc);

	msg = pv_json_get_value(buf,
			"msg",
			tokv,
			tokc);

	__code = pv_json_get_value(buf,
			"code",
			tokv,
			tokc);
	if (__code) {
		sscanf(__code, "%d", &code);
		free(__code);
		__code = NULL;
	}

	if (error && msg) {
		pv_log(WARN, "Error %s: Message %s, code = %d",
				error, msg, code);
	}
	else {
		pv_log(WARN, "Malformed Error JSON from API,"
				" error:%s,msg:%s, code=%d",
				(error ? error : "nil"),
				(msg ? msg : "nil"),
				code);
	}
	if (error)
		free(error);
	if (msg)
		free(msg);
}

static void trail_log_thttp_err(thttp_response_t *thttp_res)
{
	int tokc;
	jsmntok_t *tokv = NULL;
	char *buf = NULL;

	if (!thttp_res || thttp_res->code == THTTP_STATUS_OK)
		return;
	buf = thttp_res->body;
	if (!buf)
		return;
	if (jsmnutil_parse_json(buf, &tokv, &tokc) >=0 ) {
		__trail_log_resp_err(buf, tokv, tokc);
	}
	if (tokv)
		free(tokv);
}

static void trail_log_trest_err(trest_response_ptr tres)
{

	if (!tres || tres->code == THTTP_STATUS_OK)
		return;
	if (!tres->json_tokv)
		return;
	__trail_log_resp_err(tres->body, tres->json_tokv,
			tres->json_tokc);
}

#define SHA256_STR_SIZE ((256 / 4) + 1)

static int trail_put_object(struct pantavisor *pv, struct pv_object *o, const char **crtfiles)
{
	int ret = -1;
	int fd, bytes;
	int size, pos, i, str_size;
	char *signed_puturl = NULL;
	char sha_str[SHA256_STR_SIZE];
	char body[512];
	unsigned char buf[4096];
	unsigned char local_sha[32];
	struct stat st;
	trest_request_ptr treq = 0;
	trest_response_ptr tres = 0;
	thttp_request_t *req = 0;
	thttp_request_tls_t *tls_req = 0;
	thttp_response_t *res = 0;

	fd = open(o->objpath, O_RDONLY);
	if (fd < 0)
		return -1;

	stat(o->objpath, &st);
	size = st.st_size;

	mbedtls_sha256_context sha256_ctx;

	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0);

	while ((bytes = read(fd, buf, 4096)) > 0) {
		mbedtls_sha256_update(&sha256_ctx, buf, bytes);
	}

	mbedtls_sha256_finish(&sha256_ctx, local_sha);
	mbedtls_sha256_free(&sha256_ctx);

	pos = 0;
	i = 0;
	while(i < 32) {
		pos += snprintf(sha_str+pos, 3, "%02x", local_sha[i]);
		i++;
	}

	SNPRINTF_WTRUNC(body,
			sizeof (body),
			"{ \"objectname\": \"%s\","
			" \"size\": \"%d\","
			" \"sha256sum\": \"%s\""
			" }",
			o->name,
			size,
			sha_str);

	pv_log(INFO, "syncing '%s'", o->id);

	if (strncmp(o->id, sha_str, SHA256_STR_SIZE)) {
		pv_log(INFO, "sha256 mismatch, probably writable image, skipping", o->objpath);
		goto out;
	}

	treq = trest_make_request(THTTP_METHOD_POST, "/objects/", body);

	tres = trest_do_json_request(pv->remote->client, treq);
	if (!tres) {
		pv_log(WARN, "POST /objects/ could not be initialized");
		goto out;
	} else if (tres->code == THTTP_STATUS_CONFLICT) {
		pv_log(INFO, "object '%s' already owned by user, skipping", o->id);
		ret = 0;
		goto out;
	} else if (!tres->code &&
		tres->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "POST /objects/ could not auth (status=%d)", tres->status);
		goto out;
	} else if (tres->code != THTTP_STATUS_OK) {
		pv_log(WARN, "POST /objects/ returned error (code=%d; body='%s')", tres->code, tres->body);
		goto out;
	}

	signed_puturl = pv_json_get_value(tres->body,
				"signed-puturl",
				tres->json_tokv,
				tres->json_tokc);

	tls_req = (thttp_request_tls_t*) thttp_request_tls_new_0 ();

	if (signed_puturl && tls_req) {
		tls_req->crtfiles = (char ** )crtfiles;
		req = (thttp_request_t*) tls_req;
		req->is_tls = 1;

		req->method = THTTP_METHOD_PUT;
		req->proto = THTTP_PROTO_HTTP;
		req->proto_version = THTTP_PROTO_VERSION_10;
		req->host = pv_config_get_creds_host();
		req->port = pv_config_get_creds_port();
		req->host_proxy = pv_config_get_creds_host_proxy();
		req->port_proxy = pv_config_get_creds_port_proxy();
		req->proxyconnect = !pv_config_get_creds_noproxyconnect();
		if (req->is_tls) {
			str_size = strlen("https://")
					+ strlen(req->host) + 1 /* : */ + 5 /* port */ + 2 /* 0-delim */;
			req->baseurl = calloc(sizeof (char), str_size);
			SNPRINTF_WTRUNC(req->baseurl, str_size,
					"https://%s:%d", req->host, req->port);
		} else {
			((thttp_request_tls_t*)req)->crtfiles = NULL;
			str_size = strlen("https://")
					+ strlen(req->host) + 1 /* : */ + 5 /* port */ + 2 /* 0-delim */;
			req->baseurl = calloc(sizeof (char), str_size);
			SNPRINTF_WTRUNC(req->baseurl, str_size, "http://%s:%d", req->host, req->port);
		}
		if (req->host_proxy)
			req->is_tls = false; /* XXX: global config if proxy is tls is TBD */
		req->user_agent = pv_user_agent;

		req->path = strstr(signed_puturl, "/local-s3");

		req->body_content_type = "application/json";
		lseek(fd, 0, SEEK_SET);
		req->fd = fd;
		req->len = size;

		pv_log(INFO, "'%s' does not exist, uploading", o->id);

		res = thttp_request_do(req);

		if (!res) {
			pv_log(WARN, "'%s' could not be uploaded: could not be initialized", o->id);
		} else if (!res->code) {
			pv_log(WARN, "'%s' could not be uploaded: got no response", o->id);
		} else if (res->code != THTTP_STATUS_OK) {
			pv_log(WARN, "'%s' could not be uploaded: returned HTTP error (code=%d; body='%s')",
				o->id, res->code, res->body);
		} else {
			pv_log(INFO, "'%s' uploaded correctly, size=%d, code=%d", o->id, size, res->code);
			ret = 0;
		}
	}
	else {
		pv_log(ERROR, "'%s' could not be registered, signed_puturl not retrieved", o->id);
	}

out:
	close(fd);
	if (signed_puturl)
		free(signed_puturl);
	if (treq)
		trest_request_free(treq);
	if (tres) {
		/*
		 * For Conflict on an object we don't see it
		 * as an error so skip the trail_log in this
		 * case.
		 */
		if (tres->code != THTTP_STATUS_CONFLICT)
			trail_log_trest_err(tres);
		trest_response_free(tres);
	}
	if (req)
		thttp_request_free(req);
	if (res) {
		trail_log_thttp_err(res);
		thttp_response_free(res);
	}

	return ret;
}

static int trail_put_objects(struct pantavisor *pv)
{
	int ret = 0;
	struct pv_object *curr = NULL;
	const char **crtfiles = pv_ph_get_certs(pv);

	pv_objects_iter_begin(pv->state, curr) {
		ret++;
	}
	pv_objects_iter_end;

	pv_log(DEBUG, "first boot: %d objects found, syncing", ret);

	// push all
	pv_objects_iter_begin(pv->state, curr) {
		if (trail_put_object(pv, curr, crtfiles) < 0)
			break;
		ret--;
	}
	pv_objects_iter_end;

	return ret;
}

static int trail_first_boot(struct pantavisor *pv)
{
	trest_request_ptr req;
	trest_response_ptr res;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	status = trest_update_auth(pv->remote->client);
	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "cannot update auth token");
		return -1;
	}

	// first upload all objects
	if (trail_put_objects(pv) > 0) {
		pv_log(DEBUG, "error syncing objects on first boot");
		return -1;
	}

	req = trest_make_request(THTTP_METHOD_POST, "/trails/", pv->state->json);
	res = trest_do_json_request(pv->remote->client, req);
	if (!res) {
		pv_log(WARN, "POST /trails/ could not be initialized");
	} else if (!res->code &&
		res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "POST /trails/ could not auth (status=%d)", res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "POST /trails/ returned error (code=%d; body='%s')", res->code, res->body);
	} else {
		pv_log(INFO, "factory revision (base trail) pushed to remote correctly");
	}

	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return 0;
}

int pv_updater_check_for_updates(struct pantavisor *pv)
{
	int ret;

	if (trail_remote_init(pv)) {
		pv_log(WARN, "remote not initialized");
		return 0;
	}

	if (trest_update_auth(pv->remote->client) != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "cannot authenticate to cloud");
		return 0;
	}

	// if an update is going, we might come from a download retry
	if (pv->update && pv->update->status == UPDATE_RETRY_DOWNLOAD)
		return 1;

	ret = trail_is_available(pv->remote);
	if (ret == 0)
		return trail_first_boot(pv);
	else if (ret > 0) {
		pv->synced = true;
		return trail_get_new_steps(pv);
	} else
		return 0;
}

bool pv_trail_is_auth(struct pantavisor *pv)
{
	// if remote exist, it means we have already authenticate
	if (pv->remote)
		return true;

	// authenticate if possible
	if (pv->online)
		trail_remote_init(pv);

	if (pv->remote)
		return true;

	return false;
}

static int pv_update_set_status_msg(struct pantavisor *pv, enum update_state status, char *msg)
{
	if (!pv || !pv->update) {
		pv_log(WARN, "uninitialized update");
		return -1;
	}

	return trail_remote_set_status(pv, pv->update, status, msg);
}

int pv_update_set_status(struct pantavisor *pv, enum update_state status)
{
	return pv_update_set_status_msg(pv, status, NULL);
}

static int pv_update_check_download_retry(struct pantavisor *pv)
{
	if (pv->update) {
		struct timer_state timer_state = timer_current_state(&pv->update->retry_timer);

		if (timer_state.fin) {
			pv->update->retries++;
			if (pv->update->retries > pv_config_get_updater_revision_retries())
				return -1;
			pv_log(INFO, "trying revision %s ,retry = %d",
					pv->update->pending->rev, pv->update->retries);
			// set timer for next retry
			timer_start(&pv->update->retry_timer, pv_config_get_storage_wait(),
					0, RELATIV_TIMER);
			return 0;
		}

		pv_log(INFO, "retrying in %d seconds", timer_state.sec);
		return 1;
	}

	pv_update_set_status(pv, UPDATE_FAILED);
	return -1;
}

static void pv_trail_remote_free(struct trail_remote *trail)
{
	if (!trail)
		return;

	pv_log(DEBUG, "removing trail");

	if (trail->endpoint_trail_queued)
		free(trail->endpoint_trail_queued);
	if (trail->endpoint_trail_new)
		free(trail->endpoint_trail_new);
	if (trail->endpoint_trail_queued)
		free(trail->endpoint_trail_queued);
	if (trail->endpoint_trail_inprogress)
		free(trail->endpoint_trail_inprogress);

	free(trail);
}

void pv_trail_remote_remove(struct pantavisor *pv)
{
	pv_trail_remote_free(pv->remote);
	pv->remote = NULL;
}

void pv_update_test(struct pantavisor *pv)
{
	if (!pv->update)
		return;

	switch (pv->update->status) {
	case UPDATE_TRY:
		pv_update_set_status(pv, UPDATE_TESTING_REBOOT);
		break;
	case UPDATE_TRANSITION:
		pv_update_set_status(pv, UPDATE_TESTING_NONREBOOT);
		break;
	default:
		break;
	}
}

int pv_update_finish(struct pantavisor *pv)
{
	if (!pv->update)
		return 0;

	switch (pv->update->status) {
	case UPDATE_FAILED:
		pv_bootloader_set_failed();
		pv_update_set_status(pv, UPDATE_FAILED);
		pv_update_remove(pv);
		pv_log(INFO, "update finished");
		break;
	case UPDATE_RETRY_DOWNLOAD:
		if (pv->update->retries > pv_config_get_updater_revision_retries()) {
			pv_update_set_status(pv, UPDATE_NO_DOWNLOAD);
			pv_update_remove(pv);
			pv_log(INFO, "update finished");
			return 0;
		}
		break;
	case UPDATE_NO_DOWNLOAD:
		pv_update_remove(pv);
		pv_log(INFO, "update finished");
		break;
	case UPDATE_TESTING_REBOOT:
		if (pv_bootloader_set_commited(pv->state->rev)) {
			pv_log(ERROR, "revision for next boot could not be set");
			return -1;
		}
		pv_update_set_status(pv, UPDATE_DONE);
		// we keep this here so we can rollback to new DONE revisions from old pantavisor versio
		pv_storage_set_rev_done(pv, pv->state->rev);
		pv_update_remove(pv);
		pv_log(INFO, "update finished");
		break;
	case UPDATE_TESTING_NONREBOOT:
		pv_update_set_status(pv, UPDATE_UPDATED);
		pv_update_remove(pv);
		pv_log(INFO, "update finished");
		break;
	default:
		pv_update_set_status(pv, pv->update->status);
		pv_log(WARN, "update finished during wrong state %d", pv->update->status);
		pv_update_remove(pv);
		break;
	}

	return 0;
}

static int trail_download_get_meta(struct pantavisor *pv, struct pv_object *o)
{
	int ret = 0;
	char *endpoint = 0;
	int str_size;
	char *url = 0;
	char *prn, *size = NULL;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!o)
		goto out;

	prn = o->id;

	str_size = sizeof(TRAIL_OBJECT_DL_FMT) + strlen(prn);
	endpoint = malloc(str_size * sizeof(char));
	SNPRINTF_WTRUNC(endpoint, str_size, TRAIL_OBJECT_DL_FMT, prn);

	pv_log(DEBUG, "requesting obj='%s'", endpoint);

	req = trest_make_request(THTTP_METHOD_GET, endpoint, 0);

	res = trest_do_json_request(pv->remote->client, req);
	if (!res) {
		pv_log(WARN, "GET %s could not be initialized", endpoint);
		goto out;
	} else if (!res->code &&
		res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "GET %s could not auth (status=%d)", endpoint, res->status);
		goto out;
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "GET %s returned error (code=%d; body='%s')", endpoint, res->code, res->body);
		goto out;
	}

	size = pv_json_get_value(res->body, "size",
			res->json_tokv, res->json_tokc);
	if (size)
		o->size = atoll(size);

	o->sha256 = pv_json_get_value(res->body, "sha256sum",
				 res->json_tokv, res->json_tokc);

	url = pv_json_get_value(res->body, "signed-geturl",
				 res->json_tokv, res->json_tokc);
	if (!url) {
		pv_log(ERROR, "unable to get download url for object");
		goto out;
	}
	url = unescape_utf8_to_apvii(url, "\\u0026", '&');
	o->geturl = url;

	// FIXME:
	// if (verify_url(url)) ret = 1;
	ret = 1;

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	if (endpoint)
		free(endpoint);
	if (size)
		free(size);

	return ret;
}

static int obj_is_kernel_pvk(struct pantavisor *pv, struct pv_object *obj)
{
	if (pv->state->bsp.img.std.kernel) {
		if (strcmp(pv->state->bsp.img.std.kernel, obj->name))
			return 0;
	} else if (pv->state->bsp.img.ut.fit) {
		if (strcmp(pv->state->bsp.img.ut.fit, obj->name))
			return 0;
	}

	if (pv_config_get_bl_type() == BL_UBOOT_PVK)
		return 1;

	return 0;
}

struct progress_update {
	struct timer timer_next_update;
	struct pantavisor *pv;
	struct object_update *object_update;
	struct pv_object *pv_object;
};

static uint64_t get_update_size(struct pv_update *u)
{
	uint64_t size = 0;
	struct stat st;
	struct pv_object *curr = NULL;

	pv_objects_iter_begin(u->pending, curr) {
		if (stat(curr->objpath, &st) < 0)
			size += curr->size;
	}
	pv_objects_iter_end;

	return size;
}
/*
 * see object_update
 */
static void trail_download_object_progress(ssize_t written, ssize_t chunk_size, void *obj)
{
	struct progress_update *progress_update = (struct progress_update*)obj;
	struct pv_object *pv_object = NULL;
	char *msg = NULL;
	const int OBJ_JSON_SIZE = 1024;
	struct object_update *total_update = NULL;

	if (!obj)
		return;
	total_update = progress_update->pv->update->total_update;
	if (timer_current_state(&progress_update->timer_next_update).fin) {
		if (chunk_size == written) {
			progress_update->object_update->total_downloaded += chunk_size;
			total_update->total_downloaded += chunk_size;
			return;
		}
		/*
		 * written != chunk_size then allow for
		 * error message to be posted.
		 */
	}
	pv_object = progress_update->pv_object;
	if (!pv_object)
		return;

	msg = (char*)calloc(1, OBJ_JSON_SIZE);
	if (!msg)
		return;

	if (written != chunk_size) {
		pv_log(ERROR, "Error downloading object %s", pv_object->name);
		goto out;
	}
	else {
		progress_update->object_update->total_downloaded += chunk_size;
		total_update->total_downloaded += chunk_size;
		progress_update->object_update->current_time = time(NULL);
		object_update_json(progress_update->object_update, msg, OBJ_JSON_SIZE);
	}
	timer_start(&progress_update->timer_next_update, UPDATE_PROGRESS_FREQ, 0, RELATIV_TIMER);
	pv_update_set_status_msg(progress_update->pv, UPDATE_DOWNLOAD_PROGRESS, msg);
out:
	free(msg);
}

static int trail_download_object(struct pantavisor *pv, struct pv_object *obj, const char **crtfiles)
{
	int ret = 0;
	int volatile_tmp_fd = -1, fd = -1, obj_fd = -1;
	int bytes, n;
	int is_kernel_pvk;
	int use_volatile_tmp = 0;
	int size = -1;
	char *tmp_sha;
	char *host = 0;
	char *start = 0, *port = 0, *end = 0;
	char mmc_tmp_obj_path [PATH_MAX];
	char volatile_tmp_obj_path[] = VOLATILE_TMP_OBJ_PATH;
	unsigned char buf[4096];
	unsigned char cloud_sha[32];
	unsigned char local_sha[32];
	struct stat st;
	mbedtls_sha256_context sha256_ctx;
	thttp_response_t* res = 0;
	thttp_request_tls_t* tls_req = 0;
	thttp_request_t* req = 0;
	struct object_update object_update;
	struct progress_update progress_update = {
		.pv = pv,
		.pv_object = obj,
		.object_update = &object_update,
	};
	if (!obj)
		goto out;

	tls_req = thttp_request_tls_new_0 ();
	tls_req->crtfiles = (char ** )crtfiles;

	req = (thttp_request_t*) tls_req;

	req->user_agent = pv_user_agent;
	req->method = THTTP_METHOD_GET;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;

	is_kernel_pvk = obj_is_kernel_pvk(pv, obj);
	if (!is_kernel_pvk && stat(obj->objpath, &st) == 0) {
		pv_log(DEBUG, "file exists (%s)", obj->objpath);
		ret = 1;
		goto out;
	}

	if (obj->geturl == NULL) {
		pv_log(INFO, "there is no get url defined");
		goto out;
	}

	// SSL is mandatory
	if (strncmp(obj->geturl, "https://", 8) != 0) {
		pv_log(INFO, "object url (%s) is invalid", obj->geturl);
		goto out;
	}
	req->port = 443;

	start = obj->geturl + 8;
	port = strchr(start, ':');
	if (port) {
		int p = strtol (++port, &end, 0);
		if (p > 0)
		req->port = p;
	} else {
		end = strchr(start, '/');
	}

	n = (unsigned long) end - (unsigned long) start;
	host = malloc((n+1) * sizeof(char));
	strncpy(host, start, n);
	host[n] = '\0';

	req->host = host;
	req->host_proxy = pv_config_get_creds_host_proxy();
	req->port_proxy = pv_config_get_creds_port_proxy();
	req->proxyconnect = !pv_config_get_creds_noproxyconnect();
	if (req->is_tls) {
		size = strlen("https://") + strlen(req->host) + 1 /* : */ + 5 /* port */ + 2 /* 0-delim */;
		req->baseurl = calloc(sizeof (char), size);
		SNPRINTF_WTRUNC(req->baseurl, size, "https://%s:%d", req->host, req->port);
	} else {
		((thttp_request_tls_t*)req)->crtfiles = NULL;
		size = strlen("https://") + strlen(req->host) + 1 /* : */ + 5 /* port */ + 2 /* 0-delim */;
		req->baseurl = calloc(sizeof(char), size);
		SNPRINTF_WTRUNC(req->baseurl, size, "http://%s:%d", req->host, req->port);
			pv_log(WARN, "req->baseurl truncated to %s", req->baseurl);
	}

	if (req->host_proxy)
		req->is_tls = false; /* XXX: global config if proxy is tls is TBD */

	req->path = end;

	if (pv_config_get_updater_network_use_tmp_objects() &&
		(!strcmp(pv_config_get_storage_fstype(), "jffs2") ||
	    !strcmp(pv_config_get_storage_fstype(), "ubifs")))
		use_volatile_tmp = 1;

	// temporary path where we will store the file until validated
	SNPRINTF_WTRUNC(mmc_tmp_obj_path, sizeof (mmc_tmp_obj_path), MMC_TMP_OBJ_FMT, obj->objpath);
	obj_fd = open(mmc_tmp_obj_path, O_CREAT | O_RDWR, 0644);
	if (obj_fd < 0) {
		pv_log(ERROR, "open failed for %s: %s", mmc_tmp_obj_path, strerror(errno));
		goto out;
	}

	if (use_volatile_tmp) {
		mkstemp(volatile_tmp_obj_path);
		volatile_tmp_fd = open(volatile_tmp_obj_path, O_CREAT | O_RDWR, 0644);
		fd = volatile_tmp_fd;
	} else {
		fd = obj_fd;
	}

	if (is_kernel_pvk) {
		fsync(obj_fd);
		close(obj_fd);
		fd = volatile_tmp_fd;
	}

	// download to tmp
	lseek(fd, 0, SEEK_SET);
	pv_log(INFO, "downloading object to tmp path (%s)", mmc_tmp_obj_path);
	object_update.start_time = time(NULL);
	object_update.object_name = obj->name;
	object_update.object_id = obj->id;
	object_update.total_size = obj->size;
	object_update.current_time = object_update.start_time;
	object_update.total_downloaded = 0;
	timer_start(&progress_update.timer_next_update, UPDATE_PROGRESS_FREQ, 0, RELATIV_TIMER);
	res = thttp_request_do_file_with_cb (req, fd,
			trail_download_object_progress, &progress_update);
	if (!res) {
		pv_log(WARN, "'%s' could not be downloaded: could not be initialized", obj->id);
		remove(mmc_tmp_obj_path);
		goto out;
	} else if (!res->code) {
		pv_log(WARN, "'%s' could not be downloaded: got no response", obj->id);
		remove(mmc_tmp_obj_path);
		goto out;
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "'%s' could not be downloaded: returned HTTP error (code=%d; body='%s')",
			obj->id, res->code, res->body);
		remove(mmc_tmp_obj_path);
		goto out;
	}

	if (use_volatile_tmp) {
		pv_log(INFO, "copying %s to tmp path (%s)", volatile_tmp_obj_path, mmc_tmp_obj_path);
		bytes = pv_file_copy_and_close(volatile_tmp_fd, obj_fd);
		fd = obj_fd;
	}
	pv_log(DEBUG, "downloaded object to tmp path (%s)", mmc_tmp_obj_path);
	fsync(fd);
	object_update.current_time = time(NULL);


	// verify file downloaded correctly before syncing to disk
	lseek(fd, 0, SEEK_SET);
	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0);

	while ((bytes = read(fd, buf, 4096)) > 0) {
		mbedtls_sha256_update(&sha256_ctx, buf, bytes);
	}

	mbedtls_sha256_finish(&sha256_ctx, local_sha);
	mbedtls_sha256_free(&sha256_ctx);

	tmp_sha = obj->sha256;
	for (int i = 0, j = 0; i < (int) strlen(tmp_sha); i=i+2, j++) {
		char byte[3];
		strncpy(byte, tmp_sha+i, 2);
		byte[2] = 0;
		cloud_sha[j] = strtoul(byte, NULL, 16);
	}

	// compare hashes FIXME: retry if fail
	for (int i = 0; i < 32; i++) {
		if (cloud_sha[i] != local_sha[i]) {
			pv_log(WARN, "sha256 mismatch with local object");
			remove(mmc_tmp_obj_path);
			goto out;
		}
	}

	pv_log(DEBUG, "renaming %s to %s...", mmc_tmp_obj_path, obj->objpath);
	if (pv_file_rename(mmc_tmp_obj_path, obj->objpath) < 0) {
		pv_log(ERROR, "could not rename");
	}

	ret = 1;
	if (pv->update && pv->update->progress_objects) {
		int data_len = strlen(pv->update->progress_objects);
		char this_obj_json[512];
		int to_write = 0;
		int remaining = pv->update->progress_size - data_len - 1;
		bool can_write = true;

		/*
		 * Use a placeholder for this object's json.
		 */
		object_update_json(&object_update, this_obj_json,
					sizeof(this_obj_json));
		to_write += strlen(this_obj_json);
		/*
		 * if there already were other objects we would
		 * need to add a ,
		 */
		if (data_len)
			to_write += 1;

		if (to_write > remaining) {
			char *__new_progress_objects =
				(char*)realloc(pv->update->progress_objects,
						(2 * pv->update->progress_size));
			if (!__new_progress_objects)
				can_write = false;
			else {
				pv->update->progress_size *= 2;
				pv->update->progress_objects = __new_progress_objects;
			}
		}
		if (can_write) {
			if (data_len) {
				strcat(pv->update->progress_objects, ",");
				data_len += 1;
			}
			SNPRINTF_WTRUNC(pv->update->progress_objects + data_len,
					pv->update->progress_size - data_len,
					"%s",
					this_obj_json);
		} else {
			pv_log(ERROR, "Failed to allocate space for progress data");
		}
		pv_log(DEBUG, "progress_objects is %s",
				pv->update->progress_objects);
	}
out:
	if (fd)
		close(fd);
	if (host)
		free(host);
	if (req)
		thttp_request_free(req);
	if (res)
		thttp_response_free(res);

	return ret;
}

static int trail_link_objects(struct pantavisor *pv)
{
	struct pv_object *obj = NULL;
	char *ext;

	pv_objects_iter_begin(pv->update->pending, obj) {
		mkbasedir_p(obj->relpath, 0755);
		ext = strrchr(obj->relpath, '.');
		if (ext && (strcmp(ext, ".bind") == 0)) {
			pv_log(INFO, "copying bind volume '%s' from '%s'", obj->relpath, obj->objpath);
			if (pv_file_copy(obj->objpath, obj->relpath, 0644) < 0)
				pv_log(ERROR, "could not copy objects");
			continue;
		}
		if (link(obj->objpath, obj->relpath) < 0) {
			if (errno != EEXIST) {
				pv_log(ERROR, "unable to link %s, errno=%d", obj->relpath, errno);
				return -1;
			}
		} else {
			syncdir(obj->objpath);
			pv_log(DEBUG, "linked %s to %s", obj->relpath, obj->objpath);
		}
	}
	pv_objects_iter_end;

	return pv_storage_meta_link_boot(pv, pv->update->pending);
}

static int trail_check_update_size(struct pantavisor *pv)
{
	off_t update_size, free_size;
	char msg[128];

	update_size = get_update_size(pv->update);
	pv_log(INFO, "update size: %" PRIu64 " B", update_size);

	free_size = pv_storage_gc_run_needed(update_size);

	if (update_size > free_size) {
		pv_log(ERROR, "cannot process update. Aborting...");
		SNPRINTF_WTRUNC(msg, sizeof (msg),
				"Space required %"PRIu64" B, available %"PRIu64" B",
				update_size, free_size);
		pv_update_set_status_msg(pv, UPDATE_NO_DOWNLOAD, msg);
		return -1;
	}

	return 0;
}

static int trail_download_objects(struct pantavisor *pv)
{
	struct pv_update *u = pv->update;
	struct pv_object *o = NULL;
	const char **crtfiles = pv_ph_get_certs(pv);

	pv_objects_iter_begin(u->pending, o) {
		if (!trail_download_get_meta(pv, o)) {
			pv_update_set_status(pv, UPDATE_RETRY_DOWNLOAD);
			return -1;
		}
	}
	pv_objects_iter_end;

	// check size and collect garbage if needed
	if (trail_check_update_size(pv))
		return -1;

	if (u->total_update) {
		u->total_update->object_name = "total";
		u->total_update->object_id = "none";
		u->total_update->total_size = get_update_size(u);
		u->total_update->start_time = time(NULL);
		u->total_update->total_downloaded = 0;
		u->total_update->current_time = time(NULL);
		pv_update_set_status(pv, UPDATE_DOWNLOAD_PROGRESS);
	}
	pv_objects_iter_begin(u->pending, o) {
		if (!trail_download_object(pv, o, crtfiles)) {
			pv_update_set_status(pv, UPDATE_RETRY_DOWNLOAD);
			return -1;
		}
	}
	u->total_update->current_time = time(NULL);
	pv_update_set_status(pv, UPDATE_DOWNLOAD_PROGRESS);
	pv_objects_iter_end;
	return 0;
}

struct pv_update* pv_update_get_step_local(char *rev)
{
	struct pantavisor *pv = pv_get_instance();
	struct pv_update *update = NULL;
	char *json = NULL;

	update = pv_update_new(pv_config_get_creds_id(), rev, true);
	if (!update)
		goto err;

	json = pv_storage_get_state_json(rev);
	if (!json) {
		pv_log(ERROR, "Could not read state json");
		goto err;
	}

	if (!pv_signature_verify(json)) {
		trail_remote_set_status(pv, update, UPDATE_NO_SIGNATURE, NULL);
		pv_log(WARN, "state signature verification went wrong");
		goto err;
	}
	update->pending = pv_parser_get_state(json, rev);
	if (!update->pending) {
		trail_remote_set_status(pv, update, UPDATE_NO_PARSE, NULL);
		pv_log(WARN, "state parse went wrong");
		goto err;
	}

	update->pending->local = true;

	if (json)
		free(json);
	return update;

err:
	if (json)
		free(json);
	pv_update_free(update);
	return NULL;
}

int pv_update_download(struct pantavisor *pv)
{
	int ret = -1;
	char path[PATH_MAX];

	if (!pv || !pv->state || !pv->update || !pv->update->pending) {
		pv_log(WARN, "uninitialized state or update");
		goto out;
	}

	pv_paths_storage_trail_pv_file(path, PATH_MAX, pv->update->pending->rev, "");
	mkdir_p(path, 0755);

	// do not download if this is a local update
	if (pv->update->local)
		return 0;

	if (trail_remote_init(pv)) {
		pv_log(WARN, "remote not initialized");
		goto out;
	}

	pv_log(DEBUG, "downloading update...");

	if (pv_update_check_download_retry(pv))
		goto out;

	ret = trail_download_objects(pv);
	if (ret < 0) {
		pv_log(WARN, "unable to download objects");
		goto out;
	}

	pv_update_set_status(pv, UPDATE_DOWNLOADED);

	ret = 0;
out:
	return ret;
}

int pv_update_install(struct pantavisor *pv)
{
	int ret = -1;
	struct pv_state *pending = pv->update->pending;
	char path[PATH_MAX];

	if (!pv || !pv->state || !pv->update || !pv->update->pending) {
		pv_log(WARN, "uninitialized state or update");
		goto out;
	}

	pv_log(DEBUG, "installing update...");

	// make sure target directories exist
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, pending->rev, "");
	mkdir_p(path, 0755);

	ret = trail_link_objects(pv);
	if (ret < 0) {
		pv_log(ERROR, "unable to link objects to relative path");
		pv_update_set_status(pv, UPDATE_FAILED);
		goto out;
	}

	// install state.json for new rev
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, pending->rev, JSON_FNAME);
	if (pv_file_save(path, pending->json, 0644) < 0)
		pv_log(ERROR, "could not save %s: %s", path, strerror(errno));

	if (!pv_storage_meta_expand_jsons(pv, pending)) {
		pv_log(ERROR, "unable to install platform and pantavisor jsons");
		ret = -1;
		goto out;
	}

	pv_log(DEBUG, "update successfully installed");
	if (pv_bootloader_set_installed(pending->rev)) {
		pv_log(ERROR, "unable to write pv_try to boot cmd env");
		ret = -1;
		goto out;
	}

	pv_update_set_status(pv, UPDATE_INSTALLED);
out:
	if (pending && (ret < 0))
		pv_storage_rm_rev(pending->rev);

	return ret;
}

int pv_update_resume(struct pantavisor *pv)
{
	const char *rev;

	// If update exist, it means we come from a non reboot start
	if (pv->update)
		return 0;

	// If update is in progress, we are going to load it to report its completion or failure
	if (pv_bootloader_update_in_progress()) {
		rev = pv_bootloader_get_try();
		if (!rev)
			return -1;

		pv_log(INFO, "loading update data from rev %s after reboot...", rev);
		pv->update = pv_update_new(pv_config_get_creds_id(), rev, false);
		if (!pv->update)
			return -1;

		if (pv_bootloader_trying_update())
			pv_update_set_status(pv, UPDATE_TRY);
		else
			pv_update_set_status(pv, UPDATE_FAILED);
	}

	return 0;
}

bool pv_update_is_transitioning(struct pv_update *u)
{
	return (u && u->status == UPDATE_TRANSITION);
}

bool pv_update_is_trying(struct pv_update *u)
{
	return (u &&
		((u->status == UPDATE_TRANSITION) ||
		(u->status == UPDATE_TRY)));
}

bool pv_update_is_testing(struct pv_update *u)
{
	return (u &&
		((u->status == UPDATE_TESTING_REBOOT) ||
		(u->status == UPDATE_TESTING_NONREBOOT)));
}
