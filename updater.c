/*
 * Copyright (c) 2017 Pantacor Ltd.
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

#define MODULE_NAME			"updater"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"
#include "objects.h"
#include "parser/parser.h"
#include "updater.h"
#include "bootloader.h"
#include "pantahub.h"
#include "storage.h"
#include "trestclient.h"
#include "wdt.h"
#include "init.h"
#include "revision.h"
#include "parser/parser_bundle.h"
#include "state.h"

int MAX_REVISION_RETRIES = 0;
int DOWNLOAD_RETRY_WAIT = 0;

typedef int (*token_iter_f) (void *d1, void *d2, char *buf, jsmntok_t* tok, int c);

static void pv_update_free(struct pv_update *update)
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

	if (pv->remote)
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

	endpoint_trail = malloc((sizeof(DEVICE_TRAIL_ENDPOINT_FMT)
		+ strlen(pv->config->creds.id)) * sizeof(char));
	if (!endpoint_trail)
		goto err;
	sprintf(endpoint_trail, DEVICE_TRAIL_ENDPOINT_FMT, pv->config->creds.id);

	remote->endpoint_trail_queued = (char*)calloc(1, strlen(endpoint_trail)
		+ sizeof(DEVICE_TRAIL_ENDPOINT_QUEUED));
	if (!remote->endpoint_trail_queued)
		goto err;
	sprintf(remote->endpoint_trail_queued, "%s%s", endpoint_trail, DEVICE_TRAIL_ENDPOINT_QUEUED);

	remote->endpoint_trail_new = (char*)calloc(1, strlen(endpoint_trail)
		+ sizeof(DEVICE_TRAIL_ENDPOINT_NEW));
	if (!remote->endpoint_trail_new)
		goto err;
	sprintf(remote->endpoint_trail_new, "%s%s", endpoint_trail, DEVICE_TRAIL_ENDPOINT_NEW);

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
	char *json = __json;
	char *json_progress = "";
	char retries[6]; /*json holder for retry_count*/
	char retry_message[128];
	char total_progress_json[512];
	int __retries = 0;

	if (!pv->remote || !update) {
		pv_log(WARN, "remote or update not initialized");
		goto out;
	}

	switch (status) {
	case UPDATE_QUEUED:
		if (update->pending)
			__retries = update->pending->retries;

		pv_log(DEBUG, "update queued, retry count is %d", __retries);
		if (__retries > 0) {
			snprintf(retries, sizeof(retries), "%d", __retries);
			sprintf(retry_message, "Update queued, retry %s of %d", retries,
					MAX_REVISION_RETRIES);
		} else
			sprintf(retry_message, "Update queued");
		sprintf(json, DEVICE_STEP_STATUS_FMT_WITH_DATA,
			"QUEUED", retry_message, 0, retries);
		if (update) {
			snprintf(update->retry_data,
				sizeof(update->retry_data), "%s", retries);
		}
		break;
	case UPDATE_DOWNLOADED:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Update objects downloaded", 40);
		break;
	case UPDATE_INSTALLED:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Update installed", 80);
		break;
	case UPDATE_TRY:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Starting updated version", 95);
		break;
	case UPDATE_TRANSITION:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Transitioning to new revision without rebooting", 95);
		break;
	case UPDATE_REBOOT:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Rebooting", 95);
		break;
	case UPDATE_UPDATED:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"UPDATED", "Update finished, revision not set as rollback point", 100);
		break;
	case UPDATE_DONE:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"DONE", "Update finished, revision set as rollback point", 100);
		break;
	case UPDATE_NO_DOWNLOAD:
		if (!msg)
			msg = "Unable to download and/or install update";
		sprintf(json, DEVICE_STEP_STATUS_FMT, "WONTGO", msg, 0);
		break;
	case UPDATE_NO_PARSE:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"WONTGO", "Remote state cannot be parsed", 0);
		break;
	case UPDATE_RETRY_DOWNLOAD:
		//BUG_ON(!update)
		if (update->pending->retries) {
			snprintf(retry_message, sizeof(retry_message),
				"Network unavailable while downloading "
				"(%d/%d)",update->pending->retries,
				MAX_REVISION_RETRIES);
		} else {
			snprintf(retry_message, sizeof(retry_message),
				"Network unavailable while downloading. Retrying shortly");
		}
		snprintf(retries, sizeof(retries), "%d",
				update->pending->retries);
		sprintf(json, DEVICE_STEP_STATUS_FMT_WITH_DATA,
			"QUEUED", retry_message, 0, retries);

		snprintf(update->retry_data,
				sizeof(update->retry_data), "%s", retries);
		/*
		 * Clear what was downloaded.
		 */
		update->total_update->total_downloaded = 0;
		break;
	case UPDATE_TESTING_REBOOT:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"TESTING", "Awaiting to set rollback point if update is stable", 95);
		break;
	case UPDATE_TESTING_NONREBOOT:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"TESTING", "Awaiting to see if update is stable", 95);
		break;
	case UPDATE_DOWNLOAD_PROGRESS:
		/*
		 * check if there is retry data pending.
		 */
		if (strlen(update->retry_data))
			json_progress = update->retry_data;

		if (update->total_update) {
			object_update_json(update->total_update,
					total_progress_json, sizeof(total_progress_json));
		}
		if (update->progress_objects) {
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
				json = (char*)calloc(1, 
						PATH_MAX + update->progress_size);
			}
			/*
			 * we must post the total
			 */
			if (!json)
				json = __json;
			/*
			 * just post the total and bail out.
			 */
			if (__json == json) {
				sprintf(json, DEVICE_STEP_STATUS_FMT_PROGRESS_DATA,
						"DOWNLOADING", "Progress", 0, json_progress,
						total_progress_json,
						"");
				break;
			}
			if (msg) {
				if (len) {
					strncat(buff + len, ",", 1);
					len += 1;
				}
				snprintf(buff + len,
						pv->update->progress_size - len, "%s", msg);
				len = (len > 0 ? len - 1 : len);
			}
			sprintf(json, DEVICE_STEP_STATUS_FMT_PROGRESS_DATA,
					"DOWNLOADING", "Progress", 0, json_progress,
					total_progress_json,
					update->progress_objects);
			update->progress_objects[len] = '\0';
		}
		break;
	default:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"ERROR", "Error during update", 0);
		break;
	}

	req = trest_make_request(TREST_METHOD_PUT,
				 update->endpoint,
				 0, 0,
				 json);

	res = trest_do_json_request(pv->remote->client, req);

	if (!res) {
		pv_log(INFO, "unable to do trail request");
		ret = -1;
		goto out;
	}

	if (res->code == THTTP_STATUS_OK) {
		pv_log(INFO, "remote state updated to %s", res->body);
	} else {
		pv_log(WARN, "unable to update remote status, http code %d", res->code);
		ret = -1;
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

static trest_response_ptr trail_get_steps_response(struct pantavisor *pv,
							char *endpoint)
{
	trest_request_ptr req = NULL;
	trest_response_ptr res = NULL;
	struct trail_remote *remote = NULL;
	int size = 0;

	if (!endpoint || !pv)
		goto out;
	remote = pv->remote;
	req = trest_make_request(TREST_METHOD_GET,
			endpoint,
			0, 0, 0);

	res = trest_do_json_request(remote->client, req);
	if (!res) {
		pv_log(INFO, "unable to do trail request");
		goto out;
	}
	if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "http error (%d) on trail request", res->code);
		goto out;
	}
	size = jsmnutil_array_count(res->body, res->json_tokv);
	if (!size)
		goto out;

	pv_log(DEBUG, "%d steps found", size);
	trest_request_free(req);
	return res;
out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	return NULL;
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
			pv_log(INFO, "retry_count = %s", retry_count);
			sscanf(retry_count, "%d", ctx->retries);
			free(retry_count);
		}
	}
	return ret;
}

static struct pv_update* pv_update_new(char *id, int rev)
{
	struct pv_update *u;

	u = calloc(1, sizeof(struct pv_update));
	if (u) {
		u->total_update = (struct object_update*) calloc(1, sizeof(struct object_update));
		u->progress_size = PATH_MAX;
		u->progress_objects = (char*)calloc(1, u->progress_size);
		u->status = UPDATE_INIT;

		// to construct endpoint
		u->endpoint = malloc((sizeof(DEVICE_STEP_ENDPOINT_FMT)
					+ (strlen(id))
					+ get_digit_count(rev)) * sizeof(char));
		sprintf(u->endpoint, DEVICE_STEP_ENDPOINT_FMT, id, rev);
	}

	return u;
}

static int trail_get_new_steps(struct pantavisor *pv)
{
	int rev = 0, ret = 0;
	char *state = 0, *rev_s = 0;
	struct trail_remote *remote = pv->remote;
	trest_response_ptr res = 0;
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

	// check for QUEUED updates
	res = trail_get_steps_response(pv, remote->endpoint_trail_queued);
	if (res) {
		pv_log(DEBUG, "found QUEUED revision");
		if (start_json_parsing_with_action(res->body, jka, JSMN_ARRAY))
			pv_log(WARN, "failed to parse QUEUED revision");
		goto process_response;
	}

new_update:
	// check for NEW updates
	res = trail_get_steps_response(pv, remote->endpoint_trail_new);
	if (res) {
		pv_log(DEBUG, "found NEW revision");
		if (start_json_parsing_with_action(res->body, jka, JSMN_ARRAY))
			pv_log(WARN, "failed to parse NEW revision");
	}

process_response:
	if (res) {
		rev_s = get_json_key_value(res->body, "rev",
				res->json_tokv, res->json_tokc);
		state = get_json_key_value(res->body, "state",
				res->json_tokv, res->json_tokc);
	} else {
		pv_log(DEBUG, "no steps to process found, continuing");
		goto out;
	}

	if (!rev_s || !state) {
		pv_log(WARN, "invalid or no data found on trail, ignoring");
		goto out;
	}

	rev = atoi(rev_s);
	pv_log(DEBUG, "parse rev %d with json state = '%s'", rev, state);

	// create temp update to be able to report the revision state
	update = pv_update_new(pv->config->creds.id, rev);
	if (!update)
		goto out;

	// parse state
	update->pending = pv_state_parse(pv, state, rev);
	if (!update->pending) {
		pv_log(INFO, "invalid rev (%d) found on remote", rev);
		trail_remote_set_status(pv, update, UPDATE_NO_PARSE, NULL);
		pv_update_free(update);
		goto out;
	}

	// if update is not going on, we prepare this one to be installed
	if (!pv->update) {
		pv->update = update;
		pv_log(DEBUG, "first pending step found is rev %d", pv->update->pending->rev);
		pv_update_set_status(pv, UPDATE_QUEUED);
		ret = 1;
	// if update is going on, just report the update as QUEUED
	} else {
		trail_remote_set_status(pv, update, UPDATE_QUEUED, NULL);
		pv_update_free(update);
	}


out:
	if (rev_s)
		free(rev_s);
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
	int size = 0;

	if (!r)
		return -1;

	req = trest_make_request(TREST_METHOD_GET,
				 "/trails/",
				 0, 0, 0);

	res = trest_do_json_request(r->client, req);

	if (!res) {
		pv_log(INFO, "unable to do trail request");
		size = -1;
		goto out;
	}

	if (res->code != THTTP_STATUS_OK || res->body == NULL) {
		size = -1;
		goto out;
	}

	size = jsmnutil_array_count(res->body, res->json_tokv);
	if (size)
		pv_log(DEBUG, "trail found, using remote");

out:
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
	error = get_json_key_value(buf,
			"error",
			tokv,
			tokc);

	msg = get_json_key_value(buf,
			"msg",
			tokv,
			tokc);

	__code = get_json_key_value(buf,
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

static int trail_put_object(struct pantavisor *pv, struct pv_object *o, const char **crtfiles)
{
	int ret = 0;
	int fd, bytes;
	int size, pos, i;
	char *signed_puturl = NULL;
	char sha_str[128];
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
		pos += sprintf(sha_str+pos, "%02x", local_sha[i]);
		i++;
	}

	sprintf(body,
		"{ \"objectname\": \"%s\","
		" \"size\": \"%d\","
		" \"sha256sum\": \"%s\""
		" }",
		o->name,
		size,
		sha_str);

	pv_log(INFO, "syncing '%s'", o->id, body);

	if (strcmp(o->id,sha_str)) {
		pv_log(INFO, "sha256 mismatch, probably writable image, skipping", o->objpath);
		goto out;
	}

	treq = trest_make_request(TREST_METHOD_POST,
				"/objects/",
				0,
				0,
				body);

	tres = trest_do_json_request(pv->remote->client, treq);
	if (!tres) {
		pv_log(ERROR, "'%s' could not be registered, request error", o->id);
		ret = -1;
		goto out;
	}

	if (tres->code == THTTP_STATUS_CONFLICT) {
		pv_log(INFO, "'%s' already owned by user, skipping", o->id);
		goto out;
	}

	if (tres->code != THTTP_STATUS_OK) {
		pv_log(ERROR, "'%s' could not be registered, code=%d", o->id, tres->code);
		ret = -1;
		goto out;
	}

	signed_puturl = get_json_key_value(tres->body,
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
		req->host = pv->config->creds.host;
		req->port = pv->config->creds.port;
		req->user_agent = pv_user_agent;

		req->path = strstr(signed_puturl, "/local-s3");

		req->headers = NULL;
		req->body_content_type = "application/json";
		lseek(fd, 0, SEEK_SET);
		req->fd = fd;
		req->len = size;

		pv_log(INFO, "'%s' does not exist, uploading", o->id);

		res = thttp_request_do(req);

		if (!res) {
			pv_log(ERROR, "'%s' could not be uploaded, request error", o->id);
			ret = -1;
			goto out;
		}

		if (res->code != THTTP_STATUS_OK) {
			pv_log(ERROR, "'%s' could not be uploaded, code=%d", o->id, res->code);
			ret = -1;
			goto out;
		}

		pv_log(INFO, "'%s' uploaded correctly, size=%d, code=%d", o->id, size, res->code);
	}
	else {
		pv_log(ERROR, "'%s' could not be registered, signed_puturl not retrieved", o->id);
		ret = -1;
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
	int ret = 0;
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

	req = trest_make_request(TREST_METHOD_POST, "/trails/", 0, 0, pv->step);
	res = trest_do_json_request(pv->remote->client, req);

	if (!res) {
		pv_log(ERROR, "error on first boot json request");
		ret = -1;
		goto out;
	}

	if (res->code != THTTP_STATUS_OK) {
		pv_log(ERROR, "http request error (%d) for initial trail", res->code);
		ret = -1;
		goto out;
	}

	pv_log(INFO, "factory revision (base trail) pushed to remote correctly");
	ret = 0;

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

/* API */

int pv_check_for_updates(struct pantavisor *pv)
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

	/*
	 * [PKS]
	 * Improve first boot object upload,
	 * on an error case this won't be retried.
	 */
	ret = trail_is_available(pv->remote);
	if (ret == 0)
		return trail_first_boot(pv);
	else if (ret > 0)
		return trail_get_new_steps(pv);
	else
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

	pv->update->status = status;

	if (!pv->online || trail_remote_init(pv)) {
		pv_log(WARN, "status will not be send to cloud");
		return 0;
	}

	return trail_remote_set_status(pv, pv->update, status, msg);
}

int pv_update_set_status(struct pantavisor *pv, enum update_state status)
{
	return pv_update_set_status_msg(pv, status, NULL);
}

static int pv_update_start(struct pantavisor *pv)
{
	if (pv->update && pv->update->status == UPDATE_QUEUED) {
		int time_left = pv->update->retry_at - time(NULL);

		if (time_left <= 0) {
			pv->update->pending->retries++;
			pv_log(INFO, "trying revision %d ,retry = %d",
					pv->update->pending->rev, pv->update->pending->retries);
			// set timer for next retry
			pv->update->retry_at = time(NULL) + DOWNLOAD_RETRY_WAIT;
			return 0;
		}

		pv_log(INFO, "retrying in %d seconds", time_left);
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
	case UPDATE_TESTING_REBOOT:
	case UPDATE_TRY:
		pv_update_set_status(pv, UPDATE_TESTING_REBOOT);
		break;
	case UPDATE_TESTING_NONREBOOT:
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
		pv_revision_set_failed();
		pv_update_set_status(pv, UPDATE_FAILED);
		pv_update_remove(pv);
		pv_log(INFO, "update finished");
		break;
	case UPDATE_RETRY_DOWNLOAD:
		if (pv->update->pending->retries >= MAX_REVISION_RETRIES) {
			pv_update_set_status(pv, UPDATE_NO_DOWNLOAD);
			pv_update_remove(pv);
			pv_log(INFO, "update finished");
			return 0;
		}
		break;
	case UPDATE_TESTING_REBOOT:
		if (pv_revision_set_commited(pv->state->rev)) {
			pv_log(ERROR, "revision for next boot could not be set");
			return -1;
		}
		pv_update_set_status(pv, UPDATE_DONE);
		// we keep this here so we can rollback to new DONE revisions from old pantavisor versio
		pv_set_rev_done(pv, pv->state->rev);
		pv_update_remove(pv);
		pv_log(INFO, "update finished");
		break;
	case UPDATE_TESTING_NONREBOOT:
		pv_update_set_status(pv, UPDATE_UPDATED);
		pv_update_remove(pv);
		pv_log(INFO, "update finished");
		break;
	default:
		pv_log(WARN, "update finished during wrong state %d", pv->update->status);
		break;
	}

	return 0;
}

static int trail_download_get_meta(struct pantavisor *pv, struct pv_object *o)
{
	int ret = 0;
	char *endpoint = 0;
	char *url = 0;
	char *prn, *size;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!o)
		goto out;

	prn = o->id;

	endpoint = malloc((sizeof(TRAIL_OBJECT_DL_FMT) + strlen(prn)) * sizeof(char));
	sprintf(endpoint, TRAIL_OBJECT_DL_FMT, prn);

	pv_log(DEBUG, "requesting obj='%s'", endpoint);

	req = trest_make_request(TREST_METHOD_GET,
				 endpoint,
				 0, 0, 0);

	res = trest_do_json_request(pv->remote->client, req);
	if (!res) {
		pv_log(WARN, "unable to do trail request");
		goto out;
	}
	if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "http request error (%d) on object metadata", res->code);
		goto out;
	}

	size = get_json_key_value(res->body, "size",
			res->json_tokv, res->json_tokc);
	if (size)
		o->size = atoll(size);

	o->sha256 = get_json_key_value(res->body, "sha256sum",
				 res->json_tokv, res->json_tokc);

	url = get_json_key_value(res->body, "signed-geturl",
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

	return ret;
}

static int obj_is_kernel_pvk(struct pantavisor *pv, struct pv_object *obj)
{
	if (strcmp(pv->state->bsp.kernel, obj->name))
		return 0;

	if (pv->config->bl.type == BL_UBOOT_PVK)
		return 1;

	return 0;
}

static int copy_and_close(int s_fd, int d_fd)
{
	int bytes_r = 0, bytes_w = 0;
	char buf[4096];

	lseek(s_fd, 0, SEEK_SET);
	lseek(d_fd, 0, SEEK_SET);

	while (bytes_r = read(s_fd, buf, sizeof(buf)), bytes_r > 0)
		bytes_w += write(d_fd, buf, bytes_r);

	close(s_fd);

	pv_log(INFO, "  bytes_r=%d bytes_w=%d", bytes_r, bytes_w);

	return bytes_r;
}

struct progress_update {
	time_t next_update_at;
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
	pv_log(INFO, "update size: %" PRIu64 " bytes", size);

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
	if (progress_update->next_update_at > time(NULL)) {
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
	progress_update->next_update_at = time(NULL) + UPDATE_PROGRESS_FREQ;
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

	req->path = obj->geturl;
	req->headers = 0;

	if (!strcmp(pv->config->storage.fstype, "jffs2") ||
	    !strcmp(pv->config->storage.fstype, "ubifs"))
		use_volatile_tmp = 1;

	// temporary path where we will store the file until validated
	sprintf(mmc_tmp_obj_path, MMC_TMP_OBJ_FMT, obj->objpath);
	obj_fd = open(mmc_tmp_obj_path, O_CREAT | O_RDWR, 0644);

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
	progress_update.next_update_at = object_update.start_time + 
						UPDATE_PROGRESS_FREQ;
	res = thttp_request_do_file_with_cb (req, fd,
			trail_download_object_progress, &progress_update);
	if (!res) {
		pv_log(WARN, "no response from server");
		remove(mmc_tmp_obj_path);
		goto out;
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "error response from server, http code %d", res->code);
		remove(mmc_tmp_obj_path);
		goto out;
	}

	if (use_volatile_tmp) {
		pv_log(INFO, "copying %s to tmp path (%s)", volatile_tmp_obj_path, mmc_tmp_obj_path);
		bytes = copy_and_close(volatile_tmp_fd, obj_fd);
		fd = obj_fd;
	}
	pv_log(INFO, "downloaded object to tmp path (%s)", mmc_tmp_obj_path);
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
	syncdir(mmc_tmp_obj_path);

	pv_log(INFO, "verified object (%s), renaming from (%s)", obj->objpath, mmc_tmp_obj_path);
	rename(mmc_tmp_obj_path, obj->objpath);

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
				strncat(pv->update->progress_objects, ",", 1);
				data_len += 1;
			}
			sprintf(pv->update->progress_objects + data_len,"%s",
					this_obj_json);
		} else {
			pv_log(ERROR, "Failed to allocate space for progress data");
		}
		pv_log(DEBUG, "retry_data is %s", 
				pv->update->retry_data);
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
	int err = 0;
	struct pv_object *obj = NULL;
	char *c, *tmp, *ext;

	pv_objects_iter_begin(pv->update->pending, obj) {
		tmp = strdup(obj->relpath);
		c = strrchr(tmp, '/');
		*c = '\0';
		mkdir_p(tmp, 0755);
		free(tmp);
	        ext = strrchr(obj->relpath, '.');
		if (ext && (strcmp(ext, ".bind") == 0)) {
			int s_fd, d_fd;
			s_fd = open(obj->objpath, O_RDONLY);
			d_fd = open(obj->relpath, O_CREAT | O_WRONLY | O_SYNC, 0644);
			pv_log(INFO, "copying bind volume '%s' from '%s'", obj->relpath, obj->objpath);
			copy_and_close(s_fd, d_fd);
			continue;
		}
		if (link(obj->objpath, obj->relpath) < 0) {
			if (errno != EEXIST)
				err++;
			pv_log(ERROR, "unable to link %s, errno=%d",
				obj->relpath, errno);
		} else {
			syncdir(obj->objpath);
			pv_log(INFO, "linked %s to %s",
				obj->relpath, obj->objpath);
		}
	}
	pv_objects_iter_end;

	err += pv_meta_link_boot(pv, pv->update->pending);

	return -err;
}



static int trail_download_objects(struct pantavisor *pv)
{
	int ret = -1;
	struct pv_object *k_new, *k_old;
	struct pv_update *u = pv->update;
	struct pv_object *o = NULL;
	const char **crtfiles = pv_ph_get_certs(pv);

	pv_objects_iter_begin(u->pending, o) {
		if (!trail_download_get_meta(pv, o)) {
			ret = TRAIL_NO_NETWORK;
			goto out;
		}
	}
	pv_objects_iter_end;

	// Check free space for update
	if (!pv_storage_get_free(pv, get_update_size(u))) {
		// Run GC as last resort
		pv_storage_gc_run(pv);
		// Check again
		if (!pv_storage_get_free(pv, get_update_size(u))) {
			pv_log(WARN, "not enough space to process update");
			ret = TRAIL_NO_SPACE;
			goto out;
		}
	}

	k_new = pv_objects_get_by_name(u->pending,
			u->pending->bsp.kernel);
	k_old = pv_objects_get_by_name(pv->state,
			pv->state->bsp.kernel);


	if (u->total_update) {
		u->total_update->object_name = "total";
		u->total_update->object_id = "none";
		u->total_update->total_size = get_update_size(u);
		u->total_update->start_time = time(NULL);
		u->total_update->total_downloaded = 0;
	}
	pv_objects_iter_begin(u->pending, o) {
		if (!trail_download_object(pv, o, crtfiles)) {
			ret = TRAIL_NO_NETWORK;
			goto out;
		}
		u->total_update->current_time = time(NULL);
		pv_update_set_status(pv, UPDATE_DOWNLOAD_PROGRESS);
	}
	pv_objects_iter_end;
	ret = 0;

out:
	return ret;
}

int pv_update_install(struct pantavisor *pv)
{
	int ret = -1, fd;
	struct pv_state *pending = pv->update->pending;
	char path[PATH_MAX];
	char path_new[PATH_MAX];
	char *msg = NULL;

	if (trail_remote_init(pv)) {
		pv_log(WARN, "remote not initialized");
		goto out;
	}

	if (!pv || !pv->state || !pv->update || !pv->update->pending) {
		pv_log(WARN, "uninitialized state or update");
		goto out;
	}

	pv_log(INFO, "starting update...");

	if (pv_update_start(pv))
		goto out;

	pv_log(INFO, "downloading update...");
	ret = trail_download_objects(pv);

	if (ret < 0) {
		pv_log(ERROR, "unable to download objects");
		if (ret == TRAIL_NO_NETWORK)
			pv_update_set_status(pv, UPDATE_RETRY_DOWNLOAD);
		else {
			/*
			 * Required space wasn't available.
			 * reusing, path to store message.
			 */
			uint64_t reqd_bytes = (uint64_t)get_update_size(pv->update);
			uint64_t have_bytes = (uint64_t)pv_storage_get_free(pv, 0);
			const uint32_t one_mib = (1024 * 1024);

			msg = path;
			sprintf(msg, "Space required %"PRIu64".%"PRIu64" MB"
					",available %"PRIu64".%"PRIu64 " MB",
					reqd_bytes / one_mib,
					reqd_bytes % one_mib,
					have_bytes / one_mib,
					have_bytes % one_mib);
			pv_update_set_status_msg(pv, UPDATE_NO_DOWNLOAD, msg);
		}
		goto out;
	}

	pv_update_set_status(pv, UPDATE_DOWNLOADED);

	pv_log(INFO, "installing update...");

	// make sure target directories exist
	sprintf(path, "%s/trails/%d/.pvr", pv->config->storage.mntpoint, pending->rev);
	mkdir_p(path, 0755);
	sprintf(path, "%s/trails/%d/.pv", pv->config->storage.mntpoint, pending->rev);
	mkdir_p(path, 0755);

	ret = trail_link_objects(pv);
	if (ret < 0) {
		pv_log(ERROR, "unable to link objects to relative path (failed=%d)", ret);
		pv_update_set_status(pv, UPDATE_FAILED);
		goto out;
	}

	// install state.json for new rev
	sprintf(path_new, "%s/trails/%d/.pvr/json.new", pv->config->storage.mntpoint, pending->rev);
	sprintf(path, "%s/trails/%d/.pvr/json", pv->config->storage.mntpoint, pending->rev);
	fd = open(path_new, O_CREAT | O_WRONLY | O_SYNC | O_TRUNC, 0644);
	if (fd < 0) {
		pv_log(ERROR, "unable to write state.json file for update");
		ret = -1;
		goto out;
	}
	write_nointr(fd, pending->json, strlen(pending->json));
	close(fd);
	rename(path_new, path);

	if (!pv_meta_expand_jsons(pv, pending)) {
		pv_log(ERROR, "unable to install platform and pantavisor jsons");
		ret = -1;
		goto out;
	}

	ret = pending->rev;
	pv_log(INFO, "update successfully installed");
	if (pv_revision_set_installed(ret)) {
		pv_log(ERROR, "unable to write pv_try to boot cmd env");
		ret = -1;
		goto out;
	}

	pv_update_set_status(pv, UPDATE_INSTALLED);

	pv->update->runlevel = pv_state_compare_states(pending, pv->state);
	pv_log(INFO, "update runlevel set to %d", pv->update->runlevel);
out:
	if (pending && (ret < 0))
		pv_storage_rm_rev(pv, pending->rev);

	return ret;
}

int pv_update_resume(struct pantavisor *pv)
{
	int rev;

	// If update exist, it means we come from a non reboot start
	if (pv->update)
		return pv->update->runlevel;

	// If update is in progress, we are going to load it to report its completion or failure
	if (pv_revision_update_in_progress()) {
		rev = pv_revision_get_try();
		pv_log(INFO, "loading update data from rev %d after reboot...", rev);
		pv->update = pv_update_new(pv->config->creds.id, rev);
		if (!pv->update)
			return -1;

		if (pv_revision_trying_update())
			pv_update_set_status(pv, UPDATE_TRY);
		else
			pv_update_set_status(pv, UPDATE_FAILED);
	}

	return 0;
}

bool pv_update_requires_reboot(struct pantavisor *pv)
{
	// we reboot for changes with explicitly configured "root" platforms and non-configured ones
	if (pv->update->runlevel <= 1) {
		pv_log(WARN, "update runlevel %d requires reboot, rebooting...",
			pv->update->runlevel);
		pv_update_set_status(pv, UPDATE_REBOOT);
		return true;
	}

	pv_log(WARN, "update runlevel %d does not require reboot, running new revision...",
		pv->update->runlevel);
	pv_update_set_status(pv, UPDATE_TRANSITION);
	return false;
}

bool pv_update_is_transitioning(struct pv_update *u)
{
	return (u && u->status == UPDATE_TRANSITION);
}

bool pv_update_is_testing(struct pv_update *u)
{
	return (u &&
		((u->status == UPDATE_TESTING_REBOOT) ||
		(u->status == UPDATE_TESTING_NONREBOOT)));
}


static int pv_update_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	int ret = -1;

	pv = get_pv_instance();

	if (!pv || !pv->config)
		goto out;
	config = pv->config;
	if (config->revision_retries <= 0) MAX_REVISION_RETRIES = DEFAULT_MAX_REVISION_RETRIES;
	else
		MAX_REVISION_RETRIES = config->revision_retries;

	if (config->revision_retry_timeout <= 0)
		DOWNLOAD_RETRY_WAIT = DEFAULT_DOWNLOAD_RETRY_WAIT;
	else
		DOWNLOAD_RETRY_WAIT = config->revision_retry_timeout;

	if (config->update_commit_delay <= 0)
		config->update_commit_delay = DEFAULT_UPDATE_COMMIT_DELAY;

	ret = 0;
out:
	return 0;
}

struct pv_init pv_init_update = {
	.init_fn = pv_update_init,
	.flags = 0,
};
