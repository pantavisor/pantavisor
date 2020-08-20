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

int MAX_REVISION_RETRIES = 0;
int DOWNLOAD_RETRY_WAIT = 0;

static struct trail_object *head;
static struct trail_object *last;

typedef int (*token_iter_f) (void *d1, void *d2, char *buf, jsmntok_t* tok, int c);

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

	client = pv_get_trest_client(pv, NULL);

	if (!client) {
		pv_log(INFO, "unable to create device client");
		goto err;
	}

	// FIXME: Crash here if unable to auth
	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "unable to auth device client");
		goto err;
	}

	remote = malloc(sizeof(struct trail_remote));
	remote->client = client;

	remote->endpoint = malloc((sizeof(DEVICE_TRAIL_ENDPOINT_FMT)
				   + strlen(pv->config->creds.id)) * sizeof(char));
	sprintf(remote->endpoint, DEVICE_TRAIL_ENDPOINT_FMT, pv->config->creds.id);

	pv->remote = remote;

	return 0;

err:
	if (client)
		free(client);
	if (remote)
		free(remote);

	return -1;
}

static int trail_remote_set_status(struct pantavisor *pv, int rev, enum update_state status)
{
	int ret = 0;
	struct pv_update *pending_update = pv->update;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;
	char json[1024];
	char retries[6]; /*We wouldn't want a very big number here anyway*/
	char *endpoint;
	char retry_message[128];

	if (!pending_update) {
		endpoint = malloc(sizeof(DEVICE_STEP_ENDPOINT_FMT) +
			strlen(pv->config->creds.id) + get_digit_count(rev));
		sprintf(endpoint, DEVICE_STEP_ENDPOINT_FMT, pv->config->creds.id, rev);
	} else {
		endpoint = pending_update->endpoint;
	}

	if (!pv->remote)
		trail_remote_init(pv);

	if (!pv->remote)
		goto out;

	switch (status) {
	case UPDATE_QUEUED:
		if (pending_update)
			snprintf(retries, sizeof(retries), "%d", pending_update->pending->retries);
		else
			sprintf(retries, "%d", 0);
		pv_log(DEBUG, "Update queued, retry count is %s", retries);
		sprintf(retry_message, "Update queued (%s/%d)", retries,
				MAX_REVISION_RETRIES);
		sprintf(json, DEVICE_STEP_STATUS_FMT_WITH_DATA,
			"QUEUED", retry_message, 0, retries);
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
			"INPROGRESS", "Starting updated version", 90);
		break;
	case UPDATE_REBOOT:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"INPROGRESS", "Rebooting", 95);
		break;
	case UPDATE_DONE:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"DONE", "Update finished", 100);
		break;
	case UPDATE_NO_DOWNLOAD:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"WONTGO", "Unable to download and/or install update", 0);
		break;
	case UPDATE_NO_PARSE:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"WONTGO", "Remote state cannot be parsed", 0);
		break;
	case UPDATE_RETRY_DOWNLOAD:
		//BUG_ON(!u)
		if (pending_update->pending->retries) {
			snprintf(retry_message, sizeof(retry_message),
				"Network unavailable while downloading "
				"(%d/%d)",pending_update->pending->retries,
				MAX_REVISION_RETRIES);
		} else {
			snprintf(retry_message, sizeof(retry_message),
				"Network unavailable while downloading. Retrying shortly");
		}
		snprintf(retries, sizeof(retries), "%d", pending_update->pending->retries);
		sprintf(json, DEVICE_STEP_STATUS_FMT_WITH_DATA,
			"QUEUED", retry_message, 0, retries);
		break;
	case UPDATE_DEVICE_AUTH_OK:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"AUTHENTICATED", "Device Login Successful.", 0);
		break;
	case UPDATE_DEVICE_COMMIT_WAIT:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"UPDATED", "Awaiting update commit.",0);
		break;
	default:
		sprintf(json, DEVICE_STEP_STATUS_FMT,
			"ERROR", "Error during update", 0);
		break;
	}

	req = trest_make_request(TREST_METHOD_PUT,
				 endpoint,
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
	if (!pending_update && endpoint)
		free(endpoint);
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

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

	pv_log(DEBUG, "steps found in NEW state = '%d'", size);
	trest_request_free(req);
	return res;
out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	return NULL;
}

static int trail_get_new_steps(struct pantavisor *pv)
{
	int rev = 0, ret = 0;
	char *state = 0, *rev_s = 0;
	struct trail_remote *remote = pv->remote;
	trest_response_ptr res = 0;
	jsmntok_t *tokv = 0;
	char *retry_endpoint = NULL;
	int retries = 0;
	bool update_pending = false;

	if (!remote)
		return 0;
	if (pv->update)
		return 1; /*A revision is pending, let's take care of that.*/
	/*
	 * Check for pending updates first.
	 * */
	retry_endpoint = (char*)calloc(1, strlen(remote->endpoint)
			+ sizeof(DEVICE_TRAIL_ENDPOINT_QUERY));
	if (retry_endpoint) {
		sprintf(retry_endpoint, "%s%s",remote->endpoint,DEVICE_TRAIL_ENDPOINT_QUERY);
		res = trail_get_steps_response(pv, retry_endpoint);
		if (res) {
			char *data = NULL;

			update_pending = true;
			data = get_json_key_value(res->body, "progress",
					res->json_tokv, res->json_tokc);
			if (data) {
				jsmntok_t *tokv = 0;
				int toks_out = 0;

				if (jsmnutil_parse_json(data, &tokv, &toks_out)>=0) {
					char *__retries = get_json_key_value(data,"data", tokv, toks_out);
					if (__retries) {
						sscanf(__retries, "%d", &retries);
						free(__retries);
					}
					if (tokv)
						free(tokv);
				}
				free(data);
				data = NULL;
			}
		}
		free(retry_endpoint);
		retry_endpoint = NULL;
	}

	/*
	 * If there's no QUEUED ones, check for
	 * any NEW ones.
	 * */
	if (!update_pending)
		res = trail_get_steps_response(pv, remote->endpoint);

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

	// parse state
	rev = atoi(rev_s);
	remote->pending = pv_state_parse(pv, state, rev);

	if (!remote->pending) {
		pv_log(INFO, "invalid rev (%d) found on remote", rev);
		trail_remote_set_status(pv, rev, UPDATE_NO_PARSE);
	} else {
		pv_log(DEBUG, "adding rev (%d), state = '%s'", rev, state);
		pv_log(DEBUG, "first pending found to be rev = %d", remote->pending->rev);
		retries++; /*Add one since we're now retrying this.*/
		remote->pending->retries = retries;
		pv_log(DEBUG, "current retry count  = %d", retries);
		if (retries > MAX_REVISION_RETRIES) {
			pv_log(WARN, "Revision %d exceeded download retries."
					"Max set at %d, current attempt =%d", rev, MAX_REVISION_RETRIES, retries);
			trail_remote_set_status(pv, rev, UPDATE_FAILED);
			pv_state_free(remote->pending);
			remote->pending = NULL;
		}
	}
	ret = 1;/*A revision is pending, either a new one or a queued one*/
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
	trest_auth_status_enum auth_status;

	if (!pv->remote)
		trail_remote_init(pv);

	// Offline
	if (!pv->remote)
		return 0;

	auth_status = trest_update_auth(pv->remote->client);
	if (auth_status != TREST_AUTH_STATUS_OK) {
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

int pv_update_set_status(struct pantavisor *pv, enum update_state status)
{
	if (!pv) {
		pv_log(WARN, "uninitialized pantavisor object");
		return 0;
	}

	if (!pv->update) {
		pv_log(WARN, "invalid update in current state");
		return 0;
	}

	pv->update->status = status;

	return 1;
}
/*
 * Return value
 * -ve for error,
 *  0 for success,
 * +ve for retry time not yet reached.
 * */
int pv_update_start(struct pantavisor *pv, int offline)
{
	int c;
	int ret = -1, rev = -1;
	struct pv_update *u;

	if (!pv) {
		pv_log(WARN, "uninitialized pantavisor object");
		goto out;
	}

	if (!pv->state) {
		pv_log(WARN, "invalid pantavisor state");
		goto out;
	}

	/*
	 * From a retry.
	 * */
	if (pv->update) {
		if (time(NULL) >=  pv->update->retry_at) {
			pv->update->pending->retries++;
			ret = 0;
			if (!offline)
				trail_remote_set_status(pv, -1, pv->update->status);

			pv_log(INFO, "Retrying revision %d ,turn = %d",
					pv->update->pending->rev, pv->update->pending->retries);
			goto update_status;
		}
		else {
			ret = 1;
		}
		goto out;
	}

	u = calloc(sizeof(struct pv_update), 1);

	head = NULL;
	last = NULL;

	// Offline update
	if (!pv->remote && offline) {
		rev = pv->state->rev;
	} else {
		u->pending = pv->remote->pending;
		rev = u->pending->rev;
	}

	// to construct endpoint
	c = get_digit_count(rev);
	u->endpoint = malloc((sizeof(DEVICE_STEP_ENDPOINT_FMT)
		          + (strlen(pv->config->creds.id)) + c) * sizeof(char));
	sprintf(u->endpoint, DEVICE_STEP_ENDPOINT_FMT,
		pv->config->creds.id, rev);

	// FIXME: currently we only support strict (always rebot) updates
	u->need_reboot = 1;
	u->need_finish = 0;
	pv->update = u;

	// all done up to here for offline
	ret = 0;

update_status:
	if (!offline) {
		ret = trail_remote_set_status(pv, -1, UPDATE_QUEUED);
		if (ret < 0)
			pv_log(INFO, "failed to update cloud status, possibly offline");
	}
out:
	return ret;
}

int pv_update_finish(struct pantavisor *pv)
{
	int ret = 0;

	switch (pv->update->status) {
	case UPDATE_DONE:
		ret = trail_remote_set_status(pv, -1, UPDATE_DONE);
		goto out;
		break;
	case UPDATE_REBOOT:
		pv_log(INFO, "update requires reboot, cleaning up...");
		goto out;
		break;
	case UPDATE_FAILED:
		ret = trail_remote_set_status(pv, -1, UPDATE_FAILED);
		pv_log(ERROR, "update has failed");
		goto out;
	case UPDATE_RETRY_DOWNLOAD:
		pv->update->retry_at = time(NULL) + DOWNLOAD_RETRY_WAIT;
		if (pv->update->pending->retries >= MAX_REVISION_RETRIES) {
			ret = trail_remote_set_status(pv, -1, UPDATE_FAILED);
			goto out;
		}
		pv_log(WARN, "Unable to download revision, retrying update in %d seconds",
				pv->update->retry_at);
		goto retry_update;
	case UPDATE_DEVICE_COMMIT_WAIT:
		ret = trail_remote_set_status(pv, -1, UPDATE_DEVICE_COMMIT_WAIT);
		pv_log(ERROR, "update has failed");
		break;
	default:
		ret = -1;
		goto out;
		break;
	}
out:
	if (pv->update->pending)
		pv_state_free(pv->update->pending);
	if (pv->update->endpoint)
		free(pv->update->endpoint);

	free(pv->update);

	pv->update = NULL;
retry_update:
	return ret;
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
	if (strcmp(pv->state->kernel, obj->name))
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

static int trail_update_has_new_initrd(struct pantavisor *pv)
{
	char *old = 0, *new = 0;
	struct pv_object *o_new = 0, *o_old = 0;

	if (!pv)
		return 0;

	if (pv->state)
		old = pv->state->initrd;

	if (pv->update && pv->update->pending)
		new = pv->update->pending->initrd;

	if (!old || !new)
		return 0;

	if (strcmp(old, new))
		return 1;

	o_new = pv_objects_get_by_name(pv->update->pending, new);
	o_old = pv_objects_get_by_name(pv->state, old);
	if (!o_new || !o_old)
		return 1;

	if (strcmp(o_new->id, o_old->id))
		return 1;

	return 0;
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
		mktemp(volatile_tmp_obj_path);
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
	res = thttp_request_do_file (req, fd);
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

	if (is_kernel_pvk)
		pv_bl_install_kernel(pv, volatile_tmp_obj_path);

	ret = 1;

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

static int get_update_size(struct pv_update *u)
{
	int size = 0;
	struct stat st;
	struct pv_object *curr = NULL;

	pv_objects_iter_begin(u->pending, curr) {
		if (stat(curr->objpath, &st) < 0)
			size += curr->size;
	}
	pv_objects_iter_end;
	pv_log(INFO, "update size: %d bytes", size);

	return size;
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

	// Run GC as last resort
	if (!pv_storage_get_free(pv, get_update_size(u)))
		pv_storage_gc_run(pv);

	// Check again
	if (!pv_storage_get_free(pv, get_update_size(u))) {
		pv_log(WARN, "not enough space to process update");
		ret = TRAIL_NO_SPACE;
		goto out;
	}

	k_new = pv_objects_get_by_name(u->pending,
			u->pending->kernel);
	k_old = pv_objects_get_by_name(pv->state,
			pv->state->kernel);

	if (k_new && k_old && strcmp(k_new->id, k_old->id))
		u->need_reboot = 1;

	pv_objects_iter_begin(u->pending, o) {
		if (!trail_download_object(pv, o, crtfiles)) {
			ret = TRAIL_NO_NETWORK;
			goto out;
		}
	}
	pv_objects_iter_end;

	ret = 0;

out:
	return ret;
}

int pv_update_install(struct pantavisor *pv)
{
	int ret, fd;
	struct pv_state *pending = pv->update->pending;
	char path[PATH_MAX];
	char path_new[PATH_MAX];

	if (!pv->remote)
		trail_remote_init(pv);

	if (!pending) {
		ret = -1;
		pv_log(ERROR, "update data is invalid");
		goto out;
	}

	pv_log(INFO, "applying update...");
	ret = trail_download_objects(pv);

	if (ret < 0) {
		pv_log(ERROR, "unable to download objects");
		if (ret == TRAIL_NO_NETWORK)
			pv->update->status = UPDATE_RETRY_DOWNLOAD;
		else
			pv->update->status = UPDATE_NO_DOWNLOAD;
		goto out;
	}

	trail_remote_set_status(pv, -1, UPDATE_DOWNLOADED);

	if (trail_update_has_new_initrd(pv))
		pv->update->need_reboot = 1;

	// make sure target directories exist
	sprintf(path, "%s/trails/%d/.pvr", pv->config->storage.mntpoint, pending->rev);
	mkdir_p(path, 0755);
	sprintf(path, "%s/trails/%d/.pv", pv->config->storage.mntpoint, pending->rev);
	mkdir_p(path, 0755);

	ret = trail_link_objects(pv);
	if (ret < 0) {
		pv_log(ERROR, "unable to link objects to relative path (failed=%d)", ret);
		pv->update->status = UPDATE_FAILED;
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

	trail_remote_set_status(pv, -1, UPDATE_INSTALLED);

	sleep(2);
	pv->update->status = UPDATE_TRY;
	ret = pending->rev;

	if (pv->update->need_reboot) {
		pv->update->status = UPDATE_REBOOT;
		pv_bl_set_try(pv, ret);
	}

out:
	trail_remote_set_status(pv, -1, pv->update->status);
	if (pending && (ret < 0))
		pv_storage_rm_rev(pv, pending->rev);

	return ret;
}

void pv_remote_destroy(struct pantavisor *pv)
{
	if (!pv->remote)
		return;

	free(pv->remote->client);
	free(pv->remote->endpoint);
	free(pv->remote);
}

int pv_set_current_status(struct pantavisor *pv, enum update_state state)
{
	return trail_remote_set_status(pv, pv->state->rev, state);
}

static int pv_update_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	int bl_rev = 0;
	int pv_rev = 0;
	int ret = -1;

	pv = get_pv_instance();

	if (!pv || !pv->config)
		goto out;
	config = pv->config;
	if (config->revision_retries <= 0)
		MAX_REVISION_RETRIES = DEFAULT_MAX_REVISION_RETRIES;
	else 
		MAX_REVISION_RETRIES = config->revision_retries;

	if (config->revision_retry_timeout <= 0)
		DOWNLOAD_RETRY_WAIT = DEFAULT_DOWNLOAD_RETRY_WAIT;
	else
		DOWNLOAD_RETRY_WAIT = config->revision_retry_timeout;

	if (config->update_commit_delay <= 0)
		config->update_commit_delay = DEFAULT_UPDATE_COMMIT_DELAY;

	// get try revision from bl
	bl_rev = pv_bl_get_try(pv);
	pv_rev = pv_revision_get_rev();

	if (bl_rev <= 0) {
		ret = 0;
		goto out;
	}
	if (bl_rev == pv_rev) {
		pv_update_start(pv, 1);
		pv_update_set_status(pv, UPDATE_TRY);
	} else {
		struct pv_state *s = pv->state;
		pv->state = pv_get_state(pv, bl_rev);
		if (pv->state) {
			pv_update_start(pv, 1);
			pv_update_set_status(pv, UPDATE_FAILED);
			pv_release_state(pv);
		}
		pv->state = s;
	}
	ret = 0;
out:
	return ret;
}

struct pv_init pv_init_update = {
	.init_fn = pv_update_init,
	.flags = 0,
};
