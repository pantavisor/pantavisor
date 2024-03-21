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
#include "utils/str.h"
#include "utils/fs.h"
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
#include "signature.h"
#include "logserver/logserver.h"

#define MODULE_NAME "updater"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define VOLATILE_TMP_OBJ_PATH "/tmp/object-XXXXXX"
#define MMC_TMP_OBJ_FMT "%s.tmp"

typedef int (*token_iter_f)(void *d1, void *d2, char *buf, jsmntok_t *tok,
			    int c);

void pv_update_free(struct pv_update *update)
{
	if (!update)
		return;

	pv_log(DEBUG, "removing update");

	if (update->endpoint)
		free(update->endpoint);
	if (update->rev)
		free(update->rev);
	if (update->pending) {
		pv_state_free(update->pending);
		update->pending = NULL;
	}

	free(update);
}

static void pv_update_remove(struct pantavisor *pv)
{
	if (!pv->update)
		return;

	pv_update_free(pv->update);
	pv->update = NULL;
}

// takes an allocated buffer
static char *unescape_utf8_to_apvii(char *buf, char *code, char c)
{
	char *p = 0;
	char *new_str = 0;
	char *old;
	int pos = 0, replaced = 0;
	char *tmp;

	size_t len = strlen(buf) + strlen(code) + 1;
	tmp = malloc(strlen(buf) + strlen(code) + 1);

	snprintf(tmp, len, "%s%s", buf, code);

	old = tmp;

	p = strstr(tmp, code);
	while (p) {
		*p = '\0';
		new_str = realloc(new_str, pos + strlen(tmp) + 2);
		snprintf(new_str + pos, strlen(tmp) + 2, "%s", tmp);
		pos = pos + strlen(tmp);
		new_str[pos] = c;
		pos += 1;
		new_str[pos] = '\0';
		replaced += 1;
		tmp = p + strlen(code);
		p = strstr(tmp, code);
	}

	if (new_str && new_str[strlen(new_str) - 1] == c)
		new_str[strlen(new_str) - 1] = '\0';

	if (old)
		free(old);
	if (buf)
		free(buf);

	return new_str;
}

static int trail_remote_init(struct pantavisor *pv)
{
	struct trail_remote *remote = NULL;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_ptr client = 0;
	char *endpoint_trail = NULL;
	int size = -1;

	if (pv->remote || !pv_config_get_creds_id())
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

	size = sizeof(DEVICE_TRAIL_ENDPOINT_FMT) +
	       strlen(pv_config_get_creds_id());
	endpoint_trail = malloc(size * sizeof(char));
	if (!endpoint_trail)
		goto err;
	SNPRINTF_WTRUNC(endpoint_trail, size, DEVICE_TRAIL_ENDPOINT_FMT,
			pv_config_get_creds_id());

	size = strlen(endpoint_trail) + sizeof(DEVICE_TRAIL_ENDPOINT_QUEUED);

	remote->endpoint_trail_queued = calloc(size, sizeof(char));
	if (!remote->endpoint_trail_queued)
		goto err;
	SNPRINTF_WTRUNC(remote->endpoint_trail_queued, size, "%s%s",
			endpoint_trail, DEVICE_TRAIL_ENDPOINT_QUEUED);

	size = strlen(endpoint_trail) + sizeof(DEVICE_TRAIL_ENDPOINT_NEW);

	remote->endpoint_trail_new = calloc(size, sizeof(char));
	if (!remote->endpoint_trail_new)
		goto err;
	SNPRINTF_WTRUNC(remote->endpoint_trail_new, size, "%s%s",
			endpoint_trail, DEVICE_TRAIL_ENDPOINT_NEW);

	size = strlen(endpoint_trail) +
	       sizeof(DEVICE_TRAIL_ENDPOINT_DOWNLOADING);
	remote->endpoint_trail_downloading = calloc(size, sizeof(char));
	if (!remote->endpoint_trail_downloading)
		goto err;
	SNPRINTF_WTRUNC(remote->endpoint_trail_downloading, size, "%s%s",
			endpoint_trail, DEVICE_TRAIL_ENDPOINT_DOWNLOADING);

	size = strlen(endpoint_trail) +
	       sizeof(DEVICE_TRAIL_ENDPOINT_INPROGRESS);
	remote->endpoint_trail_inprogress = calloc(size, sizeof(char));
	if (!remote->endpoint_trail_inprogress)
		goto err;
	SNPRINTF_WTRUNC(remote->endpoint_trail_inprogress, size, "%s%s",
			endpoint_trail, DEVICE_TRAIL_ENDPOINT_INPROGRESS);

	pv->remote = remote;

	free(endpoint_trail);

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

static int pv_update_send_progress(struct pv_update *update, char *json)
{
	struct pantavisor *pv = pv_get_instance();
	if ((update->pending && update->pending->local) ||
	    !pv_get_instance()->remote_mode || !pv->online ||
	    trail_remote_init(pv))
		return 0;

	trest_request_ptr req = NULL;
	trest_response_ptr res = NULL;
	int ret = -1;

	req = trest_make_request(THTTP_METHOD_PUT, update->endpoint, json);

	res = trest_do_json_request(pv->remote->client, req);
	if (!res) {
		pv_log(WARN, "HTTP request PUT %s could not be initialized",
		       update->endpoint);
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request PUT %s could not auth (status=%d)",
		       update->endpoint, res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request PUT %s returned error (code=%d; body='%s')",
		       update->endpoint, res->code, res->body);
	} else {
		pv_log(DEBUG, "remote state updated to %s", res->body);
		ret = 0;
	}

	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

struct pv_update_progress {
	char status[UPDATE_PROGRESS_STATUS_SIZE];
	char msg[UPDATE_PROGRESS_STATUS_MSG_SIZE];
	char data[UPDATE_PROGRESS_DATA_SIZE];
	char *logs;
	struct download_info *total;
	unsigned int progress;
};

static void pv_update_free_progress(struct pv_update_progress *progress)
{
	if (progress->logs)
		free(progress->logs);
}

static void pv_update_fill_progress(struct pv_update_progress *progress,
				    struct pv_update *update)
{
	struct pv_update_progress *p = progress;
	struct pv_update *u = update;

	SNPRINTF_WTRUNC(p->data, sizeof(p->data), "%d", u->retries);

	switch (update->status) {
	case UPDATE_QUEUED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "QUEUED");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Retried %d of %d",
				u->retries,
				pv_config_get_updater_revision_retries());
		p->progress = 0;
		break;
	case UPDATE_DOWNLOADED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "INPROGRESS");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"Update objects downloaded");
		p->progress = 25;
		break;
	case UPDATE_APPLIED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "INPROGRESS");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Update applied");
		p->progress = 50;
		break;
	case UPDATE_INSTALLED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "INPROGRESS");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Update installed");
		p->progress = 50;
		break;
	case UPDATE_TRY:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "INPROGRESS");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"Starting updated version");
		p->progress = 75;
		break;
	case UPDATE_TRANSITION:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "INPROGRESS");
		SNPRINTF_WTRUNC(
			p->msg, sizeof(p->msg),
			"Transitioning to new revision without rebooting");
		p->progress = 50;
		break;
	case UPDATE_REBOOT:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "INPROGRESS");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Rebooting");
		p->progress = 50;
		break;
	case UPDATE_UPDATED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "UPDATED");
		SNPRINTF_WTRUNC(
			p->msg, sizeof(p->msg),
			"Update finished, revision not set as rollback point");
		p->progress = 100;
		break;
	case UPDATE_DONE:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "DONE");
		SNPRINTF_WTRUNC(
			p->msg, sizeof(p->msg),
			"Update finished, revision set as rollback point");
		p->progress = 100;
		break;
	case UPDATE_ABORTED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "WONTGO");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Update aborted");
		p->progress = 100;
		break;
	case UPDATE_NO_DOWNLOAD:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "WONTGO");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"Max download retries reached");
		p->progress = 100;
		break;
	case UPDATE_NO_SPACE:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "WONTGO");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "%s", u->msg);
		p->progress = 100;
		break;
	case UPDATE_BAD_SIGNATURE:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "WONTGO");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "%s", u->msg);
		p->progress = 100;
		break;
	case UPDATE_NO_PARSE:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "WONTGO");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"State JSON has bad format");
		p->progress = 100;
		break;
	case UPDATE_SIGNATURE_FAILED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "ERROR");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "%s", u->msg);
		p->progress = 100;
		break;
	case UPDATE_BAD_CHECKSUM:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "ERROR");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"Object validation went wrong");
		p->progress = 100;
		break;
	case UPDATE_HUB_NOT_REACHABLE:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "ERROR");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Hub not reachable");
		p->progress = 100;
		break;
	case UPDATE_HUB_NOT_STABLE:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "ERROR");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"Hub communication not stable");
		p->progress = 100;
		break;
	case UPDATE_STALE_REVISION:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "ERROR");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Stale revision");
		p->progress = 100;
		break;
	case UPDATE_STATUS_GOAL_FAILED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "ERROR");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"Status goal not reached");
		p->progress = 100;
		break;
	case UPDATE_CONTAINER_FAILED:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "ERROR");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"A container could not be started");
		p->progress = 100;
		break;
	case UPDATE_RETRY_DOWNLOAD:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "QUEUED");
		SNPRINTF_WTRUNC(
			p->msg, sizeof(p->msg),
			"Network unavailable while downloading, retry %d of %d",
			update->retries,
			pv_config_get_updater_revision_retries());
		p->progress = 0;
		break;
	case UPDATE_TESTING_REBOOT:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "TESTING");
		SNPRINTF_WTRUNC(
			p->msg, sizeof(p->msg),
			"Awaiting to set rollback point if update is stable");
		p->progress = 75;
		break;
	case UPDATE_TESTING_NONREBOOT:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "TESTING");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg),
				"Awaiting to see if update is stable");
		p->progress = 75;
		break;
	case UPDATE_DOWNLOAD_PROGRESS:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "DOWNLOADING");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Retry %d of %d",
				update->retries,
				pv_config_get_updater_revision_retries());
		p->progress = 0;
		p->total = &update->total;
		break;
	default:
		SNPRINTF_WTRUNC(p->status, sizeof(p->status), "ERROR");
		SNPRINTF_WTRUNC(p->msg, sizeof(p->msg), "Internal error");
		p->progress = 100;
		break;
	}

	char path[PATH_MAX];
	pv_paths_storage_trail_pv_file(path, PATH_MAX, u->rev, LOGS_FNAME);
	p->logs = pv_fs_file_load(path, UPDATE_PROGRESS_LOGS_SIZE);
}

static char *pv_update_get_progress_json(struct pv_update_progress *progress)
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, UPDATE_PROGRESS_JSON_SIZE);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "status");
		pv_json_ser_string(&js, progress->status);
		pv_json_ser_key(&js, "status-msg");
		pv_json_ser_string(&js, progress->msg);
		pv_json_ser_key(&js, "progress");
		pv_json_ser_number(&js, progress->progress);
		if (progress->data && (strlen(progress->data) > 0)) {
			pv_json_ser_key(&js, "data");
			pv_json_ser_string(&js, progress->data);
		}
		if (progress->total) {
			pv_json_ser_key(&js, "downloads");
			pv_json_ser_object(&js);

			pv_json_ser_key(&js, "total");
			pv_json_ser_object(&js);
			{
				pv_json_ser_key(&js, "object_name");
				pv_json_ser_string(&js, "total");
				pv_json_ser_key(&js, "object_id");
				pv_json_ser_string(&js, "none");
				pv_json_ser_key(&js, "total_size");
				pv_json_ser_number(&js,
						   progress->total->total_size);
				pv_json_ser_key(&js, "start_time");
				pv_json_ser_number(&js,
						   progress->total->start_time);
				pv_json_ser_key(&js, "current_time");
				pv_json_ser_number(
					&js, progress->total->current_time);
				pv_json_ser_key(&js, "total_downloaded");
				pv_json_ser_number(
					&js, progress->total->total_downloaded);
				pv_json_ser_object_pop(&js);
			}
			pv_json_ser_key(&js, "objects");
			pv_json_ser_array(&js);
			{
				pv_json_ser_array_pop(&js);
			}
			pv_json_ser_object_pop(&js);
		}
		if (progress->logs) {
			pv_json_ser_key(&js, "logs");
			pv_json_ser_string(&js, progress->logs);
		}

		pv_json_ser_object_pop(&js);
	}

	return pv_json_ser_str(&js);
}

static int pv_update_report_progress(struct pv_update *update)
{
	// prepare update progress struct
	struct pv_update_progress progress;
	memset(&progress, 0, sizeof(progress));
	pv_update_fill_progress(&progress, update);

	// serialize update progress json
	char *json = NULL;
	json = pv_update_get_progress_json(&progress);
	pv_update_free_progress(&progress);

	// store progress in trails
	pv_storage_set_rev_progress(update->rev, json);

	// send progress to hub
	int ret = 0;
	ret = pv_update_send_progress(update, json);

	if (json)
		free(json);
	return ret;
}

static int trail_get_steps_response(struct pantavisor *pv, char *endpoint,
				    trest_response_ptr *response)
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
		pv_log(WARN, "HTTP request GET %s could not be initialized",
		       endpoint);
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request GET %s could not auth (status=%d)",
		       endpoint, res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request GET %s returned error (code=%d; body='%s')",
		       endpoint, res->code, res->body);
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
	struct jka_update_ctx *ctx = (struct jka_update_ctx *)jka->opaque;
	struct json_key_action jka_arr[] = {
		ADD_JKA_ENTRY("data", JSMN_STRING, &retry_count, NULL, true),
		ADD_JKA_NULL_ENTRY()
	};

	int ret = __start_json_parsing_with_action(
		jka->buf, jka_arr, JSMN_OBJECT, jka->tokv, jka->tokc);
	if (!ret) {
		if (retry_count) {
			pv_log(DEBUG, "retry_count = %s", retry_count);
			sscanf(retry_count, "%d", ctx->retries);
			free(retry_count);
		}
	}
	return ret;
}

static struct pv_update *pv_update_new(const char *id, const char *rev,
				       bool local)
{
	struct pv_update *u;
	int size;

	if (!rev)
		return NULL;

	u = calloc(1, sizeof(struct pv_update));
	if (u) {
		u->progress_size = PATH_MAX;
		u->status = UPDATE_INIT;
		u->rev = strdup(rev);
		u->retries = 0;
		u->local = local;

		if (!id) {
			u->local = true;
			goto out;
		}

		size = sizeof(DEVICE_STEP_ENDPOINT_FMT) + strlen(id) +
		       strlen(rev);
		u->endpoint = malloc(sizeof(char) * size);
		SNPRINTF_WTRUNC(u->endpoint, size, DEVICE_STEP_ENDPOINT_FMT, id,
				rev);
	}

out:
	return u;
}

static int pv_update_signature_verify(struct pv_update *update,
				      const char *state)
{
	int ret = -1;

	sign_state_res_t sres;
	sres = pv_signature_verify(state);
	if (sres != SIGN_STATE_OK) {
		pv_log(WARN, "invalid state signature with result %d", sres);
		pv_update_set_status_msg(update, UPDATE_BAD_SIGNATURE,
					 pv_signature_sign_state_str(sres));
		goto out;
	}

	ret = 0;

out:
	return ret;
}

void pv_update_set_status_msg(struct pv_update *update,
			      enum update_status status, const char *msg)
{
	if (!update) {
		pv_log(WARN, "uninitialized update");
		return;
	}

	// in case we do not have new information, we get out
	if ((update->status == status) && !msg)
		return;
	update->status = status;
	SNPRINTF_WTRUNC(update->msg, sizeof(update->msg), "%s", msg);

	// in this case, we don't want to overwrite the ERROR progress information
	if (status == UPDATE_ROLLEDBACK)
		return;

	pv_update_report_progress(update);
}

void pv_update_set_status(struct pv_update *update, enum update_status status)
{
	pv_update_set_status_msg(update, status, NULL);
}

void pv_update_set_factory_status()
{
	struct pantavisor *pv = pv_get_instance();

	if (strncmp(pv->state->rev, "0", sizeof("0")))
		return;

	struct pv_update_progress p;
	memset(&p, 0, sizeof(p));

	SNPRINTF_WTRUNC(p.status, sizeof(p.status), "DONE");
	SNPRINTF_WTRUNC(p.msg, sizeof(p.msg), "Factory revision");
	p.progress = 100;

	// serialize update progress json
	char *json = NULL;
	json = pv_update_get_progress_json(&p);

	// store progress in trails
	pv_storage_set_rev_progress("0", json);

	if (json)
		free(json);

	pv_storage_set_rev_done("0");
}

static int pv_update_refresh_progress(struct pv_update *update)
{
	int ret = -1;

	if (!update)
		return ret;

	char *json;
	json = pv_storage_get_rev_progress(update->rev);
	if (!json)
		return ret;

	pv_log(DEBUG,
	       "rev '%s' already existed in this device with progress '%s'",
	       update->rev, json);

	ret = pv_update_send_progress(update, json);

	free(json);
	return ret;
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
	struct jka_update_ctx update_ctx = { .retries = &retries };
	struct json_key_action jka[] = {
		ADD_JKA_ENTRY("progress", JSMN_OBJECT, &update_ctx,
			      do_progress_action, false),
		ADD_JKA_NULL_ENTRY()
	};
	struct pv_update *update;

	if (!remote)
		return 0;

	// if update is going on, just check for NEW updates so test json can be parsed
	if (pv->update && pv->update->status != UPDATE_APPLIED)
		goto new_update;

	// check for INPROGRESS updates
	ret = trail_get_steps_response(pv, remote->endpoint_trail_inprogress,
				       &res);
	if (ret > 0) {
		pv_log(DEBUG, "found INPROGRESS revision");
		goto process_response;
	} else if (ret < 0) {
		goto out;
	}

	// check for DOWNLOADING updates
	ret = trail_get_steps_response(pv, remote->endpoint_trail_downloading,
				       &res);
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
	rev = pv_json_get_value(res->body, "rev", res->json_tokv,
				res->json_tokc);

	// this could mean either the server is returning a malformed response or json parser is not working properly
	if (!rev) {
		pv_log(ERROR,
		       "rev not found in endpoint response, ignoring...");
		goto out;
	}

	pv_logserver_start_update(rev);

	pv_log(DEBUG, "parse rev %s...", rev);

	// create temp update to be able to report the revision state
	update = pv_update_new(pv_config_get_creds_id(), rev, false);
	if (!update)
		goto out;

	if (atoi(rev) <= atoi(pv->state->rev)) {
		pv_log(WARN, "stale rev %s found on remote", rev);
		pv_update_set_status(update, UPDATE_STALE_REVISION);
		wrong_revision = true;
		goto send_feedback;
	}

	// get raw revision state and parse retry
	state = pv_json_get_value(res->body, "state", res->json_tokv,
				  res->json_tokc);
	if (start_json_parsing_with_action(res->body, jka, JSMN_ARRAY) ||
	    !state) {
		pv_log(WARN, "failed to parse the rest of the response");
		pv_update_set_status(update, UPDATE_NO_PARSE);
		pv_update_free(update);
		goto out;
	}

send_feedback:
	if (pv_update_refresh_progress(update))
		pv_log(DEBUG, "could not refresh progress from rev %s", rev);

	if (wrong_revision) {
		pv_log(WARN, "stale revision found. Aborting update...");
		pv_update_free(update);
		goto out;
	}

	// report revision retry max reached
	if (retries > pv_config_get_updater_revision_retries()) {
		pv_log(WARN, "max retries reached in rev %s", rev);
		pv_update_set_status(update, UPDATE_NO_DOWNLOAD);
		pv_update_free(update);
		goto out;
	}

	// retry number recovered from endpoint response
	update->retries = retries;
	// if everything went well until this point, put revision to queue
	pv_update_set_status(update, UPDATE_QUEUED);

	// parse state
	if (pv_update_signature_verify(update, state)) {
		pv_update_free(update);
		goto out;
	}
	update->pending = pv_parser_get_state(state, rev);
	if (!update->pending) {
		pv_log(WARN, "invalid state from rev %s", rev);
		pv_update_set_status(update, UPDATE_NO_PARSE);
		pv_update_free(update);
		goto out;
	}

	// make sure target directories exist
	char path[PATH_MAX];
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, update->rev, "");
	pv_fs_mkdir_p(path, 0755);

	// install state.json for new rev
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, rev, JSON_FNAME);
	if (pv_fs_file_save(path, state, 0644) < 0)
		pv_log(ERROR, "could not save %s: %s", path, strerror(errno));

	// if an applied update is staged, reset it
	if (pv->update && pv->update->status == UPDATE_APPLIED)
		pv_update_finish(pv);

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
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "GET /trails/ could not auth (status=%d)",
		       res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "GET /trails/ returned error (code=%d; body='%s')",
		       res->code, res->body);
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
	error = pv_json_get_value(buf, "error", tokv, tokc);

	msg = pv_json_get_value(buf, "msg", tokv, tokc);

	__code = pv_json_get_value(buf, "code", tokv, tokc);
	if (__code) {
		sscanf(__code, "%d", &code);
		free(__code);
		__code = NULL;
	}

	if (error && msg) {
		pv_log(WARN, "Error %s: Message %s, code = %d", error, msg,
		       code);
	} else {
		pv_log(WARN,
		       "Malformed Error JSON from API,"
		       " error:%s,msg:%s, code=%d",
		       (error ? error : "nil"), (msg ? msg : "nil"), code);
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
	if (jsmnutil_parse_json(buf, &tokv, &tokc) >= 0) {
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
	__trail_log_resp_err(tres->body, tres->json_tokv, tres->json_tokc);
}

#define SHA256_STR_SIZE ((256 / 4) + 1)

static int trail_put_object(struct pantavisor *pv, struct pv_object *o,
			    const char **crtfiles)
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

	if (o->uploaded) {
		pv_log(INFO, "object '%s' already uploaded, skipping", o->id);
		return 0;
	}

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
	while (i < 32) {
		pos += snprintf(sha_str + pos, 3, "%02x", local_sha[i]);
		i++;
	}

	SNPRINTF_WTRUNC(body, sizeof(body),
			"{ \"objectname\": \"%s\","
			" \"size\": \"%d\","
			" \"sha256sum\": \"%s\""
			" }",
			o->name, size, sha_str);

	pv_log(INFO, "syncing '%s'", o->id);

	if (strncmp(o->id, sha_str, SHA256_STR_SIZE)) {
		pv_log(INFO,
		       "sha256 mismatch, probably writable image, skipping",
		       o->objpath);
		goto out;
	}

	treq = trest_make_request(THTTP_METHOD_POST, "/objects/", body);

	tres = trest_do_json_request(pv->remote->client, treq);
	if (!tres) {
		pv_log(WARN, "POST /objects/ could not be initialized");
		goto out;
	} else if (tres->code == THTTP_STATUS_CONFLICT) {
		pv_log(INFO, "object '%s' already owned by user, skipping",
		       o->id);
		o->uploaded = true;
		ret = 0;
		goto out;
	} else if (!tres->code && tres->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "POST /objects/ could not auth (status=%d)",
		       tres->status);
		goto out;
	} else if (tres->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "POST /objects/ returned error (code=%d; body='%s')",
		       tres->code, tres->body);
		goto out;
	}

	signed_puturl = pv_json_get_value(tres->body, "signed-puturl",
					  tres->json_tokv, tres->json_tokc);

	tls_req = (thttp_request_tls_t *)thttp_request_tls_new_0();

	if (signed_puturl && tls_req) {
		tls_req->crtfiles = (char **)crtfiles;
		req = (thttp_request_t *)tls_req;
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
			str_size = strlen("https://") + strlen(req->host) +
				   1 /* : */ + 5 /* port */ + 2 /* 0-delim */;
			req->baseurl = calloc(str_size, sizeof(char));
			SNPRINTF_WTRUNC(req->baseurl, str_size, "https://%s:%d",
					req->host, req->port);
		} else {
			((thttp_request_tls_t *)req)->crtfiles = NULL;
			str_size = strlen("https://") + strlen(req->host) +
				   1 /* : */ + 5 /* port */ + 2 /* 0-delim */;
			req->baseurl = calloc(str_size, sizeof(char));
			SNPRINTF_WTRUNC(req->baseurl, str_size, "http://%s:%d",
					req->host, req->port);
		}
		if (req->host_proxy)
			req->is_tls =
				false; /* XXX: global config if proxy is tls is TBD */
		req->user_agent = pv_user_agent;

		req->path = strstr(signed_puturl, "/local-s3");

		req->body_content_type = "application/json";
		lseek(fd, 0, SEEK_SET);
		req->fd = fd;
		req->len = size;

		pv_log(INFO, "'%s' does not exist, uploading", o->id);

		res = thttp_request_do(req);

		if (!res) {
			pv_log(WARN,
			       "'%s' could not be uploaded: could not be initialized",
			       o->id);
		} else if (!res->code) {
			pv_log(WARN,
			       "'%s' could not be uploaded: got no response",
			       o->id);
		} else if (res->code != THTTP_STATUS_OK) {
			pv_log(WARN,
			       "'%s' could not be uploaded: returned HTTP error (code=%d; body='%s')",
			       o->id, res->code, res->body);
		} else {
			pv_log(INFO,
			       "'%s' uploaded correctly, size=%d, code=%d",
			       o->id, size, res->code);
			o->uploaded = true;
			ret = 0;
		}
	} else {
		pv_log(ERROR,
		       "'%s' could not be registered, signed_puturl not retrieved",
		       o->id);
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

	pv_objects_iter_begin(pv->state, curr)
	{
		ret++;
	}
	pv_objects_iter_end;

	pv_log(DEBUG, "first boot: %d objects found, syncing", ret);

	// push all
	pv_objects_iter_begin(pv->state, curr)
	{
		if (trail_put_object(pv, curr, crtfiles) < 0)
			break;
		ret--;
	}
	pv_objects_iter_end;

	return ret;
}

static int trail_first_boot(struct pantavisor *pv)
{
	char *json = pv_storage_get_state_json(pv->state->rev);
	if (!json) {
		pv_log(ERROR, "Could not read state json");
		return -1;
	}

	trest_request_ptr req;
	trest_response_ptr res;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	status = trest_update_auth(pv->remote->client);
	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "cannot update auth token");
		free(json);
		return -1;
	}

	// first upload all objects
	if (trail_put_objects(pv) > 0) {
		pv_log(DEBUG, "error syncing objects on first boot");
		free(json);
		return -1;
	}

	req = trest_make_request(THTTP_METHOD_POST, "/trails/", json);

	res = trest_do_json_request(pv->remote->client, req);
	if (!res) {
		pv_log(WARN, "POST /trails/ could not be initialized");
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "POST /trails/ could not auth (status=%d)",
		       res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "POST /trails/ returned error (code=%d; body='%s')",
		       res->code, res->body);
	} else {
		pv_log(INFO,
		       "factory revision (base trail) pushed to remote correctly");
	}

	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	free(json);

	return 0;
}

#include <trest.h>
#include "metadata.h"

int pv_updater_check_for_updates(struct pantavisor *pv)
{
	int ret;
	char *addr;

	if (trail_remote_init(pv)) {
		pv_log(WARN, "remote not initialized");
		return 0;
	}

	if (trest_update_auth(pv->remote->client) != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "cannot authenticate to cloud");
		return 0;
	}

	// report pantahub ip to devmeta
	if (pv->remote && pv->remote->client) {
		addr = trest_get_addr(pv->remote->client);
		if (addr) {
			pv_metadata_add_devmeta(DEVMETA_KEY_PH_ADDRESS, addr);
			free(addr);
		}
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

static int pv_update_check_download_retry(struct pv_update *update)
{
	if (!update)
		return -1;

	struct timer_state timer_state =
		timer_current_state(&update->retry_timer);

	if (timer_state.fin) {
		update->retries++;
		if (update->retries >
		    pv_config_get_updater_revision_retries()) {
			pv_log(WARN, "max retries reached in rev %s",
			       update->rev);
			pv_update_set_status(update, UPDATE_NO_DOWNLOAD);
			return -1;
		}
		pv_log(INFO, "trying revision %s ,retry = %d", update->rev,
		       update->retries);
		// set timer for next retry
		timer_start(&update->retry_timer, pv_config_get_storage_wait(),
			    0, RELATIV_TIMER);
		return 0;
	}

	pv_log(INFO, "retrying in %d seconds", timer_state.sec);
	return 1;
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
	if (trail->endpoint_trail_downloading)
		free(trail->endpoint_trail_downloading);
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
		pv_update_set_status(pv->update, UPDATE_TESTING_REBOOT);
		break;
	case UPDATE_TRANSITION:
		pv_update_set_status(pv->update, UPDATE_TESTING_NONREBOOT);
		break;
	default:
		break;
	}
}

static bool pv_update_can_rollback(struct pv_update *u)
{
	struct pantavisor *pv = pv_get_instance();
	return pv_str_matches(pv->state->rev, strlen(pv->state->rev), u->rev,
			      strlen(u->rev));
}

int pv_update_finish(struct pantavisor *pv)
{
	int ret = 0;

	struct pv_update *u = pv->update;
	if (!u)
		return ret;

	switch (u->status) {
	// DONE TRANSITIONS
	case UPDATE_TESTING_REBOOT:
		pv_update_set_status(u, UPDATE_DONE);
		if (pv_bootloader_commit_update(pv->state->rev)) {
			pv_update_set_status(u, UPDATE_INTERNAL_ERROR);
			pv_log(ERROR,
			       "revision could not be committed to bootloader");
			ret = -1;
			goto out;
		}
		pv_storage_set_rev_done(pv->state->rev);
		pv->state->done = true;
		break;
	// UPDATED TRANSITIONS
	case UPDATE_TESTING_NONREBOOT:
		pv_update_set_status(u, UPDATE_UPDATED);
		break;
	// WONTGO
	case UPDATE_RETRY_DOWNLOAD:
		if (u->retries <= pv_config_get_updater_revision_retries())
			return ret;

		pv_update_set_status(u, UPDATE_NO_DOWNLOAD);
		break;
	case UPDATE_APPLIED:
		pv_update_set_status(u, UPDATE_ABORTED);
		break;
	// ERROR
	case UPDATE_ROLLEDBACK:
		pv_update_refresh_progress(u);
		if (!pv_update_can_rollback(u))
			pv_bootloader_fail_update();
		break;
	case UPDATE_SIGNATURE_FAILED:
	case UPDATE_BAD_CHECKSUM:
	case UPDATE_HUB_NOT_REACHABLE:
	case UPDATE_HUB_NOT_STABLE:
	case UPDATE_STALE_REVISION:
	case UPDATE_STATUS_GOAL_FAILED:
	case UPDATE_CONTAINER_STOPPED:
	case UPDATE_CONTAINER_FAILED:
	case UPDATE_INTERNAL_ERROR:
	case UPDATE_NO_DOWNLOAD:
	case UPDATE_NO_SPACE:
	case UPDATE_BAD_SIGNATURE:
	case UPDATE_NO_PARSE:
		break;
	default:
		pv_log(WARN, "finishing update in an unexpected state");
		pv_update_set_status(u, UPDATE_INTERNAL_ERROR);
		break;
	}

out:
	pv_logserver_stop_update(u->rev);
	if (u->status != UPDATE_ROLLEDBACK)
		pv_update_report_progress(u);
	pv_log(INFO, "update finished with status %d", u->status);
	pv_update_remove(pv);

	return ret;
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
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "GET %s could not auth (status=%d)", endpoint,
		       res->status);
		goto out;
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "GET %s returned error (code=%d; body='%s')",
		       endpoint, res->code, res->body);
		goto out;
	}

	size = pv_json_get_value(res->body, "size", res->json_tokv,
				 res->json_tokc);
	if (size)
		o->size = atoll(size);

	o->sha256 = pv_json_get_value(res->body, "sha256sum", res->json_tokv,
				      res->json_tokc);

	url = pv_json_get_value(res->body, "signed-geturl", res->json_tokv,
				res->json_tokc);
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
	struct pv_update *u;
	struct pv_object *o;
};

static uint64_t get_update_size(struct pv_update *u)
{
	uint64_t size = 0;
	struct stat st;
	struct pv_object *curr = NULL;

	pv_objects_iter_begin(u->pending, curr)
	{
		if (stat(curr->objpath, &st) < 0)
			size += curr->size;
	}
	pv_objects_iter_end;

	return size;
}

static void trail_download_object_progress(ssize_t written, ssize_t chunk_size,
					   void *obj)
{
	if (!obj) {
		pv_log(ERROR, "object does not exist");
		return;
	}

	struct progress_update *pu = (struct progress_update *)obj;
	struct pv_update *u = pu->u;
	struct pv_object *o = pu->o;

	if (written != chunk_size) {
		pv_log(ERROR, "error downloading object %s", o->name);
		return;
	}

	u->total.total_downloaded += chunk_size;
	pv_update_set_status(u, UPDATE_DOWNLOAD_PROGRESS);
}

static int trail_download_object(struct pantavisor *pv, struct pv_object *obj,
				 const char **crtfiles)
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
	char mmc_tmp_obj_path[PATH_MAX];
	char volatile_tmp_obj_path[] = VOLATILE_TMP_OBJ_PATH;
	unsigned char buf[4096];
	unsigned char cloud_sha[32] = { 0 };
	unsigned char local_sha[32];
	struct stat st;
	mbedtls_sha256_context sha256_ctx;
	thttp_response_t *res = 0;
	thttp_request_tls_t *tls_req = 0;
	thttp_request_t *req = 0;
	struct progress_update progress_update = {
		.u = pv->update,
		.o = obj,
	};
	if (!obj)
		goto out;

	tls_req = thttp_request_tls_new_0();
	tls_req->crtfiles = (char **)crtfiles;

	req = (thttp_request_t *)tls_req;

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
		int p = strtol(++port, &end, 0);
		if (p > 0)
			req->port = p;
	} else {
		end = strchr(start, '/');
	}

	n = (unsigned long)end - (unsigned long)start;
	host = malloc((n + 1) * sizeof(char));
	strncpy(host, start, n);
	host[n] = '\0';

	req->host = host;
	req->host_proxy = pv_config_get_creds_host_proxy();
	req->port_proxy = pv_config_get_creds_port_proxy();
	req->proxyconnect = !pv_config_get_creds_noproxyconnect();
	if (req->is_tls) {
		size = strlen("https://") + strlen(req->host) + 1 /* : */ +
		       5 /* port */ + 2 /* 0-delim */;
		req->baseurl = calloc(size, sizeof(char));
		SNPRINTF_WTRUNC(req->baseurl, size, "https://%s:%d", req->host,
				req->port);
	} else {
		((thttp_request_tls_t *)req)->crtfiles = NULL;
		size = strlen("https://") + strlen(req->host) + 1 /* : */ +
		       5 /* port */ + 2 /* 0-delim */;
		req->baseurl = calloc(size, sizeof(char));
		SNPRINTF_WTRUNC(req->baseurl, size, "http://%s:%d", req->host,
				req->port);
		pv_log(WARN, "req->baseurl truncated to %s", req->baseurl);
	}

	if (req->host_proxy)
		req->is_tls =
			false; /* XXX: global config if proxy is tls is TBD */

	req->path = end;

	if (pv_config_get_updater_network_use_tmp_objects() &&
	    (!strcmp(pv_config_get_storage_fstype(), "jffs2") ||
	     !strcmp(pv_config_get_storage_fstype(), "ubifs")))
		use_volatile_tmp = 1;

	// temporary path where we will store the file until validated
	SNPRINTF_WTRUNC(mmc_tmp_obj_path, sizeof(mmc_tmp_obj_path),
			MMC_TMP_OBJ_FMT, obj->objpath);
	obj_fd = open(mmc_tmp_obj_path, O_CREAT | O_RDWR, 0644);
	if (obj_fd < 0) {
		pv_log(ERROR, "open failed for %s: %s", mmc_tmp_obj_path,
		       strerror(errno));
		goto out;
	}

	if (use_volatile_tmp) {
		mkstemp(volatile_tmp_obj_path);
		volatile_tmp_fd =
			open(volatile_tmp_obj_path, O_CREAT | O_RDWR, 0644);
		fd = volatile_tmp_fd;
	} else {
		fd = obj_fd;
	}

	if (is_kernel_pvk) {
		fsync(obj_fd);
		close(obj_fd);
		pv_fs_path_sync(mmc_tmp_obj_path);
		fd = volatile_tmp_fd;
	}

	// download to tmp
	lseek(fd, 0, SEEK_SET);
	pv_log(INFO, "downloading object to tmp path (%s)", mmc_tmp_obj_path);
	res = thttp_request_do_file_with_cb(
		req, fd, trail_download_object_progress, &progress_update);
	if (!res) {
		pv_log(WARN,
		       "'%s' could not be downloaded: could not be initialized",
		       obj->id);
		pv_fs_path_remove(mmc_tmp_obj_path, false);
		goto out;
	} else if (!res->code) {
		pv_log(WARN, "'%s' could not be downloaded: got no response",
		       obj->id);
		pv_fs_path_remove(mmc_tmp_obj_path, false);
		goto out;
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "'%s' could not be downloaded: returned HTTP error (code=%d; body='%s')",
		       obj->id, res->code, res->body);
		pv_fs_path_remove(mmc_tmp_obj_path, false);
		goto out;
	}

	if (use_volatile_tmp) {
		pv_log(INFO, "copying %s to tmp path (%s)",
		       volatile_tmp_obj_path, mmc_tmp_obj_path);
		pv_fs_file_copy_fd(volatile_tmp_fd, obj_fd, true);
		fd = obj_fd;
	}
	pv_log(DEBUG, "downloaded object to tmp path (%s)", mmc_tmp_obj_path);
	fsync(fd);
	pv_fs_path_sync(mmc_tmp_obj_path);

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
	for (int i = 0, j = 0; i < (int)strlen(tmp_sha); i = i + 2, j++) {
		char byte[3];
		strncpy(byte, tmp_sha + i, 2);
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
	if (pv_fs_path_rename(mmc_tmp_obj_path, obj->objpath) < 0) {
		pv_log(ERROR, "could not rename: %s", strerror(errno));
	}

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
	struct pv_object *obj = NULL;
	char *ext;

	pv_objects_iter_begin(pv->update->pending, obj)
	{
		pv_fs_mkbasedir_p(obj->relpath, 0775);
		ext = strrchr(obj->relpath, '.');
		if (ext && (strcmp(ext, ".bind") == 0)) {
			pv_log(INFO, "copying bind volume '%s' from '%s'",
			       obj->relpath, obj->objpath);
			if (pv_fs_file_copy(obj->objpath, obj->relpath, 0644) <
			    0)
				pv_log(ERROR, "could not copy objects");
			continue;
		}
		if (link(obj->objpath, obj->relpath) < 0) {
			if (errno != EEXIST) {
				pv_log(ERROR, "unable to link %s, errno=%d",
				       obj->relpath, errno);
				return -1;
			}
		} else {
			pv_fs_path_sync(obj->relpath);
			pv_log(DEBUG, "linked %s to %s", obj->relpath,
			       obj->objpath);
		}
	}
	pv_objects_iter_end;

	return pv_storage_meta_link_boot(pv, pv->update->pending);
}

static int trail_check_update_size(struct pantavisor *pv)
{
	off_t update_size, free_size;
	char msg[UPDATE_PROGRESS_STATUS_MSG_SIZE];

	update_size = get_update_size(pv->update);
	pv_log(INFO, "update size: %" PRIu64 " B", update_size);

	free_size = pv_storage_gc_run_needed(update_size);

	if (update_size > free_size) {
		pv_log(ERROR, "cannot process update. Aborting...");
		SNPRINTF_WTRUNC(msg, sizeof(msg),
				"Space required %" PRIu64
				" B, available %" PRIu64 " B",
				update_size, free_size);
		pv_update_set_status_msg(pv->update, UPDATE_NO_SPACE, msg);
		return -1;
	}

	return 0;
}

static int trail_download_objects(struct pantavisor *pv)
{
	struct pv_update *u = pv->update;
	struct pv_object *o = NULL;
	const char **crtfiles = pv_ph_get_certs(pv);

	pv_objects_iter_begin(u->pending, o)
	{
		if (!trail_download_get_meta(pv, o)) {
			pv_update_set_status(pv->update, UPDATE_RETRY_DOWNLOAD);
			u->total.total_downloaded = 0;
			return -1;
		}
	}
	pv_objects_iter_end;

	// check size and collect garbage if needed
	if (trail_check_update_size(pv))
		return -1;

	u->total.total_size = get_update_size(u);
	u->total.start_time = time(NULL);
	u->total.total_downloaded = 0;
	u->total.current_time = time(NULL);
	pv_update_set_status(pv->update, UPDATE_DOWNLOAD_PROGRESS);

	pv_objects_iter_begin(u->pending, o)
	{
		if (!trail_download_object(pv, o, crtfiles)) {
			pv_update_set_status(pv->update, UPDATE_RETRY_DOWNLOAD);
			u->total.total_downloaded = 0;
			return -1;
		}
	}

	u->total.current_time = time(NULL);
	pv_update_set_status(pv->update, UPDATE_DOWNLOAD_PROGRESS);
	pv_objects_iter_end;
	return 0;
}

struct pv_update *pv_update_get_step_local(const char *rev)
{
	struct pv_update *update = NULL;
	char *json = NULL;

	pv_logserver_start_update(rev);

	update = pv_update_new(pv_config_get_creds_id(), rev, true);
	if (!update)
		goto err;

	json = pv_storage_get_state_json(rev);
	if (!json) {
		pv_log(ERROR, "Could not read state json");
		goto err;
	}

	if (pv_update_signature_verify(update, json))
		goto err;
	update->pending = pv_parser_get_state(json, rev);
	if (!update->pending) {
		pv_update_set_status(update, UPDATE_NO_PARSE);
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

	pv_paths_storage_trail_pv_file(path, PATH_MAX, pv->update->rev, "");
	pv_fs_mkdir_p(path, 0755);

	// do not download if this is a local update
	if (pv->update->local)
		return 0;

	if (trail_remote_init(pv)) {
		pv_log(WARN, "remote not initialized");
		goto out;
	}

	pv_log(DEBUG, "downloading update...");

	if (pv_update_check_download_retry(pv->update))
		goto out;

	ret = trail_download_objects(pv);
	if (ret < 0) {
		pv_log(WARN, "unable to download objects");
		goto out;
	}

	pv_update_set_status(pv->update, UPDATE_DOWNLOADED);

	ret = 0;
out:
	return ret;
}

int pv_update_install(struct pantavisor *pv)
{
	int ret = -1;
	struct pv_update *update = pv->update;
	struct pv_state *pending = pv->update->pending;

	if (!pv || !pv->state || !pv->update || !pv->update->pending) {
		pv_log(WARN, "uninitialized state or update");
		goto out;
	}

	pv_log(DEBUG, "installing update...");

	ret = trail_link_objects(pv);
	if (ret < 0) {
		pv_log(ERROR, "unable to link objects to relative path");
		pv_update_set_status(pv->update, UPDATE_INTERNAL_ERROR);
		goto out;
	}

	if (!pv_storage_meta_expand_jsons(pv, pending)) {
		pv_log(ERROR,
		       "unable to install platform and pantavisor jsons");
		ret = -1;
		goto out;
	}

	pv_log(DEBUG, "update successfully installed");
	if (pv_bootloader_install_update(update->rev)) {
		pv_log(ERROR,
		       "revision could not be set as installed to bootloader");
		ret = -1;
		goto out;
	}

	pv_update_set_status(pv->update, UPDATE_INSTALLED);
out:
	if (pending && (ret < 0))
		pv_storage_rm_rev(update->rev);

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

		pv_logserver_start_update(rev);

		pv_log(INFO, "loading update data from rev %s after reboot...",
		       rev);
		pv->update =
			pv_update_new(pv_config_get_creds_id(), rev, false);
		if (!pv->update)
			return -1;

		if (pv_bootloader_trying_update())
			pv_update_set_status(pv->update, UPDATE_TRY);
		else
			pv_update_set_status(pv->update, UPDATE_ROLLEDBACK);
	}

	return 0;
}

bool pv_update_is_transitioning(struct pv_update *u)
{
	return (u && u->status == UPDATE_TRANSITION);
}

bool pv_update_is_trying(struct pv_update *u)
{
	return (u && ((u->status == UPDATE_TRANSITION) ||
		      (u->status == UPDATE_TRY)));
}

bool pv_update_is_testing(struct pv_update *u)
{
	return (u && ((u->status == UPDATE_TESTING_REBOOT) ||
		      (u->status == UPDATE_TESTING_NONREBOOT)));
}
