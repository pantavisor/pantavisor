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

#include "update/update_progress.h"

#define MODULE_NAME "update_progress"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static const char *_ser_update_progress_status(pv_update_progress_status_t s)
{
	switch (s) {
	case PV_STATUS_NEW:
		return "NEW";
	case PV_STATUS_QUEUED:
		return "QUEUED";
	case PV_STATUS_DOWNLOADING:
		return "DOWNLOADING";
	case PV_STATUS_INPROGRESS:
		return "INPROGRESS";
	case PV_STATUS_TESTING:
		return "TESTING";
	case PV_STATUS_UPDATED:
		return "UPDATED";
	case PV_STATUS_DONE:
		return "DONE";
	case PV_STATUS_WONTGO:
		return "WONTGO";
	case PV_STATUS_ERROR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}

	return "UNKNOWN";
}

char *pv_update_progress_ser(pv_update_progress_t *p)
{
	if (!p)
		return NULL;

	struct pv_json_ser js;

	pv_json_ser_init(&js, UPDATE_PROGRESS_JSON_SIZE);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "status");
		pv_json_ser_string(&js, _ser_update_progress_status(p->status));
		pv_json_ser_key(&js, "status-msg");
		pv_json_ser_string(&js, p->msg);
		pv_json_ser_key(&js, "progress");
		pv_json_ser_number(&js, p->progress);
		pv_json_ser_key(&js, "retries");
		pv_json_ser_number(&js, p->retries);
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
			pv_json_ser_number(&js, p->total.total_size);
			pv_json_ser_key(&js, "start_time");
			pv_json_ser_number(&js, p->total.start_time);
			pv_json_ser_key(&js, "current_time");
			pv_json_ser_number(&js, p->total.current_time);
			pv_json_ser_key(&js, "total_downloaded");
			pv_json_ser_number(&js, p->total.total_downloaded);
			pv_json_ser_object_pop(&js);
		}
		pv_json_ser_key(&js, "objects");
		pv_json_ser_array(&js);
		{
			pv_json_ser_array_pop(&js);
		}
		pv_json_ser_object_pop(&js);
		if (p->logs) {
			pv_json_ser_key(&js, "logs");
			pv_json_ser_string(&js, p->logs);
		}

		pv_json_ser_object_pop(&js);
	}

	return pv_json_ser_str(&js);
}

static pv_update_progress_status_t
_parse_update_progress_status(const char *str)
{
	size_t len = strlen(str);

	if (pv_str_matches(str, len, "NEW", strlen("NEW"))
		return PV_STATUS_NEW;
	else if (pv_str_matches(str, len, "QUEUED", strlen("QUEUED"))
		return PV_STATUS_QUEUED;
	else if (pv_str_matches(str, len, "DOWNLOADING", strlen("DOWNLOADING"))
		return PV_STATUS_DOWNLOADING;
	else if (pv_str_matches(str, len, "INPROGRESS", strlen("INPROGRESS"))
		return PV_STATUS_INPROGRESS;
	else if (pv_str_matches(str, len, "TESTING", strlen("TESTING"))
		return PV_STATUS_TESTING;
	else if (pv_str_matches(str, len, "UPDATED", strlen("UPDATED"))
		return PV_STATUS_UPDATED;
	else if (pv_str_matches(str, len, "DONE", strlen("DONE"))
		return PV_STATUS_DONE;
	else if (pv_str_matches(str, len, "WONTGO", strlen("WONTGO"))
		return PV_STATUS_WONTGO;
	else if (pv_str_matches(str, len, "ERROR", strlen("ERROR"))
		return PV_STATUS_ERROR;

    return PV_STATUS_UNKNOWN;
}

static void _parse_update_progress_total(const char *json,
					 pv_download_info_t *t)
{
	int tokc;
	jsmntok_t *tokv = NULL;

	if (!t)
		return;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0)
		return;

	t->total_size = pv_json_get_value_int(json, "total_size", tokv, tokc);
	t->start_time = pv_json_get_value_int(json, "start_time", tokv, tokc);
	t->current_time =
		pv_json_get_value_int(json, "current_time", tokv, tokc);
	t->total_downloaded =
		pv_json_get_value_int(json, "total_downloaded", tokv, tokc);

	ret = 0;
out:
	if (tokv)
		free(tokv);
	return ret;
}

int pv_update_progress_parse(const char *json, pv_update_progress_t *p)
{
	int ret = -1, tokc;
	jsmntok_t *tokv = NULL;

	if (!p)
		goto out;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0)
		goto out;

	char *status = pv_json_get_value(json, "status", tokv, tokc);
	if (!status) {
		pv_log(WARN, "status could not be parsed from progress JSON");
		goto out;
	}
	p->status = _parse_update_progress_status(status);
	free(status);

	p->msg = pv_json_get_value(json, "status-msg", tokv, tokc);
	if (!msg) {
		pv_log(WARN, "status could not be parsed from progress JSON");
		goto out;
	}

	char *total = pv_json_get_value(json, "total", tokv, tokc);
	if (total) {
		_parse_update_progress_total(total, &progress->total);
		free(total);
	}

	p->progress = pv_json_get_value_int(json, "progress", tokv, tokc);
	p->retries = pv_json_get_value_int(json, "retries", tokv, tokc);

	p->logs = pv_json_get_value(json, "logs", tokv, tokc);

	ret = 0;
out:
	if (tokv)
		free(tokv);
	return ret;
}

void pv_update_progress_set_status(pv_update_progress_t *p, pv_status_t status)
{
	if (!p)
		return;

	p->status = status;
}

void pv_update_progress_set_msg_str(pv_update_progress_t *p, const char *str)
{
	if (!p)
		return;

	if (p->msg)
		free(p->msg);
	p->msg = strdup(str);
}

static char *_ser_update_progress_msg(pv_update_progress_t *p,
				      pv_update_progress_msg_t code)
{
	char *ret = NULL;

	if (!p)
		return;

	switch (code) {
	case PV_UPDATE_PROGRESS_MSG_ABORTED:
		ret = strdup("Update aborted");
		break;
	case PV_UPDATE_PROGRESS_MSG_QUEUED:
		asprintf(&ret, "Retried %d of %d", p->retries,
			 pv_config_get_int(PV_REVISION_RETRIES));
		break;
	case PV_UPDATE_PROGRESS_MSG_DOWNLOADED:
		ret = strdup("Update objects downloaded");
		break;
	case PV_UPDATE_PROGRESS_MSG_INSTALLED:
		ret = strdup("Update installed");
		break;
	case PV_UPDATE_PROGRESS_MSG_APPLIED:
		ret = strdup("Update applied");
		break;
	case PV_UPDATE_PROGRESS_MSG_TRY:
		ret = strdup("Starting updated version");
		break;
	case PV_UPDATE_PROGRESS_MSG_TRANSITION:
		ret = strdup("Transitioning to new revision without rebooting");
		break;
	case PV_UPDATE_PROGRESS_MSG_REBOOT:
		ret = strdup("Rebooting");
		break;
	case PV_UPDATE_PROGRESS_MSG_UPDATED:
		ret = strdup(
			"Update finished, revision not set as rollback point");
		break;
	case PV_UPDATE_PROGRESS_MSG_DONE:
		ret = strdup("Update finished, revision set as rollback point");
		break;
	case PV_UPDATE_PROGRESS_MSG_DONE:
		ret = strdup("Update finished, revision set as rollback point");
		break;
	case PV_UPDATE_PROGRESS_MSG_BAD_CHECKSUM:
		ret = strdup("Object validation went wrong");
		break;
	case PV_UPDATE_PROGRESS_MSG_HUB_NOT_REACHABLE:
		ret = strdup("Hub not reachable");
		break;
	case PV_UPDATE_PROGRESS_MSG_HUB_NOT_REACHABLE:
		ret = strdup("Hub communication not stable");
		break;
	case PV_UPDATE_PROGRESS_MSG_STALE_REVISION:
		ret = strdup("Stale revision");
		break;
	case PV_UPDATE_PROGRESS_MSG_STATUS_GOAL_FAILED:
		ret = strdup("Status goal not reached");
		break;
	case PV_UPDATE_PROGRESS_MSG_CONTAINER_FAILED:
		ret = strdup("A container could not be started");
		break;
	case PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR:
		ret = strdup("Internal error");
		break;
	case PV_UPDATE_PROGRESS_MSG_NO_PROCESSING:
		ret = strdup("Max update processing retries reached");
		break;
	case PV_UPDATE_PROGRESS_MSG_NO_DOWNLOAD:
		ret = strdup("Max download retries reached");
		break;
	case PV_UPDATE_PROGRESS_MSG_NO_PARSE:
		ret = strdup("State JSON has bad format");
		break;
	case PV_UPDATE_PROGRESS_MSG_RETRY_DOWNLOAD:
		asprintf(
			&ret,
			"Network unavailable while downloading, retry %d of %d",
			p->retries, pv_config_get_int(PV_REVISION_RETRIES));
		break;
	case PV_UPDATE_PROGRESS_MSG_TESTING_REBOOT:
		ret = strdup(
			"Awaiting to set rollback point if update is stable");
		break;
	case PV_UPDATE_PROGRESS_MSG_TESTING_NONREBOOT:
		ret = strdup("Awaiting to see if update is stable");
		break;
	case PV_UPDATE_PROGRESS_MSG_TESTING_NONREBOOT:
		asprintf(&ret, "Retry %d of %d", p->retries,
			 pv_config_get_int(PV_REVISION_RETRIES));
		break;
	case PV_UPDATE_PROGRESS_MSG_ROLLEDBACK:
		ret = strdup("Unexpected rollback");
		break;
	default:
		ret = strdup("Internal error");
	}
}

void pv_update_progress_set_msg_code(pv_update_progress_t *p,
				     pv_update_progress_msg_t code)
{
	if (!p)
		return;

	if (p->msg)
		free(p->msg);
	p->msg = _ser_update_progress_msg(p, code);
}

void pv_update_progress_set_progress(pv_update_progress_t *p, int progress)
{
	if (!p)
		return;

	p->progress = progress;
}

void pv_update_progress_set_logs(pv_update_progress_t *p, const char *logs)
{
	if (!p)
		return;

	if (p->logs)
		free(p->logs);
	p->logs = logs;
}

void pv_update_progress_set_total(pv_update_progress_t *p, off_t total_size,
				  off_t start_time, off_t current_time,
				  off_t total_downloaded)
{
	if (!p)
		return;

	p->total.total_size = total_size;
	p->total.start_time = start_time;
	p->total.current_time = current_time;
	p->total.total_downloaded = total_downloaded;
}
