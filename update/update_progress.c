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

#include "config.h"

#include "update/update_progress.h"

#include "utils/json.h"
#include "utils/str.h"

#define MODULE_NAME "update_progress"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define UPDATE_PROGRESS_JSON_SIZE 4096

void pv_update_progress_init(pv_update_progress_t *p,
			     void (*report_cb)(const char *))
{
	if (!p)
		return;

	p->report_cb = report_cb;
}

static void _call_report_cb(pv_update_progress_t *p)
{
	char *progress_str = NULL;

	if (!p || !p->report_cb)
		return;

	progress_str = pv_update_progress_ser(p);
	if (!progress_str)
		return;

	p->report_cb(progress_str);
	free(progress_str);
}

static const char *_ser_update_progress_status(pv_update_progress_status_t s)
{
	switch (s) {
	case PV_UPDATE_PROGRESS_STATUS_NEW:
		return "NEW";
	case PV_UPDATE_PROGRESS_STATUS_QUEUED:
		return "QUEUED";
	case PV_UPDATE_PROGRESS_STATUS_DOWNLOADING:
		return "DOWNLOADING";
	case PV_UPDATE_PROGRESS_STATUS_INPROGRESS:
		return "INPROGRESS";
	case PV_UPDATE_PROGRESS_STATUS_TESTING:
		return "TESTING";
	case PV_UPDATE_PROGRESS_STATUS_UPDATED:
		return "UPDATED";
	case PV_UPDATE_PROGRESS_STATUS_DONE:
		return "DONE";
	case PV_UPDATE_PROGRESS_STATUS_WONTGO:
		return "WONTGO";
	case PV_UPDATE_PROGRESS_STATUS_ERROR:
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
			pv_json_ser_number(&js, p->total.size);
			pv_json_ser_key(&js, "total_downloaded");
			pv_json_ser_number(&js, p->total.downloaded);
			pv_json_ser_key(&js, "start_time");
			pv_json_ser_number(&js, p->total.start_time);
			pv_json_ser_key(&js, "current_time");
			pv_json_ser_number(&js, p->total.current_time);
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

	if (pv_str_matches(str, len, "NEW", strlen("NEW")))
		return PV_UPDATE_PROGRESS_STATUS_NEW;
	else if (pv_str_matches(str, len, "QUEUED", strlen("QUEUED")))
		return PV_UPDATE_PROGRESS_STATUS_QUEUED;
	else if (pv_str_matches(str, len, "DOWNLOADING", strlen("DOWNLOADING")))
		return PV_UPDATE_PROGRESS_STATUS_DOWNLOADING;
	else if (pv_str_matches(str, len, "INPROGRESS", strlen("INPROGRESS")))
		return PV_UPDATE_PROGRESS_STATUS_INPROGRESS;
	else if (pv_str_matches(str, len, "TESTING", strlen("TESTING")))
		return PV_UPDATE_PROGRESS_STATUS_TESTING;
	else if (pv_str_matches(str, len, "UPDATED", strlen("UPDATED")))
		return PV_UPDATE_PROGRESS_STATUS_UPDATED;
	else if (pv_str_matches(str, len, "DONE", strlen("DONE")))
		return PV_UPDATE_PROGRESS_STATUS_DONE;
	else if (pv_str_matches(str, len, "WONTGO", strlen("WONTGO")))
		return PV_UPDATE_PROGRESS_STATUS_WONTGO;
	else if (pv_str_matches(str, len, "ERROR", strlen("ERROR")))
		return PV_UPDATE_PROGRESS_STATUS_ERROR;

	return PV_UPDATE_PROGRESS_STATUS_UNKNOWN;
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

	t->size = pv_json_get_value_int(json, "total_size", tokv, tokc);
	t->downloaded =
		pv_json_get_value_int(json, "total_downloaded", tokv, tokc);
	t->start_time = pv_json_get_value_int(json, "start_time", tokv, tokc);
	t->current_time =
		pv_json_get_value_int(json, "current_time", tokv, tokc);
out:
	if (tokv)
		free(tokv);
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

	char *total = pv_json_get_value(json, "total", tokv, tokc);
	if (total) {
		_parse_update_progress_total(total, &p->total);
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

static char *_ser_update_progress_msg(pv_update_progress_t *p,
				      pv_update_progress_msg_t code)
{
	char *ret = NULL;

	if (!p)
		return strdup("Internal error");

	switch (code) {
	case PV_UPDATE_PROGRESS_MSG_ABORTED:
		ret = strdup("Update aborted");
		break;
	case PV_UPDATE_PROGRESS_MSG_QUEUED:
		asprintf(&ret, "Retried %d of %d", p->retries,
			 pv_config_get_int(PV_REVISION_RETRIES));
		break;
	case PV_UPDATE_PROGRESS_MSG_APPLIED:
		ret = strdup("Update applied");
		break;
	case PV_UPDATE_PROGRESS_MSG_TRY:
		ret = strdup("Trying new revision");
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
	case PV_UPDATE_PROGRESS_MSG_FACTORY:
		ret = strdup("Factory revision");
		break;
	case PV_UPDATE_PROGRESS_MSG_BAD_CHECKSUM:
		ret = strdup("Object validation went wrong");
		break;
	case PV_UPDATE_PROGRESS_MSG_HUB_NOT_REACHABLE:
		ret = strdup("Hub not reachable");
		break;
	case PV_UPDATE_PROGRESS_MSG_HUB_NOT_STABLE:
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
		ret = strdup("Max download update retries reached");
		break;
	case PV_UPDATE_PROGRESS_MSG_NO_PARSE:
		ret = strdup("State JSON has bad format");
		break;
	case PV_UPDATE_PROGRESS_MSG_TESTING_REBOOT:
		ret = strdup(
			"Awaiting to set rollback point if update is stable");
		break;
	case PV_UPDATE_PROGRESS_MSG_TESTING_NONREBOOT:
		ret = strdup("Awaiting to see if update is stable");
		break;
	case PV_UPDATE_PROGRESS_MSG_PREP_DOWNLOAD_PROGRESS:
		asprintf(&ret, "Downloading update metadata, retry %d of %d",
			 p->retries, pv_config_get_int(PV_REVISION_RETRIES));
		break;
	case PV_UPDATE_PROGRESS_MSG_DOWNLOAD_PROGRESS:
		asprintf(&ret, "Downloading update artifacts, retry %d of %d",
			 p->retries, pv_config_get_int(PV_REVISION_RETRIES));
		break;
	case PV_UPDATE_PROGRESS_MSG_ROLLEDBACK:
		ret = strdup("Unexpected rollback");
		break;
	default:
		ret = strdup("Internal error");
	}

	return ret;
}

void pv_update_progress_set(pv_update_progress_t *p,
			    pv_update_progress_status_t status,
			    pv_update_progress_msg_t code)
{
	if (!p)
		return;

	p->status = status;

	if (p->msg)
		free(p->msg);
	p->msg = _ser_update_progress_msg(p, code);

	_call_report_cb(p);
}

void pv_update_progress_set_str(pv_update_progress_t *p,
				pv_update_progress_status_t status,
				const char *fmt, ...)
{
	char *msg;
	va_list args;

	if (!p || !fmt)
		return;

	p->status = status;

	va_start(args, fmt);

	vasprintf(&msg, fmt, args);

	va_end(args);

	if (!msg)
		return;
	if (p->msg)
		free(p->msg);
	p->msg = msg;

	_call_report_cb(p);
}

void pv_update_progress_start_record(pv_update_progress_t *p)
{
	if (!p)
		return;

	p->status = PV_UPDATE_PROGRESS_STATUS_QUEUED;

	if (p->msg)
		free(p->msg);
	p->msg = _ser_update_progress_msg(
		p, PV_UPDATE_PROGRESS_MSG_PREP_DOWNLOAD_PROGRESS);

	p->total.size = 0;

	_call_report_cb(p);
}

void pv_update_progress_add_size(pv_update_progress_t *p, off_t size)
{
	if (!p)
		return;

	p->total.size += size;
}

off_t pv_update_progress_get_size(pv_update_progress_t *p)
{
	if (!p)
		return 0;

	return p->total.size;
}

void pv_update_progress_start_download(pv_update_progress_t *p)
{
	if (!p)
		return;

	p->status = PV_UPDATE_PROGRESS_STATUS_DOWNLOADING;

	if (p->msg)
		free(p->msg);
	p->msg = _ser_update_progress_msg(
		p, PV_UPDATE_PROGRESS_MSG_DOWNLOAD_PROGRESS);

	p->total.downloaded = 0;
	p->total.start_time = time(NULL);
	p->total.current_time = time(NULL);

	_call_report_cb(p);
}

void pv_update_progress_add_downloaded(pv_update_progress_t *p,
				       off_t downloaded)
{
	if (!p)
		return;

	p->total.downloaded += downloaded;
	p->total.current_time = time(NULL);

	_call_report_cb(p);
}
