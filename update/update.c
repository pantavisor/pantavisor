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

#include <errno.h>
#include <string.h>

#include "update/update.h"
#include "update/update_progress.h"
#include "update/update_struct.h"

#include "bootloader.h"
#include "objects.h"
#include "paths.h"
#include "signature.h"
#include "storage.h"

#include "logserver/logserver.h"

#include "parser/parser.h"

#include "utils/fs.h"
#include "utils/str.h"

#define MODULE_NAME "update"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define FACTORY_REVISION "0"

static struct pv_update *_get_update_instance()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return NULL;

	return pv->update;
}

static void _call_report_cb(const char *progress_str)
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	if (!progress_str)
		return;

	pv_log(DEBUG, "report progress for rev '%s': '%s'", u->rev,
	       progress_str);

	// save progress in disk
	pv_storage_set_rev_progress(u->rev, progress_str);

	if (!u->report_cb) {
		pv_log(DEBUG, "report callback not set");
		return;
	}

	// send progress to hub
	u->report_cb(u->rev, progress_str);
}

static struct pv_update *
_update_new(const char *rev, void (*report_cb)(const char *, const char *))
{
	struct pv_update *u = calloc(1, sizeof(struct pv_update));
	if (!u)
		return NULL;

	u->rev = strdup(rev);
	u->transition = PV_SYSTEM_TRANSITION_REBOOT;
	u->report_cb = report_cb;
	pv_update_progress_init(&u->progress, u->rev, _call_report_cb);

	return u;
}

static void _free_update(struct pv_update *update)
{
	if (!update)
		return;

	if (update->rev)
		free(update->rev);
	if (update->progress.msg)
		free(update->progress.msg);
	if (update->progress.logs)
		free(update->progress.logs);
	if (update->state)
		pv_state_free(update->state);
}

static void _reset_object_list_retries(struct pv_update *update)
{
	if (!update)
		return;

	update->object_list_retries = 0;
}

static int _enroll_object_list(struct pv_update *update)
{
	const int max_count = pv_config_get_int(PH_UPDATER_TRANSFER_MAX_COUNT);
	// we want to be able to retry each object at least once,
	// so we divide by the max allowed per cycle and round up
	int object_list_max_retries;
	object_list_max_retries =
		((pv_state_get_object_count(update->state) + max_count - 1) /
		 max_count);

	update->object_list_retries++;
	pv_log(DEBUG, "enroll object list retry count %d",
	       update->object_list_retries);

	if (update->object_list_retries > object_list_max_retries) {
		pv_log(DEBUG,
		       "max enroll object list retries reached, retrying update");
		update->progress.retries++;
		pv_log(DEBUG, "update retry count %d",
		       update->progress.retries);

		if (update->progress.retries >=
		    pv_config_get_int(PV_REVISION_RETRIES)) {
			pv_log(WARN, "max update retries eached");
			return -1;
		}

		_reset_object_list_retries(update);
	}

	return 0;
}

static void _finish_update_installation()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	struct pv_state *s = u->state;
	if (!s)
		return;

	if (pv_state_prepare_run(s)) {
		pv_log(WARN, "could not prepare state to be run");
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_ERROR,
				       PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		return;
	}

	if (pv_bootloader_install_update(u->rev)) {
		pv_log(WARN, "could not set bootloader with new update info");
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_ERROR,
				       PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		return;
	}

	u->transition = pv_run_update();
	switch (u->transition) {
	case PV_SYSTEM_TRANSITION_REBOOT:
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_INPROGRESS,
				       PV_UPDATE_PROGRESS_MSG_REBOOT);
		return;
	case PV_SYSTEM_TRANSITION_NONREBOOT:
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_INPROGRESS,
				       PV_UPDATE_PROGRESS_MSG_TRANSITION);
		return;
	default:
		pv_log(WARN, "invalid transition '%s'",
		       pv_system_transition_str(u->transition));
		break;
	}

	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_ERROR,
			       PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
}

void pv_update_start_install(const char *rev, const char *progress_hub,
			     const char *state,
			     void (*report_cb)(const char *, const char *))
{
	int res;
	char *progress_str = NULL;
	struct pantavisor *pv = pv_get_instance();

	if (!rev || !state)
		goto out;

	pv_log(DEBUG, "evaluating whether update from rev '%s' can be started",
	       rev);

	struct pv_update *u = _update_new(rev, report_cb);
	if (!u)
		goto out;
	pv->update = u;

	pv_log(DEBUG, "checking existing progress data from disk");

	progress_str = pv_storage_get_rev_progress(rev);
	if (!progress_str && progress_hub) {
		pv_log(DEBUG,
		       "could not get progress from disk, using progress from Hub");
		progress_str = strdup(progress_hub);
	} else if (progress_str) {
		pv_log(DEBUG, "progress from disk found, checking if final");
		pv_update_progress_parse(progress_str, &u->progress);
		if (pv_update_is_final()) {
			pv_log(WARN, "progress already in a final state");
			_call_report_cb(progress_str);
			free(progress_str);
			goto out;
		} else {
			pv_log(DEBUG, "progress not final, queueing again");
		}
	} else {
		pv_log(DEBUG,
		       "could not get progress neither from disk nor from Hub, using default");
	}

	pv_log(DEBUG, "queueing update");
	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_QUEUED,
			       PV_UPDATE_PROGRESS_MSG_QUEUED);

	pv_log(DEBUG, "verifying update");

	u->progress.retries++;

	pv_log(DEBUG, "update retry count %d", u->progress.retries);

	if (u->progress.retries >= pv_config_get_int(PV_REVISION_RETRIES)) {
		pv_log(WARN, "max update retries eached");
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_WONTGO,
				       PV_UPDATE_PROGRESS_MSG_NO_PROCESSING);
		goto out;
	}

	sign_state_res_t sres;
	sres = pv_signature_verify(state);
	if (sres != SIGN_STATE_OK) {
		pv_log(WARN, "signature validation failed: %s",
		       pv_signature_sign_state_str(sres));
		pv_update_progress_set_str(&u->progress,
					   PV_UPDATE_PROGRESS_STATUS_WONTGO,
					   pv_signature_sign_state_str(sres));
		goto out;
	}
	u->state = pv_parser_get_state(state, rev);
	if (!u->state) {
		pv_log(WARN, "state parse failed");
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_WONTGO,
				       PV_UPDATE_PROGRESS_MSG_NO_PARSE);
		goto out;
	}
	_reset_object_list_retries(u);

	pv_log(DEBUG, "starting update");

	pv_logserver_start_update(rev);

	if (pv_storage_install_state_json(state, rev)) {
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_WONTGO,
				       PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		goto out;
	}

	if (pv_state_are_all_objects_installed(u->state)) {
		pv_log(DEBUG, "all objects already installed");
		_finish_update_installation();
	}
out:
	if (pv_update_is_final())
		pv_update_finish();
}

static void _finish_object_metadata_setting()
{
	off_t update_size, free_size;

	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	update_size = pv_update_progress_get_size(&u->progress);
	pv_log(DEBUG, "update size %jd B", update_size);
	free_size = pv_storage_gc_run_needed(update_size);

	if (update_size > free_size) {
		pv_log(WARN, "free space only %jd B", free_size);
		pv_update_progress_set_str(
			&u->progress, PV_UPDATE_PROGRESS_STATUS_WONTGO,
			"Space required %jd B, available %jd B", update_size,
			free_size);
		return;
	}

	_reset_object_list_retries(u);
	pv_update_progress_start_download(&u->progress);
}

void pv_update_get_unrecorded_objects(char ***objects)
{
	struct pv_state *s;
	struct pv_update *u = _get_update_instance();
	if (!u)
		goto out;

	if (_enroll_object_list(u)) {
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_WONTGO,
				       PV_UPDATE_PROGRESS_MSG_NO_DOWNLOAD);
		goto out;
	}

	s = u->state;
	if (!s) {
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_ERROR,
				       PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		goto out;
	}

	if (pv_state_are_all_objects_recorded(s)) {
		pv_log(WARN,
		       "trying to get unrecorded objects, but they are all already recorded");
		_finish_object_metadata_setting();
		goto out;
	}

	pv_update_progress_start_record(&u->progress);

	*objects = pv_state_get_unrecorded_objects(
		s, pv_config_get_int(PH_UPDATER_TRANSFER_MAX_COUNT));
out:
	if (pv_update_is_final())
		pv_update_finish();
}

void pv_update_set_object_metadata(const char *sha256sum, off_t size,
				   const char *geturl)
{
	off_t free_size = 0;

	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	struct pv_state *s = u->state;
	if (!s)
		return;

	pv_log(DEBUG,
	       "set object metadata: size=%jd sha256sum='%s' geturl='%s'", size,
	       sha256sum, geturl);

	if (!pv_storage_is_object_installed(sha256sum))
		pv_update_progress_add_size(&u->progress, size);
	else
		pv_log(DEBUG, "object '%s' already installed", sha256sum);

	pv_state_set_object_metadata(s, sha256sum, geturl);
	if (!pv_state_are_all_objects_recorded(s))
		goto out;

	pv_log(DEBUG, "every objects metadata recorded");

	_finish_object_metadata_setting();
out:
	if (pv_update_is_final())
		pv_update_finish();
}

void pv_update_get_unavailable_objects(char ***objects)
{
	struct pv_state *s;
	struct pv_update *u = _get_update_instance();
	if (!u)
		goto out;

	if (_enroll_object_list(u)) {
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_WONTGO,
				       PV_UPDATE_PROGRESS_MSG_NO_DOWNLOAD);
		goto out;
	}

	s = u->state;
	if (!s) {
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_ERROR,
				       PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		goto out;
	}

	if (pv_state_are_all_objects_installed(s)) {
		pv_log(WARN,
		       "trying to get unavailable objects, but they are all already installed");
		_finish_update_installation();
		goto out;
	}

	pv_update_progress_set(&u->progress,
			       PV_UPDATE_PROGRESS_STATUS_DOWNLOADING,
			       PV_UPDATE_PROGRESS_MSG_DOWNLOAD_PROGRESS);

	*objects = pv_state_get_unavailable_objects(
		s, pv_config_get_int(PH_UPDATER_TRANSFER_MAX_COUNT));
out:
	if (pv_update_is_final())
		pv_update_finish();
}

char *pv_update_get_object_geturl(const char *sha256sum)
{
	struct pv_state *s = pv_update_get_state();
	if (!s)
		return NULL;

	return pv_state_get_object_geturl(s, sha256sum);
}

int pv_update_install_object(const char *in_path)
{
	int ret = -1;
	char *sha256sum = NULL;
	struct pv_object *o = NULL;

	struct pv_update *u = _get_update_instance();
	if (!u)
		return -1;

	struct pv_state *s = u->state;
	if (!s)
		return -1;

	sha256sum = pv_storage_calculate_sha256sum(in_path);
	if (!sha256sum) {
		pv_log(WARN, "could not calculate sha256sum of '%s': %s",
		       in_path, strerror(errno));
		goto out;
	}

	o = pv_state_fetch_object_id(s, sha256sum);
	if (!o) {
		pv_log(WARN, "object '%s' could not be found in state",
		       sha256sum);
		goto out;
	}

	if (pv_storage_is_object_installed(sha256sum)) {
		pv_log(WARN, "object '%s' already installed", sha256sum);
		goto out;
	}

	if (pv_storage_install_object(in_path, sha256sum)) {
		pv_log(WARN, "could not install '%s'", sha256sum);
		goto out;
	}

	pv_update_progress_add_downloaded(&u->progress, o->size);

	ret = 0;

	if (!pv_state_are_all_objects_installed(s))
		goto out;

	pv_log(DEBUG, "all objects installed");

	_finish_update_installation();
out:
	if (sha256sum)
		free(sha256sum);
	if (pv_update_is_final())
		pv_update_finish();
	return ret;
}

void pv_update_run(const char *rev)
{
	char *json = NULL;
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		goto out;

	struct pv_update *u = _update_new(rev, NULL);
	if (!u)
		goto out;
	pv->update = u;

	pv_log(DEBUG, "loading rev '%s' to be run", rev);

	pv_logserver_start_update(rev);

	json = pv_storage_get_state_json(rev);
	if (!json) {
		pv_log(WARN, "Could not read state json");
		goto out;
	}

	sign_state_res_t sres;
	sres = pv_signature_verify(json);
	if (sres != SIGN_STATE_OK) {
		pv_log(WARN, "signature validation failed: %s",
		       pv_signature_sign_state_str(sres));
		pv_update_progress_set_str(&u->progress,
					   PV_UPDATE_PROGRESS_STATUS_WONTGO,
					   pv_signature_sign_state_str(sres));
		goto out;
	}
	u->state = pv_parser_get_state(json, rev);
	if (!u->state) {
		pv_log(WARN, "state parse failed");
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_WONTGO,
				       PV_UPDATE_PROGRESS_MSG_NO_PARSE);
		goto out;
	}

	_finish_update_installation();
out:
	if (json)
		free(json);
	if (pv_update_is_final())
		pv_update_finish();
}

static bool _is_factory(const char *rev)
{
	if (!rev)
		return false;

	return pv_str_matches(rev, strlen(rev), FACTORY_REVISION,
			      strlen(FACTORY_REVISION));
}

int pv_update_resume(void (*report_cb)(const char *, const char *))
{
	char *progress_str;
	const char *rev;
	struct pv_update *u = NULL;
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return -1;

	// if update already exists, we came from non-reboot update
	if (pv->update) {
		u = pv->update;
		pv_log(DEBUG,
		       "update with rev '%s' to be resumed after non-reboot transition...",
		       pv->update->rev);
		goto out;
	}

	// we know if we are not coming from a reboot from bootloader
	if (pv_bootloader_update_in_progress()) {
		rev = pv_bootloader_get_try();
		if (!rev)
			return -1;
		pv_log(INFO,
		       "loading update data from rev '%s' after reboot...",
		       rev);
	} else {
		rev = pv_bootloader_get_rev();
		if (!rev)
			return -1;
		if (!_is_factory(rev))
			return 0;
		pv_log(INFO, "loading factory revision data...");
	}

	u = _update_new(rev, report_cb);
	if (!u)
		return -1;

	pv_logserver_start_update(rev);
	pv->update = u;

	pv_log(DEBUG, "checking existing progress data from disk");
	progress_str = pv_storage_get_rev_progress(rev);
	if (progress_str) {
		pv_update_progress_parse(progress_str, &u->progress);
		free(progress_str);
	}

	// if we are currently trying a revision that already failed
	if (pv_bootloader_trying_update() && pv_update_is_failed()) {
		pv_log(DEBUG, "revision already failed");
		pv_update_finish();
		return -1;
	}

	// if the revision errored, we might already have what we need to report
	if (pv_update_is_final()) {
		pv_log(DEBUG, "revision already in a final state");
		pv_update_finish();
		return 0;
	}

	// if not coming from a reboot update and no error from disk
	if (!pv_bootloader_trying_update() && !_is_factory(rev)) {
		pv_log(WARN,
		       "booting up after a rollback with no error info from disk");
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_ERROR,
				       PV_UPDATE_PROGRESS_MSG_ROLLEDBACK);
		pv_update_finish();
		return 0;
	}
out:
	if (!u)
		return -1;

	pv_update_progress_set(&u->progress,
			       PV_UPDATE_PROGRESS_STATUS_INPROGRESS,
			       PV_UPDATE_PROGRESS_MSG_TRY);

	return 0;
}

void pv_update_set_factory()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	struct pv_state *s = pv->state;
	if (!s)
		return;

	if (!_is_factory(u->rev))
		return;

	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_DONE,
			       PV_UPDATE_PROGRESS_MSG_FACTORY);
	pv_state_set_done(s);

	pv_update_finish();
}

void pv_update_set_testing()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	if (u->transition == PV_SYSTEM_TRANSITION_REBOOT) {
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_TESTING,
				       PV_UPDATE_PROGRESS_MSG_TESTING_REBOOT);
	} else if (u->transition == PV_SYSTEM_TRANSITION_NONREBOOT) {
		pv_update_progress_set(
			&u->progress, PV_UPDATE_PROGRESS_STATUS_TESTING,
			PV_UPDATE_PROGRESS_MSG_TESTING_NONREBOOT);
	} else {
		pv_log(ERROR, "unknown transition %d", u->transition);
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_ERROR,
				       PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
	}
}

void pv_update_set_error_signature(const char *msg)
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	pv_update_progress_set_str(&u->progress,
				   PV_UPDATE_PROGRESS_STATUS_ERROR, msg);
}

void pv_update_set_error_checksum()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_ERROR,
			       PV_UPDATE_PROGRESS_MSG_BAD_CHECKSUM);
}

void pv_update_set_error_platform()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_ERROR,
			       PV_UPDATE_PROGRESS_MSG_CONTAINER_FAILED);
}

void pv_update_set_error_goal()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_ERROR,
			       PV_UPDATE_PROGRESS_MSG_STATUS_GOAL_FAILED);
}

void pv_update_set_error_hub_reach()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_ERROR,
			       PV_UPDATE_PROGRESS_MSG_HUB_NOT_REACHABLE);
}

void pv_update_set_error_hub_unstable()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return;

	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_ERROR,
			       PV_UPDATE_PROGRESS_MSG_HUB_NOT_STABLE);
}

void pv_update_set_final()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	struct pv_update *u = pv->update;
	if (!u)
		return;

	if (u->transition == PV_SYSTEM_TRANSITION_NONREBOOT) {
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_UPDATED,
				       PV_UPDATE_PROGRESS_MSG_UPDATED);
		goto out;
	}

	pv_update_progress_set(&u->progress, PV_UPDATE_PROGRESS_STATUS_DONE,
			       PV_UPDATE_PROGRESS_MSG_DONE);
	if (pv_bootloader_pre_commit_update(u->rev)) {
		pv_update_progress_set(&u->progress,
				       PV_UPDATE_PROGRESS_STATUS_ERROR,
				       PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		pv_log(ERROR, "revision could not be committed to bootloader");
		goto out;
	}
	pv_state_set_done(pv->state);
	pv_bootloader_post_commit_update(u->rev);
out:
	pv_update_finish();
}

void pv_update_finish()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	struct pv_update *u = pv->update;
	if (!u)
		return;

	pv_log(DEBUG, "finishing update");

	pv_logserver_stop_update(u->rev);

	pv_update_progress_reload_logs(&u->progress);

	_free_update(u);
	pv->update = NULL;
}

static bool _progress_has_status(pv_update_progress_status_t status)
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return false;

	if (u->progress.status != status)
		return false;

	return true;
}

bool pv_update_is_queued()
{
	return _progress_has_status(PV_UPDATE_PROGRESS_STATUS_QUEUED);
}

bool pv_update_is_downloading()
{
	return _progress_has_status(PV_UPDATE_PROGRESS_STATUS_DOWNLOADING);
}

bool pv_update_is_inprogress()
{
	return _progress_has_status(PV_UPDATE_PROGRESS_STATUS_INPROGRESS);
}

bool pv_update_is_testing()
{
	return _progress_has_status(PV_UPDATE_PROGRESS_STATUS_TESTING);
}

bool pv_update_is_failed()
{
	return (_progress_has_status(PV_UPDATE_PROGRESS_STATUS_WONTGO) ||
		_progress_has_status(PV_UPDATE_PROGRESS_STATUS_ERROR));
}

bool pv_update_is_final()
{
	return (_progress_has_status(PV_UPDATE_PROGRESS_STATUS_DONE) ||
		_progress_has_status(PV_UPDATE_PROGRESS_STATUS_UPDATED) ||
		_progress_has_status(PV_UPDATE_PROGRESS_STATUS_WONTGO) ||
		_progress_has_status(PV_UPDATE_PROGRESS_STATUS_ERROR));
}

bool pv_update_is_local()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return false;

	return !(u->report_cb);
}

char *pv_update_get_rev()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return NULL;

	return u->rev;
}

struct pv_state *pv_update_get_state()
{
	struct pv_update *u = _get_update_instance();
	if (!u)
		return NULL;

	return u->state;
}
