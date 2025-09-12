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

#define MODULE_NAME "update"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define DEFAULT_COUNT 5

static pv_update_t *_update_new(const char *rev)
{
	pv_update_t *u = calloc(1, sizeof(pv_update_t));
	if (!u)
		return NULL;

	u->rev = strdup(rev);

	// this progess should never reach Hub
	pv_update_progress_set_status(&u->progress,
				      PV_UPDATE_PROGRESS_STATUS_WONTGO);
	pv_update_progress_set_msg_code(&u->progress,
					PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);

	return u;
}

static void _update_free(pv_update_t *update)
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

static void _reset_object_list_retries(pv_update_t *update)
{
	if (!update)
		return;

	update->object_list_retries = 0;
}

static int _enroll_object_list(pv_update_t *update)
{
	int object_list_max_retries;
	object_list_max_retries =
		pv_state_get_object_count(update->state) / DEFAULT_COUNT;

	pv_log(DEBUG, "enroll object list retry count %d",
	       update->object_list_retries);

	update->object_list_retries++;
	if (update->object_list_retries >= object_list_max_retries) {
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
	}

	return 0;
}

char *pv_update_start_install(const char *rev, const char *msg,
			      const char *progress_hub, const char *state)
{
	int res;
	char *ret = NULL;
	struct pantavisor *pv = pv_get_instance();

	if (!rev || !state)
		goto out;

	pv_log(DEBUG, "evaluating whether update from rev '%s' can be started",
	       rev);

	pv_update_t *u = _update_new(rev);
	if (!u)
		goto out;

	pv_log(DEBUG, "checking existing progress data");

	ret = pv_storage_get_rev_progress(rev);
	if (!ret && progress_hub) {
		pv_log(DEBUG,
		       "could not get progress from disk, using progress from Hub");
		ret = strdup(progress_hub);
	} else
		pv_log(DEBUG,
		       "could not get progress neither from disk nor from Hub, using default");

	if (ret)
		pv_update_progress_parse(ret, &u->progress);

	if (pv_update_is_final()) {
		pv_log(WARN, "update already in a final state");
		goto out;
	}

	if (ret)
		free(ret);
	ret = NULL;

	pv_log(DEBUG, "queueing update");

	pv_update_progress_set_status(&u->progress,
				      PV_UPDATE_PROGRESS_STATUS_QUEUED);
	pv_update_progress_set_msg_code(&u->progress,
					PV_UPDATE_PROGRESS_MSG_QUEUED);

	if (pv && pv->update2) {
		pv_log(DEBUG, "another update already in progress");
		goto out;
	}

	pv_log(DEBUG, "verifying update");

	u->progress.retries++;

	pv_log(DEBUG, "update retry count %d", u->progress.retries);

	if (u->progress.retries >= pv_config_get_int(PV_REVISION_RETRIES)) {
		pv_log(WARN, "max update retries eached");
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_WONTGO);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_NO_PROCESSING);
		goto out;
	}

	sign_state_res_t sres;
	sres = pv_signature_verify(state);
	if (sres != SIGN_STATE_OK) {
		pv_log(WARN, "signature validation failed: %s",
		       pv_signature_sign_state_str(sres));
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_WONTGO);
		pv_update_progress_set_msg_str(
			&u->progress, pv_signature_sign_state_str(sres));
		goto out;
	}
	u->state = pv_parser_get_state(state, rev);
	if (!u->state) {
		pv_log(WARN, "state parse failed");
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_WONTGO);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_NO_PARSE);
		goto out;
	}
	_reset_object_list_retries(u);

	pv_log(DEBUG, "stating update");

	pv_logserver_start_update(rev);

	if (pv_storage_install_state_json(state, rev)) {
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_WONTGO);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		goto out;
	}

	pv->update2 = u;
out:
	if (!pv || !u) {
		pv_log(WARN, "will not return progress");
		return NULL;
	}

	if (ret) {
		_update_free(u);
		return ret;
	}

	ret = pv_update_progress_ser(&u->progress);

	if (pv_update_is_final())
		_update_free(u);

	return ret;
}

char *pv_update_finish_install()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return NULL;

	pv_update_t *u = pv->update2;
	if (!u)
		return NULL;

	pv_logserver_stop_update(u->rev);

	_update_free(u);
	pv->update2 = NULL;

	return NULL;
}

char *pv_update_get_unrecorded_objects(char ***objects)
{
	char *ret = NULL;
	struct pantavisor *pv = pv_get_instance();

	if (!pv)
		return NULL;

	pv_update_t *u = pv->update2;
	if (!u)
		return NULL;

	struct pv_state *s = pv->update2->state;
	if (!s)
		return NULL;

	if (_enroll_object_list(u)) {
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_WONTGO);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_NO_DOWNLOAD);
		goto out;
	}

	pv_update_progress_set_msg_code(
		&u->progress, PV_UPDATE_PROGRESS_MSG_PREP_DOWNLOAD_PROGRESS);
	pv_update_progress_start_record(&u->progress);

	*objects = pv_state_get_unrecorded_objects(s, DEFAULT_COUNT);
out:
	ret = pv_update_progress_ser(&u->progress);

	if (pv_update_is_final())
		_update_free(u);

	return ret;
}

void _finish_object_metadata_setting()
{
	off_t update_size, free_size;

	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	pv_update_t *u = pv->update2;
	if (!u)
		return;

	update_size = pv_update_progress_get_size(&u->progress);
	pv_log(DEBUG, "update size %jd B", update_size);
	free_size = pv_storage_gc_run_needed(update_size);

	if (update_size > free_size) {
		pv_log(WARN, "free space only %jd B", free_size);
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_WONTGO);
		pv_update_progress_set_msg_str(
			&u->progress, "Space required %jd B, available %jd B",
			update_size, free_size);
		return;
	}

	_reset_object_list_retries(u);

	pv_update_progress_set_status(&u->progress,
				      PV_UPDATE_PROGRESS_STATUS_DOWNLOADING);
	pv_update_progress_set_msg_code(
		&u->progress, PV_UPDATE_PROGRESS_MSG_DOWNLOAD_PROGRESS);
	pv_update_progress_start_download(&u->progress);
}

char *pv_update_set_object_metadata(const char *sha256sum, off_t size,
				    const char *geturl)
{
	char *ret = NULL;
	off_t free_size = 0;
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return NULL;

	pv_update_t *u = pv->update2;
	if (!u)
		return NULL;

	struct pv_state *s = pv->update2->state;
	if (!s)
		return NULL;

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
	ret = pv_update_progress_ser(&u->progress);

	if (pv_update_is_final())
		_update_free(u);

	return ret;
}

char *pv_update_get_unavailable_objects(char ***objects)
{
	char *ret = NULL;
	struct pantavisor *pv = pv_get_instance();

	if (!pv)
		return NULL;

	pv_update_t *u = pv->update2;
	if (!u)
		return NULL;

	struct pv_state *s = pv->update2->state;
	if (!s)
		return NULL;

	if (_enroll_object_list(u)) {
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_WONTGO);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_NO_DOWNLOAD);
		goto out;
	}

	pv_update_progress_set_msg_code(
		&u->progress, PV_UPDATE_PROGRESS_MSG_DOWNLOAD_PROGRESS);

	*objects = pv_state_get_unavailable_objects(s, DEFAULT_COUNT);
out:
	ret = pv_update_progress_ser(&u->progress);

	if (pv_update_is_final())
		_update_free(u);

	return ret;
}

char *pv_update_get_object_geturl(const char *sha256sum)
{
	struct pantavisor *pv = pv_get_instance();

	if (!pv)
		return NULL;

	pv_update_t *u = pv->update2;
	if (!u)
		return NULL;

	struct pv_state *s = pv->update2->state;
	if (!s)
		return NULL;

	return pv_state_get_object_geturl(s, sha256sum);
}

void _finish_object_installation()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	pv_update_t *u = pv->update2;
	if (!u)
		return;

	struct pv_state *s = pv->update2->state;
	if (!s)
		return;

	pv_update_progress_set_status(&u->progress,
				      PV_UPDATE_PROGRESS_STATUS_INPROGRESS);
	pv_update_progress_set_msg_code(&u->progress,
					PV_UPDATE_PROGRESS_MSG_DOWNLOADED);

	if (pv_state_prepare_run(s)) {
		pv_log(WARN, "could not prepare state to be run");
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_ERROR);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		return;
	}

	if (pv_bootloader_install_update(s->rev)) {
		pv_log(WARN, "could not set bootloader with new update info");
		pv_update_progress_set_status(&u->progress,
					      PV_UPDATE_PROGRESS_STATUS_ERROR);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);
		return;
	}

	pv_update_progress_set_status(&u->progress,
				      PV_UPDATE_PROGRESS_STATUS_INPROGRESS);
	pv_update_progress_set_msg_code(&u->progress,
					PV_UPDATE_PROGRESS_MSG_INSTALLED);

	// TODO: pv_run(s);
}

char *pv_update_install_object(const char *in_path)
{
	char *ret = NULL;
	unsigned char *sha256sum = NULL;
	struct pv_object *o = NULL;
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return NULL;

	pv_update_t *u = pv->update2;
	if (!u)
		return NULL;

	struct pv_state *s = pv->update2->state;
	if (!s)
		return NULL;

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
	ret = pv_update_progress_ser(&u->progress);

	if (!pv_state_are_all_objects_installed(s))
		goto out;

	pv_log(DEBUG, "all objects installed");

	_finish_object_installation();

out:
	if (sha256sum)
		free(sha256sum);
	if (pv_update_is_final())
		_update_free(u);
	return ret;
}

static bool _progress_has_status(pv_update_progress_status_t status)
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return false;

	pv_update_t *u = pv->update2;
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

bool pv_update_is_final()
{
	return (_progress_has_status(PV_UPDATE_PROGRESS_STATUS_DONE) ||
		_progress_has_status(PV_UPDATE_PROGRESS_STATUS_UPDATED) ||
		_progress_has_status(PV_UPDATE_PROGRESS_STATUS_WONTGO) ||
		_progress_has_status(PV_UPDATE_PROGRESS_STATUS_ERROR));
}

char *pv_update_get_rev(void)
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return NULL;

	pv_update_t *u = pv->update2;
	if (!u)
		return NULL;

	return u->rev;
}
