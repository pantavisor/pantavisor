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

#include "update/update.h"
#include "update/update_struct.h"

#define MODULE_NAME "update"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static struct pv_update_t *_update_new(const char *rev)
{
	struct pv_update_t *u = calloc(1, sizeof(struct pv_update_t));
	if (!u)
		return NULL;

	u->rev = strdup(rev);

	// this progess should never reach Hub
	u->progress.status = PV_STATUS_WONTGO;
	u->progress.msg = strdup(PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR);

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

bool _update_progress_status_is_final(pv_update_progress_status_t status)
{
	return ((status == PV_STATUS_DONE) || (status == PV_STATUS_UPDATED) ||
		(status == PV_STATUS_WONTGO) || (status == PV_STATUS_ERROR));
}

char *pv_update_start(const char *rev, const char *msg,
		      const char *progress_hub, const char *state)
{
	int res;
	char *ret = NULL;
	struct pantavisor *pv = pv_get_instance();

	if (!rev || !state)
		goto out;

	pv_log(DEBUG, "evaluating whether update of rev '%s' can be started",
	       rev);

	pv_update_t *u = _update_new(rev);
	if (!u)
		goto out;

	pv_log(DEBUG, "checking existing progress data");

	ret = pv_storage_get_rev_progress(rev);
	if (!ret && progress_hub)
		ret = strdup(progress_hub);
	if (ret)
		pv_update_progress_parse(ret, &update->progress);

	if (_update_progress_status_is_final(&u->progress.status)) {
		pv_log(WARN, "update already in a final state");
		goto out;
	}

	if (ret)
		free(ret);
	ret = NULL;

	pv_log(DEBUG, "queueing update");

	pv_update_progress_set_status(&u->progress, PV_STATUS_QUEUED);
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
		pv_log(WARN, "max update processing retries %d reached",
		       u->progress.retries);
		pv_update_progress_set_status(&u->progress, PV_STATUS_WONTGO);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_NO_PROCESSING);
		goto out;
	}

	sres = pv_signature_verify(state);
	if (sres != SIGN_STATE_OK) {
		pv_log(WARN, "signature validation failed: %s",
		       pv_signature_sign_state_str(sres));
		pv_update_progress_set_status(&u->progress, PV_STATUS_WONTGO);
		pv_update_progress_set_msg_str(
			&u->progress, pv_signature_sign_state_str(sres));
		goto out;
	}
	u->state = pv_parser_get_state(state, rev);
	if (!u->state) {
		pv_log(WARN, "state parse failed");
		pv_update_progress_set_status(&u->progress, PV_STATUS_WONTGO);
		pv_update_progress_set_msg_code(
			&u->progress, PV_UPDATE_PROGRESS_MSG_NO_PARSE);
		goto out;
	}

	pv_log(DEBUG, "stating update");

	pv_logserver_start_update(rev);

	pv_paths_storage_trail_pvr_file(path, PATH_MAX, rev, JSON_FNAME);
	if (pv_fs_file_save(path, state, 0644) < 0) {
		pv_log(ERROR, "could not save %s: %s", path, strerror(errno));
		goto out;
	}

	pv->update2 = u;
out:
	if (!pv || !u) {
		pv_log(WARN, "will not return progress");
		return NULL;
	}

	if (ret && _is_update_final(u)) {
		_update_free(u);
		return ret;
	}

	ret = pv_update_progress_ser(&u->progress);

	if (_is_update_final(u))
		_update_free(u);

	return ret;
}

void pv_update_finish();
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	pv_update_t *u = pv->update2;
	if (!u->update2)
		return;

	pv_logserver_stop_update(u->rev);

	pv_update_update_free(u);
	pv->update2 = NULL;
}
