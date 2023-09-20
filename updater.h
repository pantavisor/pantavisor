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
#ifndef PV_UPDATER_H
#define PV_UPDATER_H

#include "pantavisor.h"
#include "timer.h"
#include <trest.h>

#define DEVICE_TRAIL_ENDPOINT_FMT "/trails/%s/steps"
#define DEVICE_STEP_ENDPOINT_FMT "/trails/%s/steps/%s/progress"
#define DEVICE_STEP_STATUS_FMT                                                 \
	"{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d }"
#define DEVICE_STEP_STATUS_WONTGO_FMT                                          \
	"{ \"status\" : \"WONTGO\", \"status-msg\" : \"%s: %s\", \"progress\" : 0 }"
#define DEVICE_STEP_STATUS_ERROR_FMT                                           \
	"{ \"status\" : \"ERROR\", \"status-msg\" : \"%s: %s\", \"progress\" : 0 }"
#define DEVICE_STEP_STATUS_FMT_WITH_DATA                                       \
	"{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d ,\"data\":\"%d\"}"
#define DEVICE_STEP_STATUS_FMT_PROGRESS_DATA                                   \
	"{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d ,\"data\":\"%d\",\
	\"downloads\": {\"total\":%s, \"objects\":[%s]}}"
#define DEVICE_STEP_FACTORY_PROGRESS_UNREGISTERED                              \
	"{ \"status\" : \"UNREGISTERED\", \"status-msg\" : \"Registering\", \"progress\" : 0 }"
#define DEVICE_STEP_FACTORY_PROGRESS_UNCLAIMED                                 \
	"{ \"status\" : \"UNCLAIMED\", \"status-msg\" : \"Waiting for claim\", \"progress\" : 0 }"
#define DEVICE_STEP_FACTORY_PROGRESS_SYNCING                                   \
	"{ \"status\" : \"SYNCING\", \"status-msg\" : \"Uploading initial data\", \"progress\" : 20 }"
#define DEVICE_STEP_FACTORY_PROGRESS_DONE                                      \
	"{ \"status\" : \"DONE\", \"status-msg\" : \"Factory revision\", \"progress\" : 100 }"

#define TRAIL_OBJECT_DL_FMT "/objects/%s"
#define DEVICE_TRAIL_ENDPOINT_QUEUED "?progress.status=QUEUED"
#define DEVICE_TRAIL_ENDPOINT_NEW "?progress.status=NEW"
#define DEVICE_TRAIL_ENDPOINT_DOWNLOADING "?progress.status=DOWNLOADING"
#define DEVICE_TRAIL_ENDPOINT_INPROGRESS "?progress.status=INPROGRESS"

#define MMC_TMP_OBJ_FMT "%s.tmp"

#define UPDATE_PROGRESS_FREQ (3) /*3 seconds for update*/

enum update_status {
	UPDATE_INIT,
	UPDATE_ABORTED,
	UPDATE_QUEUED,
	UPDATE_DOWNLOADED,
	UPDATE_INSTALLED,
	UPDATE_APPLIED,
	UPDATE_TRY,
	UPDATE_TRANSITION,
	UPDATE_REBOOT,
	UPDATE_UPDATED,
	UPDATE_DONE,
	UPDATE_SIGNATURE_FAILED,
	UPDATE_BAD_CHECKSUM,
	UPDATE_HUB_NOT_REACHABLE,
	UPDATE_HUB_NOT_STABLE,
	UPDATE_STALE_REVISION,
	UPDATE_STATUS_GOAL_FAILED,
	UPDATE_CONTAINER_STOPPED,
	UPDATE_CONTAINER_FAILED,
	UPDATE_INTERNAL_ERROR,
	UPDATE_NO_DOWNLOAD,
	UPDATE_NO_SPACE,
	UPDATE_BAD_SIGNATURE,
	UPDATE_NO_PARSE,
	UPDATE_RETRY_DOWNLOAD,
	UPDATE_TESTING_REBOOT,
	UPDATE_TESTING_NONREBOOT,
	UPDATE_DOWNLOAD_PROGRESS
};

struct object_update {
	char *object_name;
	char *object_id;
	uint64_t total_size;
	uint64_t start_time;
	uint64_t current_time;
	uint64_t total_downloaded;
};

struct pv_update {
	enum update_status status;
	char *endpoint;
	int progress_size;
	struct timer retry_timer;
	char *rev;
	struct pv_state *pending;
	char *progress_objects;
	int retries;
	struct object_update *total_update;
	bool local;
};

struct trail_remote {
	trest_ptr client;
	char *endpoint_trail_queued;
	char *endpoint_trail_new;
	char *endpoint_trail_downloading;
	char *endpoint_trail_inprogress;
	struct pv_state *pending;
};

void pv_update_free(struct pv_update *update);

int pv_updater_check_for_updates(struct pantavisor *pv);
bool pv_trail_is_auth(struct pantavisor *pv);
void pv_trail_remote_remove(struct pantavisor *pv);

struct pv_update *pv_update_get_step_local(char *rev);

int pv_update_download(struct pantavisor *pv);
int pv_update_install(struct pantavisor *pv);
int pv_update_resume(struct pantavisor *pv);
void pv_update_test(struct pantavisor *pv);
int pv_update_finish(struct pantavisor *pv);

bool pv_update_is_transitioning(struct pv_update *u);
bool pv_update_is_trying(struct pv_update *u);
bool pv_update_is_testing(struct pv_update *u);

void pv_update_set_status_msg(struct pv_update *update,
			      enum update_status status, const char *msg);
void pv_update_set_status(struct pv_update *update, enum update_status status);

#endif
