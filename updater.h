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
#ifndef PV_UPDATER_H
#define PV_UPDATER_H

#include "pantavisor.h"
#include <trest.h>

#define DEVICE_TRAIL_ENDPOINT_FMT "/trails/%s/steps"
#define DEVICE_STEP_ENDPOINT_FMT "/trails/%s/steps/%d/progress"
#define DEVICE_STEP_STATUS_FMT "{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d }"
#define DEVICE_STEP_STATUS_FMT_WITH_DATA  	\
	"{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d ,\"data\":\"%s\"}"
#define DEVICE_STEP_STATUS_FMT_PROGRESS_DATA  	\
	"{ \"status\" : \"%s\", \"status-msg\" : \"%s\", \"progress\" : %d ,\"data\":\"%s\",\
	\"downloads\": {\"total\":%s, \"objects\":[%s]}}"


#define TRAIL_OBJECT_DL_FMT	"/objects/%s"
#define DEVICE_TRAIL_ENDPOINT_QUEUED "?progress.status=QUEUED"
#define DEVICE_TRAIL_ENDPOINT_NEW "?progress.status=NEW"
#define DEVICE_TRAIL_ENDPOINT_DOWNLOADING "?progress.status=DOWNLOADING"
#define DEVICE_TRAIL_ENDPOINT_INPROGRESS "?progress.status=INPROGRESS"

#define VOLATILE_TMP_OBJ_PATH "/tmp/object-XXXXXX"
#define MMC_TMP_OBJ_FMT "%s.tmp"

#define DEFAULT_DOWNLOAD_RETRY_WAIT  (2 * 60) /*2 minutes*/
#define UPDATE_PROGRESS_FREQ 	(3) /*3 seconds for update*/

extern int MAX_REVISION_RETRIES;
extern int DOWNLOAD_RETRY_WAIT;

#define DEFAULT_MAX_REVISION_RETRIES 	(10)
#define DEFAULT_UPDATE_COMMIT_DELAY 	(3 * 60)

enum update_state {
	UPDATE_INIT,
	UPDATE_QUEUED,
	UPDATE_DOWNLOADED,
	UPDATE_INSTALLED,
	UPDATE_TRY,
	UPDATE_TRANSITION,
	UPDATE_REBOOT,
	UPDATE_UPDATED,
	UPDATE_DONE,
	UPDATE_FAILED,
	UPDATE_NO_DOWNLOAD,
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
	enum update_state status;
	char *endpoint;
	int runlevel;
	int progress_size;
	time_t retry_at;
	struct pv_state *pending;
	char *progress_objects;
	struct object_update *total_update;
};

struct trail_remote {
	trest_ptr client;
	char *endpoint_trail_queued;
	char *endpoint_trail_new;
	char *endpoint_trail_downloading;
	char *endpoint_trail_inprogress;
	struct pv_state *pending;
};

int pv_check_for_updates(struct pantavisor *pv);
bool pv_trail_is_auth(struct pantavisor *pv);
void pv_trail_remote_remove(struct pantavisor *pv);

int pv_update_install(struct pantavisor *pv);
int pv_update_resume(struct pantavisor *pv);
void pv_update_test(struct pantavisor *pv);
int pv_update_finish(struct pantavisor *pv);

bool pv_update_requires_reboot(struct pantavisor *pv);

bool pv_update_is_transitioning(struct pv_update *u);
bool pv_update_is_trying(struct pv_update *u);
bool pv_update_is_testing(struct pv_update *u);

int pv_update_set_status(struct pantavisor *pv, enum update_state status);

#endif
