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
#ifndef PV_UPDATE_STRUCT_H
#define PV_UPDATE_STRUCT_H

#include <sys/types.h>

typedef enum {
	PV_UPDATE_PROGRESS_STATUS_NEW,
	PV_UPDATE_PROGRESS_STATUS_QUEUED,
	PV_UPDATE_PROGRESS_STATUS_DOWNLOADING,
	PV_UPDATE_PROGRESS_STATUS_INPROGRESS,
	PV_UPDATE_PROGRESS_STATUS_TESTING,
	PV_UPDATE_PROGRESS_STATUS_UPDATED,
	PV_UPDATE_PROGRESS_STATUS_DONE,
	PV_UPDATE_PROGRESS_STATUS_WONTGO,
	PV_UPDATE_PROGRESS_STATUS_ERROR,
	PV_UPDATE_PROGRESS_STATUS_UNKNOWN
} pv_update_progress_status_t;

typedef enum {
	PV_UPDATE_PROGRESS_MSG_ABORTED,
	PV_UPDATE_PROGRESS_MSG_QUEUED,
	PV_UPDATE_PROGRESS_MSG_DOWNLOADED,
	PV_UPDATE_PROGRESS_MSG_INSTALLED,
	PV_UPDATE_PROGRESS_MSG_APPLIED,
	PV_UPDATE_PROGRESS_MSG_TRY,
	PV_UPDATE_PROGRESS_MSG_TRANSITION,
	PV_UPDATE_PROGRESS_MSG_REBOOT,
	PV_UPDATE_PROGRESS_MSG_UPDATED,
	PV_UPDATE_PROGRESS_MSG_DONE,
	PV_UPDATE_PROGRESS_MSG_BAD_CHECKSUM,
	PV_UPDATE_PROGRESS_MSG_HUB_NOT_REACHABLE,
	PV_UPDATE_PROGRESS_MSG_HUB_NOT_STABLE,
	PV_UPDATE_PROGRESS_MSG_STALE_REVISION,
	PV_UPDATE_PROGRESS_MSG_STATUS_GOAL_FAILED,
	PV_UPDATE_PROGRESS_MSG_CONTAINER_FAILED,
	PV_UPDATE_PROGRESS_MSG_INTERNAL_ERROR,
	PV_UPDATE_PROGRESS_MSG_NO_PROCESSING,
	PV_UPDATE_PROGRESS_MSG_NO_DOWNLOAD,
	PV_UPDATE_PROGRESS_MSG_NO_PARSE,
	PV_UPDATE_PROGRESS_MSG_RETRY_DOWNLOAD,
	PV_UPDATE_PROGRESS_MSG_TESTING_REBOOT,
	PV_UPDATE_PROGRESS_MSG_TESTING_NONREBOOT,
	PV_UPDATE_PROGRESS_MSG_DOWNLOAD_PROGRESS,
	PV_UPDATE_PROGRESS_MSG_ROLLEDBACK
} pv_update_progress_msg_t;

typedef struct {
	off_t total_size;
	off_t start_time;
	off_t current_time;
	off_t total_downloaded;
} pv_download_info_t;

typedef struct {
	pv_update_progress_status_t status;
	char *msg;
	char *logs;
	int progress;
	int retries;
	pv_download_info_t total;
} pv_update_progress_t;

typedef struct {
	char *rev;
	pv_update_progress_t progress;
	struct pv_state *state;
} pv_update_t;

#endif
