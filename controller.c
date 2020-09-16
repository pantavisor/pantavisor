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
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sys/reboot.h>
#include <linux/limits.h>
#include <linux/reboot.h>

#include "utils.h"
#include "pantavisor.h"
#include "loop.h"
#include "platforms.h"
#include "controller.h"
#include "updater.h"
#include "volumes.h"
#include "pantahub.h"
#include "bootloader.h"
#include "cmd.h"
#include "device.h"
#include "version.h"
#include "wdt.h"
#include "network.h"
#include "blkid.h"
#include "init.h"

#define MODULE_NAME		"controller"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "storage.h"
#include "tsh.h"
#include "ph_logger/ph_logger.h"

#define CMDLINE_OFFSET	7

static int rb_count;
static time_t wait_delay;
static time_t commit_delay;
static bool pending_commit = false;

typedef enum {
	STATE_INIT,
	STATE_RUN,
	STATE_WAIT,
	STATE_COMMAND,
	STATE_UNCLAIMED,
	STATE_UPDATE,
	STATE_ROLLBACK,
	STATE_REBOOT,
	STATE_ERROR,
	STATE_EXIT,
	STATE_FACTORY_UPLOAD,
	MAX_STATES
} pv_state_t;

static const char* pv_state_string(pv_state_t st)
{
	switch(st) {
	case STATE_INIT: return "STATE_INIT";
	case STATE_RUN: return "STATE_RUN";
	case STATE_WAIT: return "STATE_WAIT";
	case STATE_COMMAND: return "STATE_COMMAND";
	case STATE_UNCLAIMED: return "STATE_UNCLAIMED";
	case STATE_UPDATE: return "STATE_UPDATE";
	case STATE_ROLLBACK: return "STATE_ROLLBACK";
	case STATE_REBOOT: return "STATE_REBOOT";
	case STATE_ERROR: return "STATE_ERROR";
	case STATE_EXIT: return "STATE_EXIT";
	case STATE_FACTORY_UPLOAD: return "STATE_FACTORY_UPLOAD";
	default: return "STATE_UNKNOWN";
	}

	return "UNKNOWN PV STATE";
}

typedef pv_state_t pv_state_func_t(struct pantavisor *pv);

static pv_state_t _pv_factory_upload(struct pantavisor *pv)
{
	int ret = -1;
	
	ret = pv_device_factory_meta(pv);
	if (ret)
		return STATE_FACTORY_UPLOAD;
	return STATE_WAIT;
}

static int pv_step_get_prev(struct pantavisor *pv)
{
	if (!pv)
		return -1;

	if (pv->state)
		return (pv->state->rev - 1);

	return -1;
}

static pv_state_t _pv_init(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);
	struct pantavisor_config *c;

	// Initialize flags
	pv->flags = 0;
	c = calloc(1, sizeof(struct pantavisor_config));
	pv->config = c;
	if (pv_do_execute_init())
		return STATE_EXIT;
        return STATE_RUN;
}

static pv_state_t _pv_run(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);
	int ret;
	struct timespec tp;

	if (!pv->state)
		return STATE_ERROR;

	pv_meta_set_objdir(pv);

	if (pv_volumes_mount(pv, ROOT) < 0)
		return STATE_ROLLBACK;

	/*
	 * [PKS]
	 * mark active only when platforms have been started.
	 */
	pv_set_active(pv);

	ret = pv_make_config(pv);
	if (ret < 0) {
		pv_log(ERROR, "error making config");
		return STATE_ROLLBACK;
	}

	ret = pv_platforms_start(pv, ROOT);
	if (ret < 0) {
		pv_log(ERROR, "error starting platforms");
		return STATE_ROLLBACK;
	}

	pv_log(INFO, "started %d platforms", ret);

	rb_count = 0;

	// set initial wait delay
	clock_gettime(CLOCK_MONOTONIC, &tp);
	wait_delay = tp.tv_sec + pv->config->updater.interval;
	commit_delay = tp.tv_sec + pv->config->update_commit_delay;

	return STATE_WAIT;
}

static pv_state_t _pv_unclaimed(struct pantavisor *pv)
{
	int need_register = 1;
	struct stat st;
	char config_path[256];
	char *c;

	if (!pv_ph_is_available(pv)) {
		return STATE_WAIT;
	}

	c = calloc(1, sizeof(char) * 128);

	sprintf(config_path, "%s/config/unclaimed.config", pv->config->storage.mntpoint);
	if (stat(config_path, &st) == 0)
		ph_config_from_file(config_path, pv->config);

	if ((strcmp(pv->config->creds.id, "") != 0) && pv_ph_device_exists(pv))
		need_register = 0;

	if (need_register && pv_ph_register_self(pv)) {
		ph_config_to_file(pv->config, config_path);
		pv_ph_release_client(pv);
	}

	if (!pv_ph_device_is_owned(pv, &c)) {
		pv_log(INFO, "device challenge: '%s'", c);
		pv_ph_update_hint_file(pv, c);
	} else {
		pv_log(INFO, "device has been claimed, proceeding normally");
		printf("INFO: pantavisor device has been claimed, proceeding normally\n");
		sprintf(config_path, "%s/config/pantahub.config", pv->config->storage.mntpoint);
		ph_config_to_file(pv->config, config_path);
		pv_ph_release_client(pv);
		pv->flags &= ~DEVICE_UNCLAIMED;
		open("/pv/challenge", O_TRUNC | O_WRONLY);
	}

	if (c)
		free(c);

	return STATE_FACTORY_UPLOAD;
}

/*
 * Network intensive work should be ideally
 * done in it's own process.
 * Most of the time we don't need anything from pantavisor
 * apart from endpoints which can be created locally.
 */
static int pv_meta_update_to_ph(struct pantavisor *pv)
{
	if (!pv)
		return 0;
	// update meta
	pv_device_info_upload(pv);
	pv_network_update_meta(pv);
	pv_ph_device_get_meta(pv);
	return 0;
}

/*
 * _pv_wait is doing the following,
 *
 * 1. Waiting for a command on commad socket,
 * 2. Checking if device is unclaimed,
 * 3. Checking if ph is available,
 * 4. Updating meta information to PH,
 * 5. Check if a platform has exited,
 * 6. Clears an update if pending, either failed or success,
 * 7. Sets device status.
 *
 * I propose to move all network part or things which can
 * be offloaded to separate process. These would include mostly
 * the network operations.
 *
 * In above network operations include,
 * -> check if PH is available.
 * -> updating meta infromation to PH,
 * -> check if update is available,
 *
 * -> Update needs to be cleared later after we've successfully
 * started all the platforms and uploaded the information to PH
 * 
 * This can be taken care of in the helper thread as follows,
 * -> When the update is cleared, the helper posts a command
 * to pv to clear bl
 * 
 * All the above operations can be done in a separate helper
 * process. That process will post a command to pv which we'll
 * read in _pv_wait below and act upon that.
 *
 * Device update / pending etc should be done while handling
 * update state.
 */

static pv_state_t pv_update_helper(struct pantavisor *pv)
{
	static enum update_state current_status = UPDATE_DONE;
	static bool status_updated = false;
	struct timespec tp;
	pv_state_t next_state = STATE_WAIT;
	int ret = 0;
	int timeout_max = pv->config->updater.network_timeout
		/ pv->config->updater.interval;
	/*
	 * The update struct would become private and not
	 * associated with pv at all. pv would only contain
	 * state and config information.
	 */

	// if online update pending to clear, commit update to cloud
	if (pv->update && pv->update->status == UPDATE_TRY) {
		if (pv_set_current_status(pv, UPDATE_DEVICE_AUTH_OK)) {
			if (rb_count > timeout_max)
				return STATE_ROLLBACK;

			clock_gettime(CLOCK_MONOTONIC, &tp);
			wait_delay = tp.tv_sec + pv->config->updater.interval;
			pv_log(WARN, "Device couldn't authenticate to Pantahub. Retrying in %d seconds",
					pv->config->updater.interval);
			rb_count++;
			return STATE_WAIT;
		} else {
			/*
			 * we clear the pending update
			 * but we delay the commit of this update.
			 */
			pv_update_set_status(pv, UPDATE_DEVICE_COMMIT_WAIT);
			pv_update_finish(pv);
			pending_commit = true;
		}
	} else if (pv->update && pv->update->status == UPDATE_FAILED) {
		// We come from a forced rollback
		pv_set_current(pv, pv->state->rev);
		pv_update_set_status(pv, UPDATE_FAILED);
		if (!pv_update_finish(pv))
			status_updated = true;
		current_status = UPDATE_FAILED;
	}
	if (pending_commit) {
			clock_gettime(CLOCK_MONOTONIC, &tp);
			if (commit_delay > tp.tv_sec) {
				current_status = UPDATE_DEVICE_COMMIT_WAIT;
				pv_log(WARN, "Committing new update in %d seconds", commit_delay - tp.tv_sec);
				goto out;
			}
			pv_bl_clear_update(pv);
			pv_set_current(pv, pv->state->rev);
			pending_commit = false;
			status_updated = false;
			current_status = UPDATE_DONE;
			pv_log(INFO, "Marking revision %d as DONE",
					pv->state->rev);
	}
	// check for updates
	ret = pv_check_for_updates(pv);
	if (ret > 0) {
		pv_log(INFO, "updates found");
		next_state = STATE_UPDATE;
	}
out:
	if (!status_updated && !pv_set_current_status(pv, current_status))
		status_updated = true;
	/* set delay to at most the updater interval */
	clock_gettime(CLOCK_MONOTONIC, &tp);
	wait_delay = tp.tv_sec + pv->config->updater.interval;
	return next_state;
}

/*
 * Helper process comprises of most of the network actions.
 * 1. Uploading Meta information (One time).
 * 2. Checking for updates.
 * 3. Checking for PH availability
 *
 * Return statement of helper process would be made into
 * a separate command for command socket.
 */
static pv_state_t pv_helper_process(struct pantavisor *pv)
{
	pv_state_t next_state = STATE_WAIT;
	struct timespec tp;
	int timeout_max = pv->config->update_commit_delay
		/ pv->config->updater.interval;

	if (!pv_ph_is_available(pv)) {
		rb_count++;
		if (!pv_rev_is_done(pv, pv->state->rev) &&
				(rb_count > timeout_max)) {
			next_state = STATE_ROLLBACK;
			goto out;
		}
		clock_gettime(CLOCK_MONOTONIC, &tp);
		wait_delay = tp.tv_sec + pv->config->updater.interval;
		pv_log(WARN, "current rb_count = %d, max_allowed = %d",
				rb_count, timeout_max);
		goto out;
	}
	if (!pv_device_factory_meta_done(pv)) {
		next_state = STATE_FACTORY_UPLOAD;
		goto out;
	}
	pv_meta_update_to_ph(pv);
	next_state = pv_update_helper(pv);
out:
	pv_log(DEBUG, "going to state = %s", pv_state_string(STATE_WAIT));
	return next_state;
}

static pv_state_t _pv_wait(struct pantavisor *pv)
{
	struct timespec tp;
	pv_state_t next_state = STATE_WAIT;

	if (pv->req) {
		pv_log(WARN, "stable command found queued, discarding");
		pv_cmd_finish(pv);
		goto out;
	}

	clock_gettime(CLOCK_MONOTONIC, &tp);
	if (wait_delay > tp.tv_sec) {
		pv->req = pv_cmd_socket_wait(pv, 5);
		if (pv->req)
			next_state = STATE_COMMAND;
		goto out;
	}

	if (pv->flags & DEVICE_UNCLAIMED)
		return STATE_UNCLAIMED;
	// check if any platform has exited and we need to tear down
	if (pv_platforms_check_exited(pv, ROOT)) {
		pv_log(WARN, "one or more platforms exited, tearing down");
		next_state = pending_commit ? STATE_ROLLBACK : STATE_REBOOT;
		goto out;
	}
	next_state = pv_helper_process(pv);
out:
	pv_log(DEBUG, "going to state = %s", pv_state_string(next_state));
	return next_state;
}

static pv_state_t _pv_command(struct pantavisor *pv)
{
	int rev;
	char buf[4096] = { 0 };
	struct pv_cmd_req *c = pv->req;
	struct pv_state *new;
	pv_state_t next_state = STATE_WAIT;

	if (!c)
		return STATE_WAIT;

	switch (c->cmd) {
	case CMD_TRY_ONCE:
		{
		memcpy(buf, c->data, c->len);
		rev = atoi(buf);

		// lets not tryonce factory
		if (rev == 0)
			goto out;

		// load try state
		new = pv_get_state(pv, rev);
		if (!new) {
			pv_log(DEBUG, "invalid rev requested %d", rev);
			next_state = STATE_WAIT;
			goto out;
		}

		// stop current step
		if (pv_platforms_stop(pv, ROOT) < 0) {
			next_state = STATE_ROLLBACK;
			goto out;
		}
		if (pv_volumes_unmount(pv, ROOT) < 0) {
			next_state = STATE_ROLLBACK;
			goto out;
		}
 
		pv->state = new;
		pv_meta_link_boot(pv, NULL);
		pv_meta_set_tryonce(pv, 1);
		next_state = STATE_RUN;
		}
		break;
	case CMD_LOG:
		break;
	case CMD_JSON:
		switch (c->json_operation) {
		case CMD_JSON_UPDATE_METADATA:
			pv_ph_upload_metadata(pv, c->data);
			break;
		default:
			pv_log(DEBUG, "unknown json command received");
		}
		break;
	default:
		pv_log(DEBUG, "unknown command received");
	}

out:
	pv_cmd_finish(pv);
	return next_state;
}

/*
 * This is going to be part of CMD_UPDATE_DOWNLOAD
 * this command will trigger the platforms to be stopped
 * and device to be rebooted.
 *
 * The return statement would become a message to pv process.
 */
static pv_state_t pv_do_post_download_update(struct pantavisor *pv, int rev)
{
	pv_state_t next_state = STATE_RUN;

	pv->online = false;
	// stop current step
	if (pv_platforms_stop(pv, ROOT) < 0 || 
			pv_volumes_unmount(pv, ROOT) < 0) {
		next_state = STATE_ROLLBACK;
		goto out;
	}

	// Release current step
	pv_release_state(pv);

	// For now, trigger a reboot for all updates
	if (pv->update->runlevel >= NONE) {
		pv_log(WARN, "Update requires reboot, rebooting...");
		next_state = STATE_REBOOT;
		goto out;
	}

	pv_log(WARN, "State update applied, starting new revision %d", rev);

	// Load installed step
	pv->state = pv_get_state(pv, rev);

	if (pv->state == NULL) {
		pv_log(WARN, "unable to load new step state, rolling back");
		next_state = STATE_ROLLBACK;
	}
out:
	return next_state;
}

static pv_state_t _pv_update(struct pantavisor *pv)
{
	int ret = -1;
	pv_state_t next_state = STATE_WAIT;

	// queue locally and in cloud, block step
	// FIXME: requires pv_update_finish() call after RUN or boot
	ret = pv_update_start(pv, 0);
	if (ret < 0) {
		pv_log(INFO, "unable to queue update, abandoning it");
		goto out;
	} else if (ret > 0) {
		int time_left = pv->update->retry_at - time(NULL);

		pv_log(INFO, "Retrying in %d seconds", (time_left > 0 ? time_left : 0));
		goto out;
	}
	// download and install pending step
	ret = pv_update_install(pv);
	if (ret < 0) {
		pv_log(ERROR, "update has failed, continue");
		pv_update_finish(pv);
		goto out;
	}
	next_state = pv_do_post_download_update(pv, ret);
out:
	return next_state;
}

static pv_state_t _pv_rollback(struct pantavisor *pv)
{
	int ret = 0;
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	// We shouldnt get a rollback event on rev 0
	if (pv->state && pv->state->rev == 0)
		return STATE_ERROR;

	/*
	 * [PKS]
	 * rollback will only do rollback without posting
	 * any update status. When an update fails, the updater
	 * process will itself post the status message that update
	 * failed.
	 */
	// If we rollback, it means the considered OK update (kernel)
	// actually failed to start platforms or mount volumes
	if (pv->update)
		pv_update_set_status(pv, UPDATE_FAILED);

	if (pv->state) {
		ret = pv_platforms_stop(pv, ROOT);
		if (ret < 0)
			return STATE_ERROR;

		ret = pv_volumes_unmount(pv, ROOT);
		if (ret < 0)
			pv_log(WARN, "unmount error: ignoring due to rollback");

		rb_count = 0;
	}

	__pv_set_current(pv, pv_get_rollback_rev(pv), false);

	return STATE_REBOOT;
}

static pv_state_t _pv_reboot(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	if (!pv->update)
		goto out;

	/*
	 * [PKS]
	 * This will move to updater process.
	 * Reboot will only sync + reboot.
	 */
	pv_update_finish(pv);

out:
	pv_wdt_start(pv);

	// unmount storage
	umount(pv->config->storage.mntpoint);
	sync();

	pv_log(INFO, "rebooting...");
	sleep(5);
	reboot(LINUX_REBOOT_CMD_RESTART);

	return STATE_EXIT;
}

static pv_state_t _pv_error(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);
	
	return STATE_REBOOT;
}

pv_state_func_t* const state_table[MAX_STATES] = {
	_pv_init,
	_pv_run,
	_pv_wait,
	_pv_command,
	_pv_unclaimed,
	_pv_update,
	_pv_rollback,
	_pv_reboot,
	_pv_error,
	NULL,
	_pv_factory_upload,
};

static pv_state_t _pv_run_state(pv_state_t state, struct pantavisor *pv)
{
	pv_wdt_kick(pv);

	return state_table[state](pv);
}

int pv_controller_start(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	pv_state_t state = STATE_INIT;

	while (1) {
		if ((state != STATE_WAIT) && (state != STATE_COMMAND))
			pv_log(DEBUG, "going to state = %s(%d)", pv_state_string(state), state);
		state = _pv_run_state(state, pv);

		if (state == STATE_EXIT)
			return 1;
	}
}
