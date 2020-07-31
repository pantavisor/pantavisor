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

#define MODULE_NAME		"controller"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "storage.h"
#include "tsh.h"
#include "ph_logger/ph_logger.h"

#define CMDLINE_OFFSET	7

static int rb_count;
static int current;
static time_t wait_delay;

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
	int fd, ret, bytes;
	int pv_rev = 0, pv_try = 0, pv_boot = -1;
	int bl_rev = 0;
	char *buf;
	char *token;
	char pconfig_p[256];
	struct pantavisor_config *c;
	struct stat st;
	struct blkid_info dev_info;

	// Initialize flags
	pv->flags = 0;
	blkid_init(&dev_info);

	c = calloc(1, sizeof(struct pantavisor_config));
	pv->config = c;

        if (pv_config_from_file(PV_CONFIG_FILENAME, c) < 0) {
		printf("FATAL: unable to parse pantavisor config");
		return STATE_EXIT;
	}

	if (c->revision_retries <= 0)
		MAX_REVISION_RETRIES = DEFAULT_MAX_REVISION_RETRIES;
	else 
		MAX_REVISION_RETRIES = c->revision_retries;

	if (c->revision_retry_timeout <= 0)
		DOWNLOAD_RETRY_WAIT = DEFAULT_DOWNLOAD_RETRY_WAIT;
	else
		DOWNLOAD_RETRY_WAIT = c->revision_retry_timeout;

	// Create storage mountpoint and mount device
        mkdir_p(c->storage.mntpoint, 0755);
	
	/*
	 * Check that storage device has been enumerated and wait if not there yet
	 * (RPi2 for example is too slow to pvan the MMC devices in time)
	 */
	for (int wait = 5; wait > 0; wait--) {
		/*
		 * storage.path will contain UUID=XXXX or LABEL=XXXX
		 * */
		get_blkid(&dev_info, c->storage.path);
		if (dev_info.device && stat(dev_info.device, &st) == 0)
			break;
		printf("INFO: trail storage not yet available, waiting...");
		sleep(1);
		continue;
	}

	if (!dev_info.device)
		exit_error(errno, "Could not mount trails storage. No device found.");

	if (!c->storage.mnttype) {
		ret = mount(dev_info.device, c->storage.mntpoint, c->storage.fstype, 0, NULL);
	} else {
		int status;
		char *mntcmd = calloc(sizeof(char), strlen("/btools/pvmnt.%s %s") + strlen (c->storage.mnttype) + strlen (c->storage.mntpoint) + 1);
		sprintf(mntcmd, "/btools/pvmnt.%s %s", c->storage.mnttype, c->storage.mntpoint);
		printf("Mounting through helper: %s\n", mntcmd);
		ret = tsh_run(mntcmd, 1, &status);
		free(mntcmd);
	}
	if (ret < 0)
		exit_error(errno, "Could not mount trails storage");

	free_blkid_info(&dev_info); /*Keep if device_info is required later.*/

	sprintf(pconfig_p, "%s/config/pantahub.config", c->storage.mntpoint);
	if (ph_config_from_file(pconfig_p, c) < 0) {
		printf("FATAL: unable to parse pantahub config");
		return STATE_EXIT;
	}

	// Make pantavisor control area
	if (stat("/pv", &st) != 0)
		mkdir_p("/pv", 0500);

	if (stat(c->logdir, &st) != 0)
		mkdir_p(c->logdir, 0500);

	if (stat(c->metacachedir, &st) != 0)
		mkdir_p(c->metacachedir, 0500);

	if (stat(c->dropbearcachedir, &st) != 0)
		mkdir_p(c->dropbearcachedir, 0500);

	wait_delay = 0;
	// Get current step revision from cmdline
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -1;

	buf = calloc(1, sizeof(char) * (1024 + 1));
	bytes = read(fd, buf, sizeof(char)*1024);
	close(fd);

	token = strtok(buf, " ");
	while (token) {
		if (strncmp("pv_rev=", token, CMDLINE_OFFSET) == 0)
			pv_rev = atoi(token + CMDLINE_OFFSET);
		else if (strncmp("pv_try=", token, CMDLINE_OFFSET) == 0)
			pv_try = atoi(token + CMDLINE_OFFSET);
		else if (strncmp("pv_boot=", token, CMDLINE_OFFSET) == 0)
			pv_boot = atoi(token + CMDLINE_OFFSET + 1);
		token = strtok(NULL, " ");
	}
	free(buf);
	pv_log_init(pv, pv_rev);

	if (c->loglevel)
		pv_log_set_level(c->loglevel);

	pv_device_init(pv);

	pv_log(INFO, "______           _              _                ");
	pv_log(INFO, "| ___ \\         | |            (_)               ");
	pv_log(INFO, "| |_/ /_ _ _ __ | |_ __ ___   ___ ___  ___  _ __ ");
	pv_log(INFO, "|  __/ _` | '_ \\| __/ _` \\ \\ / / / __|/ _ \\| '__|");
	pv_log(INFO, "| | | (_| | | | | || (_| |\\ V /| \\__ \\ (_) | |   ");
	pv_log(INFO, "\\_|  \\__,_|_| |_|\\__\\__,_| \\_/ |_|___/\\___/|_|   ");
	pv_log(INFO, "                                                 ");
	pv_log(INFO, "Pantavisor (TM) (%s) - www.pantahub.com", pv_build_version);
	pv_log(INFO, "                                                 ");
	pv_log(DEBUG, "c->storage.path = '%s'", c->storage.path);
	pv_log(DEBUG, "c->storage.fstype = '%s'", c->storage.fstype);
	pv_log(DEBUG, "c->storage.opts = '%s'", c->storage.opts);
	pv_log(DEBUG, "c->storage.mntpoint = '%s'", c->storage.mntpoint);
	pv_log(DEBUG, "c->storage.mnttype = '%s'", c->storage.mnttype ? c->storage.mnttype : "");
	pv_log(DEBUG, "c->creds.host = '%s'", c->creds.host);
	pv_log(DEBUG, "c->creds.port = '%d'", c->creds.port);
	pv_log(DEBUG, "c->creds.id = '%s'", c->creds.id);
	pv_log(DEBUG, "c->creds.prn = '%s'", c->creds.prn);
	pv_log(DEBUG, "c->creds.secret = '%s'", c->creds.secret);

	// create hints
	fd = open("/pv/challenge", O_CREAT | O_SYNC | O_WRONLY, 0444);
	close(fd);
	fd = open("/pv/device-id", O_CREAT | O_SYNC | O_WRONLY, 0444);

	// init pv cmd control socket
	if (pv_cmd_socket_open(pv, "/pv/pv-ctrl") > 0)
		pv_log(DEBUG, "control socket initialized fd=%d", pv->ctrl_fd);

	char tmp[256];
	if (strcmp(c->creds.prn, "") == 0) {
		pv->flags |= DEVICE_UNCLAIMED;
	} else {
		sprintf(tmp, "%s\n", c->creds.id);
		write(fd, tmp, strlen(tmp));
	}

	close(fd);

	// init network helpers
	pv_network_init(pv);

	// expose pantahub host
	fd = open("/pv/pantahub-host", O_CREAT | O_SYNC | O_WRONLY, 0444);
	sprintf(tmp, "https://%s:%d\n", c->creds.host, c->creds.port);
	write(fd, tmp, strlen(tmp));
	close(fd);


	// init platform controllers
	if (!pv_platforms_init_ctrl(pv)) {
		pv_log(ERROR, "unable to load any container runtime plugin");
		return STATE_ERROR;
	}

	// init bootloader ops
	if (pv_bl_init(pv) < 0)
		return STATE_ERROR;



	// Make sure this is initialized
	pv->state = 0;
	pv->remote = 0;
	pv->update = 0;
	pv->last = -1;

	pv_log(DEBUG, "%s():%d pv_try=%d, pv_rev=%d", __func__, __LINE__, pv_try, pv_rev);

	if (ph_logger_service_start(pv, LOG_CTRL_PATH, pv_rev) <= 0) {
		pv_log(ERROR, "Unable to start logger service.");
	}

	if (ph_logger_service_start_for_range(pv, pv_rev) <= 0) {
		pv_log(ERROR, "Unable to start range logger service.");
	}

	// parse boot rev
	pv->state = pv_get_state(pv, pv_rev);

	// FIXME: maybe add some fallback configuration option
	if (!pv->state)
		return STATE_ERROR;

	// get try revision from bl
	bl_rev = pv_bl_get_try(pv);

	if (bl_rev <= 0)
		return STATE_RUN;

	if (bl_rev == pv_rev) {
		pv_update_start(pv, 1);
		pv_update_set_status(pv, UPDATE_TRY);
	} else {
		struct pv_state *s = pv->state;
		pv->state = pv_get_state(pv, bl_rev);
		if (pv->state) {
			pv_update_start(pv, 1);
			pv_update_set_status(pv, UPDATE_FAILED);
			pv_release_state(pv);
			pv->state = s;
		}
	}

	if (!pv->state) {
		pv_log(ERROR, "invalid state requested, please reconfigure");
		return STATE_ERROR;
	}

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

	if (pv_volumes_mount(pv) < 0)
		return STATE_ROLLBACK;

	pv_set_active(pv);

	ret = pv_make_config(pv);
	if (ret < 0) {
		pv_log(ERROR, "error making config");
		return STATE_ROLLBACK;
	}

	ret = pv_platforms_start_all(pv);
	if (ret < 0) {
		pv_log(ERROR, "error starting platforms");
		return STATE_ROLLBACK;
	}

	pv_log(INFO, "started %d platforms", ret);

	rb_count = 0;

	// set initial wait delay
	clock_gettime(CLOCK_MONOTONIC, &tp);
	wait_delay = tp.tv_sec + pv->config->updater.interval;

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

static pv_state_t _pv_wait(struct pantavisor *pv)
{
	int ret;
	int timeout_max = pv->config->updater.network_timeout
		/ pv->config->updater.interval;

	struct timespec tp;
	static bool status_updated = false;
	static enum update_state current_status = UPDATE_DONE;

	if (pv->req) {
		pv_log(WARN, "stable command found queued, discarding");
		pv_cmd_finish(pv);
		return STATE_WAIT;
	}

	clock_gettime(CLOCK_MONOTONIC, &tp);
	if (wait_delay > tp.tv_sec) {
		pv->req = pv_cmd_socket_wait(pv, 5);
		if (pv->req)
			return STATE_COMMAND;
		else
			return STATE_WAIT;
	}

	if (pv->flags & DEVICE_UNCLAIMED)
		return STATE_UNCLAIMED;

	if (!pv_ph_is_available(pv)) {
		rb_count++;
		if (!pv_rev_is_done(pv, pv->state->rev) &&
			 (rb_count > timeout_max)) {
			return STATE_ROLLBACK;
		}
		clock_gettime(CLOCK_MONOTONIC, &tp);
		wait_delay = tp.tv_sec + pv->config->updater.interval;
		return STATE_WAIT;
	}
	
	if (!pv_device_factory_meta_done(pv))
		return STATE_FACTORY_UPLOAD;

	// update meta
	pv_device_info_upload(pv);
	pv_network_update_meta(pv);
	pv_ph_device_get_meta(pv);

	// reset rollback rb_count
	rb_count = 0;

	// check if any platform has exited and we need to tear down
	if (pv_platforms_check_exited(pv)) {
		pv_log(WARN, "one or more platforms exited, tearing down");
		return STATE_REBOOT;
	}

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
			pv_set_current(pv, pv->state->rev);
			pv_update_set_status(pv, UPDATE_DONE);
			if (!pv_update_finish(pv))
				status_updated = true;
			pv_bl_clear_update(pv);
		}
	} else if (pv->update && pv->update->status == UPDATE_FAILED) {
		// We come from a forced rollback
		pv_set_current(pv, pv->state->rev);
		pv_update_set_status(pv, UPDATE_FAILED);
		if (!pv_update_finish(pv))
			status_updated = true;
		current_status = UPDATE_FAILED;
	}

	// make sure we always keep a ref to the latest working DONE step
	if (current != pv->state->rev && !pv_meta_get_tryonce(pv)) {
		current = pv->state->rev;
		pv_set_current(pv, current);
		pv->last = pv->state->rev;
	}

	// check for updates
	ret = pv_check_for_updates(pv);

	/* set delay to at most the updater interval */
	clock_gettime(CLOCK_MONOTONIC, &tp);
	wait_delay = tp.tv_sec + pv->config->updater.interval;

	if (ret > 0) {
		pv_log(INFO, "updates found");
		return STATE_UPDATE;
	}

	if (!status_updated && !pv_set_current_status(pv, current_status))
		status_updated = true;
	pv_log(DEBUG, "going to state = %s", pv_state_string(STATE_WAIT));

	return STATE_WAIT;
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
		if (pv_platforms_stop_all(pv) < 0) {
			next_state = STATE_ROLLBACK;
			goto out;
		}
		if (pv_volumes_unmount(pv) < 0) {
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

static pv_state_t _pv_update(struct pantavisor *pv)
{
	int ret;

	// queue locally and in cloud, block step
	// FIXME: requires pv_update_finish() call after RUN or boot
	ret = pv_update_start(pv, 0);
	if (ret < 0) {
		pv_log(INFO, "unable to queue update, abandoning it");
		return STATE_WAIT;
	} else if (ret > 0) {
		int time_left = pv->update->retry_at - time(NULL);

		pv_log(INFO, "Retrying in %d seconds", (time_left > 0 ? time_left : 0));
		return STATE_WAIT;
	}

	// download and install pending step
	ret = pv_update_install(pv);

	if (ret < 0) {
		pv_log(ERROR, "update has failed, continue");
		pv_update_finish(pv);
		return STATE_WAIT;
	}

	pv_log(WARN, "New trail state accepted, stopping current state.");

	pv->online = false;

	// stop current step
	if (pv_platforms_stop_all(pv) < 0)
		return STATE_ROLLBACK;
	if (pv_volumes_unmount(pv) < 0)
		return STATE_ROLLBACK;

	// Release current step
	pv_release_state(pv);

	// For now, trigger a reboot for all updates
	if (pv->update->need_reboot) {
		pv_log(WARN, "Update requires reboot, rebooting...");
		return STATE_REBOOT;
	}

	pv_log(WARN, "State update applied, starting new revision.", ret);

	// Load installed step
	pv->state = pv_get_state(pv, ret);

	if (pv->state == NULL) {
		pv_log(WARN, "unable to load new step state, rolling back");
		return STATE_ROLLBACK;
	}

	return STATE_RUN;
}

static pv_state_t _pv_rollback(struct pantavisor *pv)
{
	int ret = 0;
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	// We shouldnt get a rollback event on rev 0
	if (pv->state && pv->state->rev == 0)
		return STATE_ERROR;

	// If we rollback, it means the considered OK update (kernel)
	// actually failed to start platforms or mount volumes
	if (pv->update)
		pv_update_set_status(pv, UPDATE_FAILED);

	if (pv->state) {
		ret = pv_platforms_stop_all(pv);
		if (ret < 0)
			return STATE_ERROR;

		ret = pv_volumes_unmount(pv);
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
	int count = 0;

	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	while (count < 2) {
		sleep(5);
		return STATE_ERROR;
	}

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
