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
#include "state.h"
#include "revision.h"
#include "updater.h"

#define MODULE_NAME		"controller"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "storage.h"
#include "tsh.h"
#include "ph_logger/ph_logger.h"

#define CMDLINE_OFFSET	7

static int rollback_time;
static time_t wait_delay;
static time_t commit_delay;

extern pid_t shell_pid;

typedef enum {
	STATE_INIT,
	STATE_RUN,
	STATE_WAIT,
	STATE_COMMAND,
	STATE_UNCLAIMED,
	STATE_UPDATE,
	STATE_ROLLBACK,
	STATE_REBOOT,
	STATE_POWEROFF,
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
	case STATE_POWEROFF: return "STATE_POWEROFF";
	case STATE_ERROR: return "STATE_ERROR";
	case STATE_EXIT: return "STATE_EXIT";
	case STATE_FACTORY_UPLOAD: return "STATE_FACTORY_UPLOAD";
	default: return "STATE_UNKNOWN";
	}

	return "UNKNOWN PV STATE";
}

typedef pv_state_t pv_state_func_t(struct pantavisor *pv);

static bool pv_wait_delay_timedout(int seconds)
{
	struct timespec tp;

	// first, we wait until wait_delay
	clock_gettime(CLOCK_MONOTONIC, &tp);
	if (wait_delay > tp.tv_sec)
		return false;

	// then, we set wait_delay for next call
	wait_delay = tp.tv_sec + seconds;

	return true;
}

static pv_state_t _pv_factory_upload(struct pantavisor *pv)
{
	int ret = -1;

	ret = pv_device_factory_meta(pv);
	if (ret)
		return STATE_FACTORY_UPLOAD;
	return STATE_WAIT;
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
	struct timespec tp;
	int runlevel = RUNLEVEL_ROOT;

	// resume update if we have booted to test a new revision
	runlevel = pv_update_resume(pv);
	if (runlevel < RUNLEVEL_ROOT) {
		pv_log(ERROR, "update could not be resumed");
		return STATE_ROLLBACK;
	}

	if (pv_update_is_transitioning(pv->update)) {
		// for non-reboot updates...
		pv_log(INFO, "transitioning...");
		ph_logger_stop(pv);
		pv_log_start(pv, pv->update->pending->rev);
		pv_state_transfer(pv->update->pending, pv->state, runlevel);
	} else
		// after a reboot...
		pv->state = pv_get_state(pv, pv_revision_get_rev());
	if (!pv->state)
	{
		pv_log(ERROR, "state could not be loaded");
		return STATE_ROLLBACK;
	}

	// only start local ph logger, cloud services will be started when connected
	ph_logger_start(pv, pv->state->rev);

	// meta data initialization, also to be uploaded as soon as possible when connected
	pv_meta_set_objdir(pv);
	pv_device_parse_devmeta(pv);

	pv_log(DEBUG, "running pantavisor with runlevel %d", runlevel);

	// start up volumes and platforms
	if (pv_volumes_mount(pv, runlevel) < 0) {
		pv_log(ERROR, "error mounting volumes");
		return STATE_ROLLBACK;
	}

	if (pv_make_config(pv) < 0) {
		pv_log(ERROR, "error making config");
		return STATE_ROLLBACK;
	}

	if (pv_platforms_start(pv, runlevel) < 0) {
		pv_log(ERROR, "error starting platforms");
		return STATE_ROLLBACK;
	}

	// set active only after plats have been started
	pv_set_active(pv);

	// set initial wait delay and rollback count values
	clock_gettime(CLOCK_MONOTONIC, &tp);
	wait_delay = 0;
	commit_delay = 0;
	rollback_time = tp.tv_sec + pv->config->updater.network_timeout;

	return STATE_WAIT;
}

static pv_state_t _pv_unclaimed(struct pantavisor *pv)
{
	int need_register = 1;
	struct stat st;
	char config_path[256];
	char *c;

	c = calloc(1, sizeof(char) * 128);

	sprintf(config_path, "%s/config/unclaimed.config", pv->config->storage.mntpoint);
	if (stat(config_path, &st) == 0)
		ph_config_from_file(config_path, pv->config);

	if ((strcmp(pv->config->creds.id, "") != 0) && pv_ph_device_exists(pv))
		need_register = 0;

	if (need_register) {
		if (!pv_ph_register_self(pv)) {
			pv_ph_release_client(pv);
			if (c)
				free(c);
			return STATE_WAIT;
		}
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
	pv_device_upload_devmeta(pv);
	pv_network_update_meta(pv);
	pv_ph_device_get_meta(pv);
	return 0;
}

static pv_state_t pv_wait_network(struct pantavisor *pv)
{
	struct timespec tp;

	// check if we are online and authenticated
	if (!pv_ph_is_auth(pv) ||
		!pv_trail_is_auth(pv)) {
		// this could mean the trying update cannot connect to ph
		if (pv_update_is_trying(pv->update)) {
			clock_gettime(CLOCK_MONOTONIC, &tp);
			if (rollback_time <= tp.tv_sec)
				return STATE_ROLLBACK;
			pv_log(WARN, "no connection. Will rollback in %d seconds", rollback_time - tp.tv_sec);
		// or we directly rollback is connection is not stable during testing
		} else if (pv_update_is_testing(pv->update)) {
			return STATE_ROLLBACK;
		}
		// if there is no connection and no rollback yet, we avoid the rest of network operations
		return STATE_WAIT;
	}

	// start or stop ph logger depending on network and metadata configuration
	ph_logger_toggle(pv, pv->state->rev);

	// update meta info
	if (!pv_device_factory_meta_done(pv)) {
		return STATE_FACTORY_UPLOAD;
	}
	pv_meta_update_to_ph(pv);

	// check for new updates
	if (pv_check_for_updates(pv) > 0)
		return STATE_UPDATE;

	// if an update is going on at this point, it means we still have to finish it
	if (pv->update) {
		if (pv_update_is_trying(pv->update)) {
			// set initial testing time
			clock_gettime(CLOCK_MONOTONIC, &tp);
			commit_delay = tp.tv_sec + pv->config->update_commit_delay;
			// progress update state to testing
			pv_update_test(pv);
		}
		// if the update is being tested, we might have to wait
		if (pv_update_is_testing(pv->update)) {
			// progress if possible the state of testing update
			clock_gettime(CLOCK_MONOTONIC, &tp);
			if (commit_delay > tp.tv_sec) {
				pv_log(INFO, "committing new update in %d seconds", commit_delay - tp.tv_sec);
				return STATE_WAIT;
			}
		}
		if (pv_update_finish(pv) < 0)
			return STATE_ROLLBACK;
	}

	return STATE_WAIT;
}

static pv_state_t _pv_wait(struct pantavisor *pv)
{
	pv_state_t next_state = STATE_WAIT;

	// check if any platform has exited and we need to tear down
	if (pv_platforms_check_exited(pv, 0)) {
		pv_log(WARN, "one or more platforms exited, tearing down");
		if (pv_update_is_trying(pv->update) || pv_update_is_testing(pv->update))
			next_state = STATE_ROLLBACK;
		else
			next_state = STATE_REBOOT;
		goto out;
	}

	// with this wait, we make sure we have not consecutively executed network stuff
	// twice in less than the configured interval
	if (pv_wait_delay_timedout(pv->config->updater.interval)) {
		// check if device is unclaimed
		if (pv->flags & DEVICE_UNCLAIMED) {
			next_state = STATE_UNCLAIMED;
			goto out;
		}

		// rest of network wait stuff: connectivity check. update management,
		// meta data uppload, ph logger push start...
		next_state = pv_wait_network(pv);
		if (next_state != STATE_WAIT)
			goto out;
	}

	// free up previous command
	if (pv->req)
		pv_cmd_req_remove(pv);
	// receive new command. Set 2 secs as the select max blocking time, so we can do the
	// rest of WAIT operations
	pv->req = pv_cmd_socket_wait(pv, 2);
	if (pv->req) {
		next_state = STATE_COMMAND;
		goto out;
	}

out:
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
			goto out;
		}

		// stop current step
		if (pv_platforms_stop(pv, 0) < 0) {
			next_state = STATE_ROLLBACK;
			goto out;
		}
		if (pv_volumes_unmount(pv, 0) < 0) {
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
		case CMD_JSON_REBOOT_DEVICE:
			if (pv->update) {
				pv_log(WARN, "ignoring reboot command because an update is in progress");
				goto out;
			}

			pv_log(DEBUG, "reboot command with message '%s' received. Rebooting...",
				c->data);
			next_state = STATE_REBOOT;
			break;
		case CMD_JSON_POWEROFF_DEVICE:
			if (pv->update) {
				pv_log(WARN, "ignoring poweroff command because an update is in progress");
				goto out;
			}

			pv_log(DEBUG, "poweroff command with messaeg '%s' received. Powering off...",
				c->data);
			next_state = STATE_POWEROFF;
			break;
		default:
			pv_log(DEBUG, "unknown json command received");
		}
		break;
	default:
		pv_log(DEBUG, "unknown command received");
	}
out:
	pv_cmd_req_remove(pv);
	return next_state;
}

static pv_state_t _pv_update(struct pantavisor *pv)
{
	int rev = -1;

	// download and install pending step
	rev = pv_update_install(pv);
	if (rev < 0) {
		pv_log(ERROR, "update has failed, continue...");
		pv_update_finish(pv);
		return STATE_WAIT;
	}

	// if everything went well, decide whether update requires reboot or not
	if (pv_update_requires_reboot(pv))
		return STATE_REBOOT;

	pv_log(INFO, "stopping pantavisor runlevel %d and above...", pv->update->runlevel);
	if (pv_platforms_stop(pv, pv->update->runlevel) < 0 ||
			pv_volumes_unmount(pv, pv->update->runlevel) < 0) {
		pv_log(ERROR, "could not stop platforms or unmount volumes, rolling back...");
		return STATE_ROLLBACK;
	}

	return STATE_RUN;
}

static pv_state_t _pv_rollback(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	// We shouldnt get a rollback event on rev 0
	if (pv->state && pv->state->rev == 0)
		return STATE_ERROR;

	// rollback means current update needs to be reported to PH as FAILED
	if (pv->update)
		pv_update_set_status(pv, UPDATE_FAILED);

	pv_revision_set_rolledback();

	return STATE_REBOOT;
}

static void wait_shell()
{
#ifdef PANTAVISOR_DEBUG
	if (shell_pid) {
		pv_log(WARN, "waiting for debug shell with pid %d to exit", shell_pid);
		waitpid(shell_pid, NULL, 0);
	}
#endif
}

static pv_state_t _pv_reboot(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	wait_shell();

	if (pv->state) {
		pv_log(INFO, "stopping pantavisor runlevel 0 and above...");
		if (pv_platforms_stop(pv, 0) < 0)
			pv_log(WARN, "stop error: ignoring due to reboot");

		if (pv_volumes_unmount(pv, 0) < 0)
			pv_log(WARN, "unmount error: ignoring due to reboot");
	}

	pv_wdt_start(pv);

	// unmount storage
	umount(pv->config->storage.mntpoint);
	sync();

	sleep(5);
	pv_log(INFO, "rebooting...");
	ph_logger_stop(pv);
	reboot(LINUX_REBOOT_CMD_RESTART);

	return STATE_EXIT;
}

static pv_state_t _pv_poweroff(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	wait_shell();

	if (pv->state) {
		pv_log(INFO, "stopping pantavisor runlevel 0 and above...");
		if (pv_platforms_stop(pv, 0) < 0)
			pv_log(WARN, "stop error: ignoring due to poweroff");

		if (pv_volumes_unmount(pv, 0) < 0)
			pv_log(WARN, "unmount error: ignoring due to poweroff");
	}

	// unmount storage
	umount(pv->config->storage.mntpoint);
	sync();

	sleep(5);
	pv_log(INFO, "powering off...");
	ph_logger_stop(pv);
	reboot(LINUX_REBOOT_CMD_POWER_OFF);

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
	_pv_poweroff,
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
		pv_log(DEBUG, "going to state = %s", pv_state_string(state));
		state = _pv_run_state(state, pv);

		if (state == STATE_EXIT)
			return 1;
	}
}
