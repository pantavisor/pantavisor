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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reboot.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include <linux/limits.h>
#include <linux/reboot.h>

#include "pantavisor.h"
#include "loop.h"
#include "platforms.h"
#include "volumes.h"
#include "pantahub.h"
#include "bootloader.h"
#include "ctrl.h"
#include "version.h"
#include "wdt.h"
#include "network.h"
#include "blkid.h"
#include "init.h"
#include "state.h"
#include "updater.h"
#include "storage.h"
#include "metadata.h"
#include "signature.h"
#include "paths.h"
#include "ph_logger.h"
#include "logserver.h"
#include "mount.h"
#include "parser/parser.h"
#include "utils/timer.h"
#include "utils/fs.h"
#include "utils/str.h"
#include "utils/tsh.h"

#define MODULE_NAME "controller"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define CMDLINE_OFFSET 7

char pv_user_agent[4096];

static struct pantavisor *global_pv;

struct pantavisor *pv_get_instance()
{
	return global_pv;
}

static struct timer timer_rollback_remote;
static struct timer timer_wait_delay;
static struct timer timer_usrmeta_interval;
static struct timer timer_devmeta_interval;
static struct timer timer_updater_interval;
static struct timer timer_commit;

static const int PV_WAIT_PERIOD = 1;

extern pid_t shell_pid;

typedef enum {
	PV_STATE_INIT,
	PV_STATE_RUN,
	PV_STATE_WAIT,
	PV_STATE_COMMAND,
	PV_STATE_UPDATE,
	PV_STATE_UPDATE_APPLY,
	PV_STATE_ROLLBACK,
	PV_STATE_REBOOT,
	PV_STATE_POWEROFF,
	PV_STATE_ERROR,
	PV_STATE_EXIT,
	PV_STATE_FACTORY_UPLOAD,
	MAX_STATES
} pv_state_t;

static const char *pv_state_string(pv_state_t st)
{
	switch (st) {
	case PV_STATE_INIT:
		return "STATE_INIT";
	case PV_STATE_RUN:
		return "STATE_RUN";
	case PV_STATE_WAIT:
		return "STATE_WAIT";
	case PV_STATE_COMMAND:
		return "STATE_COMMAND";
	case PV_STATE_UPDATE:
		return "STATE_UPDATE";
	case PV_STATE_UPDATE_APPLY:
		return "STATE_UPDATE_APPLY";
	case PV_STATE_ROLLBACK:
		return "STATE_ROLLBACK";
	case PV_STATE_REBOOT:
		return "STATE_REBOOT";
	case PV_STATE_POWEROFF:
		return "STATE_POWEROFF";
	case PV_STATE_ERROR:
		return "STATE_ERROR";
	case PV_STATE_EXIT:
		return "STATE_EXIT";
	case PV_STATE_FACTORY_UPLOAD:
		return "STATE_FACTORY_UPLOAD";
	default:
		return "STATE_UNKNOWN";
	}

	return "STATE_UNKNOWN";
}

typedef pv_state_t pv_state_func_t(struct pantavisor *pv);

typedef enum {
	PH_STATE_INIT,
	PH_STATE_REGISTER,
	PH_STATE_CLAIM,
	PH_STATE_SYNC,
	PH_STATE_IDLE,
	PH_STATE_UPDATE,
	PH_STATE_UPDATE_APPLY,
} ph_state_t;

static const char *ph_state_string(ph_state_t st)
{
	switch (st) {
	case PH_STATE_INIT:
		return "init";
	case PH_STATE_REGISTER:
		return "register";
	case PH_STATE_CLAIM:
		return "claim";
	case PH_STATE_SYNC:
		return "sync";
	case PH_STATE_IDLE:
		return "idle";
	case PH_STATE_UPDATE:
		return "update";
	case PH_STATE_UPDATE_APPLY:
		return "updateapply";
	default:
		return "STATE_UNKNOWN";
	}

	return "STATE_UNKNOWN";
}

static bool pv_wait_delay_timedout()
{
	struct timer_state tstate = timer_current_state(&timer_wait_delay);
	// first, we check if timed out
	if (!tstate.fin)
		return false;

	// then, we set 1 sec for next wait cycle
	timer_start(&timer_wait_delay, PV_WAIT_PERIOD, 0, RELATIV_TIMER);

	return true;
}

static pv_state_t _pv_factory_upload(struct pantavisor *pv)
{
	int ret = -1;

	ret = pv_metadata_factory_meta(pv);
	if (ret)
		return PV_STATE_FACTORY_UPLOAD;
	return PV_STATE_WAIT;
}

static pv_state_t _pv_init(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	if (pv_do_execute_init())
		return PV_STATE_EXIT;

	return PV_STATE_RUN;
}

static pv_state_t _pv_run(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);
	pv_state_t next_state = PV_STATE_ROLLBACK;
	char *json = NULL;

	// resume update if we have booted to test a new revision
	if (pv_update_resume(pv)) {
		pv_log(ERROR, "update could not be resumed");
		goto out;
	}

	if (pv_update_is_transitioning(pv->update)) {
		// for non-reboot updates...
		pv_log(INFO, "transitioning...");

		pv_logserver_reload();

		ph_logger_stop_lenient();
		ph_logger_stop_force();

		pv_state_transition(pv->update->pending, pv->state);
	} else {
		// after a reboot...
		json = pv_storage_get_state_json(pv_bootloader_get_rev());
		if (!pv_signature_verify(json)) {
			pv_log(ERROR,
			       "state signature verification went wrong");
			goto out;
		}
		pv->state = pv_parser_get_state(json, pv_bootloader_get_rev());
		if (!pv->state) {
			pv_log(ERROR, "state could not be loaded");
			goto out;
		}

		// if an update is going on, we are going to need the state to report progress, so no need to parse it
		if (pv->update) {
			pv->update->pending = pv_state_new(
				pv_bootloader_get_try(), SPEC_UNKNOWN);
		}
	}

	if (!pv->state) {
		pv_log(ERROR, "current state not loaded");
		goto out;
	}

	// set current log and trail links
	pv_storage_set_active(pv);

	if (!pv_state_validate_checksum(pv->state)) {
		pv_log(ERROR, "state objects validation went wrong");
		goto out;
	}

	// set factory revision progress
	if (!strncmp(pv->state->rev, "0", sizeof("0")))
		pv_storage_set_rev_progress(
			"0", DEVICE_STEP_FACTORY_PROGRESS_UNREGISTERED);

	// reload remote bool after non reboot updates, when we don't load config again
	pv->remote_mode = pv_config_get_control_remote();
	pv->loading_objects = false;
	pv->state->local = !pv_config_get_control_remote();

	// we know if we are in local if the running revision has the local format
	if (pv_storage_is_revision_local(pv->state->rev)) {
		pv_log(DEBUG, "running local revision %s", pv->state->rev);
		pv->state->local = true;
		pv->remote_mode = false;
	}

	if (!pv->remote_mode)
		pv_log(INFO,
		       "running in local mode. Will not consume new updates from Pantahub");

	// only start local ph logger, start cloud services if connected
	pv_logserver_toggle(pv, pv->state->rev);
	ph_logger_toggle(pv->state->rev);

	if (!pv_update_is_transitioning(pv->update)) {
		if (pv_state_start(pv->state)) {
			pv_log(ERROR, "error starting state");
			goto out;
		}

		if (pv_metadata_init()) {
			pv_log(ERROR, "metadata mount failed");
			goto out;
		}
	}

	// meta data initialization, also to be uploaded as soon as possible when connected
	pv_metadata_init_devmeta(pv);

	if (pv_storage_make_config(pv) < 0) {
		pv_log(ERROR, "error making config");
		goto out;
	}

	timer_start(&timer_commit, 0, 0, RELATIV_TIMER);
	timer_start(&timer_rollback_remote,
		    pv_config_get_updater_network_timeout(), 0, RELATIV_TIMER);
	pv_state_start_groups_timer(pv->state);
	timer_start(&timer_wait_delay, 0, 0, RELATIV_TIMER);
	timer_start(&timer_usrmeta_interval, 0, 0, RELATIV_TIMER);
	timer_start(&timer_devmeta_interval, 0, 0, RELATIV_TIMER);
	timer_start(&timer_updater_interval, 0, 0, RELATIV_TIMER);

	next_state = PV_STATE_WAIT;
out:
	if (json)
		free(json);

	return next_state;
}

static pv_state_t pv_wait_unclaimed(struct pantavisor *pv)
{
	int need_register = 1;
	char *c;
	char path[PATH_MAX];

	struct timer_state tstate =
		timer_current_state(&timer_updater_interval);
	if (!tstate.fin)
		return PV_STATE_WAIT;

	timer_start(&timer_updater_interval, pv_config_get_updater_interval(),
		    0, RELATIV_TIMER);

	c = calloc(128, sizeof(char));

	pv_config_load_creds();

	if (pv_config_get_creds_id() && strcmp(pv_config_get_creds_id(), "") &&
	    pv_ph_device_exists(pv))
		need_register = 0;

	if (need_register) {
		pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE,
					ph_state_string(PH_STATE_REGISTER));
		if (!pv_ph_register_self(pv)) {
			pv_ph_release_client(pv);
			if (c)
				free(c);
			return PV_STATE_WAIT;
		}
		pv_config_save_creds();
		pv_ph_release_client(pv);
	}

	if (!pv_ph_device_is_owned(pv, &c)) {
		pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE,
					ph_state_string(PH_STATE_CLAIM));
		pv_storage_set_rev_progress(
			"0", DEVICE_STEP_FACTORY_PROGRESS_UNCLAIMED);
		pv_log(INFO, "device challenge: '%s'", c);
		pv_ph_update_hint_file(pv, c);
	} else {
		pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE,
					ph_state_string(PH_STATE_SYNC));
		pv_storage_set_rev_progress(
			"0", DEVICE_STEP_FACTORY_PROGRESS_SYNCING);
		pv_log(INFO, "device has been claimed, proceeding normally");
		printf("INFO: pantavisor device has been claimed, proceeding normally\n");
		pv->unclaimed = false;
		pv_config_save_creds();
		pv_ph_release_client(pv);
		pv_paths_pv_file(path, PATH_MAX, CHALLENGE_FNAME);
		if (pv_fs_file_save(path, "", 0444) < 0)
			pv_log(WARN, "could not save file %s: %s", path,
			       strerror(errno));
		pv_metadata_add_devmeta("pantahub.claimed", "1");
	}

	pv_ph_update_hint_file(pv, NULL);

	if (c)
		free(c);

	return PV_STATE_FACTORY_UPLOAD;
}

static int pv_meta_update_to_ph(struct pantavisor *pv)
{
	struct timer_state tstate;

	if (!pv)
		return -1;

	tstate = timer_current_state(&timer_usrmeta_interval);
	if (tstate.fin) {
		if (pv_ph_device_get_meta(pv))
			return -1;
		timer_start(&timer_usrmeta_interval,
			    pv_config_get_metadata_usrmeta_interval(), 0,
			    RELATIV_TIMER);
	}

	tstate = timer_current_state(&timer_devmeta_interval);
	if (tstate.fin) {
		if (pv_metadata_upload_devmeta(pv))
			return -1;
		timer_start(&timer_devmeta_interval,
			    pv_config_get_metadata_devmeta_interval(), 0,
			    RELATIV_TIMER);
	}

	return 0;
}

static pv_state_t pv_wait_update()
{
	struct pantavisor *pv = pv_get_instance();

	// if an update is going on at this point, it means we still have to finish it
	if (pv->update && pv->update->status != UPDATE_APPLIED) {
		if (pv_update_is_trying(pv->update)) {
			groups_goals_state_t status_goal =
				pv_state_check_goals(pv->state, NULL);

			switch (status_goal) {
			case STATUS_GOAL_FAILED:
				pv_log(ERROR,
				       "timed out before all goals are met. Rolling back...");
				return PV_STATE_ROLLBACK;
			case STATUS_GOAL_WAITING:
				return PV_STATE_WAIT;
			case STATUS_GOAL_UNKNOWN:
				pv_log(ERROR,
				       "could not check groups goals. Rolling back...");
				return PV_STATE_ROLLBACK;
			case STATUS_GOAL_REACHED:
				timer_start(
					&timer_commit,
					pv_config_get_updater_commit_delay(), 0,
					RELATIV_TIMER);
				// progress update state to testing
				pv_update_test(pv);
			}
		}
		// if the update is being tested, we might have to wait
		if (pv_update_is_testing(pv->update)) {
			// progress if possible the state of testing update
			struct timer_state tstate =
				timer_current_state(&timer_commit);
			if (!tstate.fin) {
				pv_log(INFO,
				       "committing new update in %d seconds",
				       tstate.sec);
				return PV_STATE_WAIT;
			}
		}
		if (pv_update_finish(pv) < 0) {
			pv_log(ERROR,
			       "update could not be finished. Rolling back...");
			return PV_STATE_ROLLBACK;
		}
	}

	return PV_STATE_WAIT;
}

static pv_state_t pv_wait_network(struct pantavisor *pv)
{
	struct timer_state tstate;

	// check if we are online and authenticated
	if (!pv_ph_is_auth(pv) || !pv_trail_is_auth(pv)) {
		// this could mean the trying update cannot connect to ph
		if (pv_update_is_trying(pv->update)) {
			tstate = timer_current_state(&timer_rollback_remote);
			if (tstate.fin) {
				pv_log(ERROR,
				       "timed out before getting any response from cloud. Rolling back...");
				return PV_STATE_ROLLBACK;
			}
			pv_log(WARN,
			       "no connection. Will rollback in %d seconds",
			       tstate.sec);
			// or we directly rollback is connection is not stable during testing
		} else if (pv_update_is_testing(pv->update)) {
			pv_log(ERROR,
			       "connection with cloud not stable during testing, Rolling back...");
			return PV_STATE_ROLLBACK;
		}
		// if there is no connection and no rollback yet, we avoid the rest of network operations
		return PV_STATE_WAIT;
	}

	// start or stop ph logger depending on network and configuration
	ph_logger_toggle(pv->state->rev);

	// update meta info
	if (!pv_metadata_factory_meta_done(pv)) {
		return PV_STATE_FACTORY_UPLOAD;
	}
	if (pv_meta_update_to_ph(pv))
		goto out;

	// check for new remote update
	tstate = timer_current_state(&timer_updater_interval);
	if (tstate.fin) {
		if (pv_updater_check_for_updates(pv) > 0) {
			pv_metadata_add_devmeta(
				DEVMETA_KEY_PH_STATE,
				ph_state_string(PH_STATE_UPDATE));
			return PV_STATE_UPDATE;
		}
		timer_start(&timer_updater_interval,
			    pv_config_get_updater_interval(), 0, RELATIV_TIMER);
	}

	if (pv->synced) {
		pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE,
					ph_state_string(PH_STATE_IDLE));
		if (!strncmp(pv->state->rev, "0", sizeof("0")))
			pv_storage_set_rev_progress(
				"0", DEVICE_STEP_FACTORY_PROGRESS_DONE);
	}

out:
	// process ongoing updates, if any
	return pv_wait_update();
}

static pv_state_t _pv_wait(struct pantavisor *pv)
{
	struct timer t;
	struct timer_state tstate;
	pv_state_t next_state = PV_STATE_WAIT;

	// check if any platform has exited and we need to tear down
	if (pv_state_run(pv->state)) {
		pv_log(ERROR,
		       "a platform did not work as expected. Tearing down...");
		if (pv_update_is_trying(pv->update) ||
		    pv_update_is_testing(pv->update))
			next_state = PV_STATE_ROLLBACK;
		else
			next_state = PV_STATE_REBOOT;
		goto out;
	}

	// we only get into network operations if remote mode is set to 1 in config (can be unset if revision is "locals/...")
	// also, in case device is unclaimed, the current update must finish first (this is specially done for rev 0 that comes from command make-factory)
	if (pv->remote_mode &&
	    (!pv->unclaimed ||
	     (pv->unclaimed &&
	      !(pv->update && pv->update->status != UPDATE_APPLIED)))) {
		timer_start(&t, 5, 0, RELATIV_TIMER);
		// with this wait, we make sure we have not consecutively executed network stuff
		// twice in less than the configured interval
		if (pv_wait_delay_timedout()) {
			// check if device is unclaimed
			if (pv->unclaimed) {
				// unclaimed wait operations
				next_state = pv_wait_unclaimed(pv);
			} else {
				// rest of network wait stuff: connectivity check. update management,
				// meta data uppload, ph logger push start...
				next_state = pv_wait_network(pv);
			}
		}
		tstate = timer_current_state(&t);
		if (tstate.fin)
			pv_log(DEBUG,
			       "network operations are taking %d seconds!",
			       5 + tstate.sec);
	} else {
		// process ongoing updates, if any
		next_state = pv_wait_update();
	}

	if (next_state != PV_STATE_WAIT)
		goto out;

	// update network info in devmeta
	pv_network_update_meta(pv);

	// check if we need to run garbage collector
	pv_storage_gc_run_threshold();

	// receive new command. Set 2 secs as the select max blocking time, so we can do the
	// rest of WAIT operations
	pv->cmd = pv_ctrl_socket_wait(pv->ctrl_fd, 2);
	if (pv->cmd)
		next_state = PV_STATE_COMMAND;

out:
	return next_state;
}

static pv_state_t _pv_command(struct pantavisor *pv)
{
	struct pv_cmd *cmd = pv->cmd;
	pv_state_t next_state = PV_STATE_WAIT;
	char *rev;

	if (!cmd)
		return PV_STATE_WAIT;

	switch (cmd->op) {
	case CMD_UPDATE_METADATA:
		if (pv->remote_mode) {
			pv_log(DEBUG,
			       "metadata command with payload '%s' received. Parsing metadata...",
			       cmd->payload);
			pv_metadata_parse_devmeta(cmd->payload);
		}
		break;
	case CMD_REBOOT_DEVICE:
		if (pv->update && pv->update->status != UPDATE_APPLIED) {
			pv_log(WARN,
			       "ignoring reboot command because an update is in progress");
			goto out;
		} else if (pv->update && pv->update->status == UPDATE_APPLIED) {
			pv_log(INFO,
			       "aborting current applied update to allow new reboot request to proceed");
			pv_update_finish(pv);
		}

		pv_log(DEBUG,
		       "reboot command with message '%s' received. Rebooting...",
		       cmd->payload);
		next_state = PV_STATE_REBOOT;
		break;
	case CMD_POWEROFF_DEVICE:
		if (pv->update) {
			pv_log(WARN,
			       "ignoring poweroff command because an update is in progress");
			goto out;
		}

		pv_log(DEBUG,
		       "poweroff command with message '%s' received. Powering off...",
		       cmd->payload);
		next_state = PV_STATE_POWEROFF;
		break;
	case CMD_LOCAL_RUN:
		if (pv->update && pv->update->status != UPDATE_APPLIED) {
			pv_log(WARN,
			       "ignoring install local command because an update is in progress");
			goto out;
		} else if (pv->update && pv->update->status == UPDATE_APPLIED) {
			pv_log(INFO,
			       "aborting current applied update to allow new update request to proceed");
			pv_update_finish(pv);
		}

		pv_log(DEBUG, "install local received. Processing %s json...",
		       cmd->payload);
		pv->update = pv_update_get_step_local(cmd->payload);
		if (pv->update)
			next_state = PV_STATE_UPDATE;
		break;
	case CMD_LOCAL_APPLY:
		if (pv->update && pv->update->status != UPDATE_APPLIED) {
			pv_log(WARN,
			       "ignoring applying local command because an update is in progress");
			goto out;
		} else if (pv->update && pv->update->status == UPDATE_APPLIED) {
			pv_log(INFO,
			       "aborting current applied update to allow new apply request to proceed");
			pv_update_finish(pv);
		}

		pv_log(DEBUG, "apply local received. Processing %s json...",
		       cmd->payload);
		pv->update = pv_update_get_step_local(cmd->payload);
		if (pv->update)
			next_state = PV_STATE_UPDATE_APPLY;
		break;
	case CMD_MAKE_FACTORY:

		if (!pv->unclaimed) {
			pv_log(WARN,
			       "ignoring make factory command because device is already claimed");
			goto out;
		}

		if (pv->update && pv->update->status != UPDATE_APPLIED) {
			pv_log(WARN,
			       "ignoring make factory command because an update is in progress");
			goto out;
		} else if (pv->update && pv->update->status == UPDATE_APPLIED) {
			pv_log(INFO,
			       "aborting current applied update to allow new make factory request to proceed");
			pv_update_finish(pv);
		}

		if (strlen(cmd->payload) > 0)
			rev = cmd->payload;
		else
			rev = pv->state->rev;

		pv_log(DEBUG,
		       "make factory received. Transferring revision %s to remote revision 0",
		       rev);
		if (pv_storage_update_factory(rev) < 0) {
			pv_log(ERROR, "cannot update factory revision");
			goto out;
		}

		pv_log(INFO, "revision 0 updated. Progressing to revision 0");
		pv->update = pv_update_get_step_local("0");
		if (pv->update)
			next_state = PV_STATE_UPDATE;
		break;
	case CMD_RUN_GC:
		pv_log(DEBUG, "run garbage collector received. Running...");
		pv_storage_gc_run();
		break;
	default:
		pv_log(WARN, "unknown command received. Ignoring...");
	}
out:
	pv_ctrl_free_cmd(pv->cmd);
	pv->cmd = NULL;
	return next_state;
}

static pv_state_t _pv_update_apply(struct pantavisor *pv)
{
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE,
				ph_state_string(PH_STATE_UPDATE_APPLY));

	// download and install pending step
	if (pv_update_download(pv) || pv_update_install(pv)) {
		pv_log(ERROR, "update has failed, continue...");
		pv_update_finish(pv);
		return PV_STATE_WAIT;
	}
	pv_update_set_status(pv, UPDATE_APPLIED);
	return PV_STATE_WAIT;
}

static pv_state_t _pv_update(struct pantavisor *pv)
{
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE,
				ph_state_string(PH_STATE_UPDATE));

	// download and install pending step
	if (pv_update_download(pv) || pv_update_install(pv)) {
		pv_log(ERROR, "update has failed, continue...");
		pv_update_finish(pv);
		return PV_STATE_WAIT;
	}

	// after installing, try to only stop the platforms that we need for the new update
	if (pv_state_stop_platforms(pv->state, pv->update->pending)) {
		pv_log(INFO, "update requires reboot");
		pv_update_set_status(pv, UPDATE_REBOOT);
		return PV_STATE_REBOOT;
	}

	pv_log(INFO, "update does not require reboot");
	pv_update_set_status(pv, UPDATE_TRANSITION);
	return PV_STATE_RUN;
}

static pv_state_t _pv_rollback(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

	// We shouldnt get a rollback event on rev 0
	if (pv->state && !strncmp(pv->state->rev, "0", sizeof("0"))) {
		pv_log(ERROR, "bad factory revision");
		return PV_STATE_ERROR;
	}

	// rollback means current update needs to be reported to PH as FAILED
	if (pv->update) {
		pv_update_set_status(pv, UPDATE_FAILED);
		pv_update_finish(pv);
	}

	return PV_STATE_REBOOT;
}

static void wait_shell()
{
#ifdef PANTAVISOR_DEBUG
	if (shell_pid) {
		pv_log(WARN, "waiting for debug shell with pid %d to exit",
		       shell_pid);
		waitpid(shell_pid, NULL, 0);
	}
#endif
}

typedef enum { POWEROFF, REBOOT } shutdown_type_t;

static char *shutdown_type_string(shutdown_type_t t)
{
	switch (t) {
	case POWEROFF:
		return "power off";
	case REBOOT:
		return "reboot";
	default:
		return "invalid shutdown type";
	}
}

static int shutdown_type_reboot_cmd(shutdown_type_t t)
{
	switch (t) {
	case POWEROFF:
		return LINUX_REBOOT_CMD_POWER_OFF;
	case REBOOT:
		return LINUX_REBOOT_CMD_RESTART;
	default:
		return LINUX_REBOOT_CMD_RESTART;
	}
}

static void pv_remove(struct pantavisor *pv)
{
	pv_log(DEBUG, "removing pantavisor");

	if (!pv)
		return;

	if (pv->cmdline)
		free(pv->cmdline);

	if (pv->conn)
		free(pv->conn);

	pv_update_free(pv->update);
	pv->update = NULL;
	pv_state_free(pv->state);
	pv->state = NULL;
	pv_ctrl_free_cmd(pv->cmd);
	pv_trail_remote_remove(pv);
	pv_config_free();
	pv_metadata_remove();

	free(pv);
	global_pv = NULL;
}

static pv_state_t pv_shutdown(struct pantavisor *pv, shutdown_type_t t)
{
	if (!pv)
		return PV_STATE_EXIT;

	init_mode_t initmode = pv_config_get_system_init_mode();

	pv_log(INFO, "preparing '%s'...", shutdown_type_string(t));
	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		pv_log(INFO,
		       "will not actually perform '%s' as we are in appengine mode",
		       shutdown_type_string(t));

	wait_shell();

	if ((REBOOT == t) && (initmode != IM_APPENGINE))
		pv_wdt_start(pv);

	// give it a final sync here...
	sync();

	pv_volumes_umount_firmware_modules();

	// stop childs leniently
	pv_state_stop_lenient(pv->state);
	ph_logger_stop_lenient();

	// force stop childs
	pv_state_stop_force(pv->state);
	ph_logger_stop_force();

	// unmount disks
	pv_disks_umount_all(pv->state);

	// close pvctrl
	pv_ctrl_socket_close(pv->ctrl_fd);

	// stop all logs but stdout
	pv_logserver_degrade();
	pv_log_umount();

	// kill dropbear if running ...
	if (db_pid > -1)
		kill(db_pid, SIGKILL);

	pv_mount_umount();
	pv_metadata_umount();

	pv_init_umount();

	pv_storage_umount();

	// free up memory
	pv_bootloader_remove();

	// at this point, we can shutdown if not in appengine
	if (initmode != IM_APPENGINE) {
		pv_log(INFO, "shutdown complete, rebooting in 2 second ...");
		sleep(2);
		pv_remove(pv);
		reboot(shutdown_type_reboot_cmd(t));
	} else {
		pv_log(INFO, "shutdown complete ...");
		pv_logserver_stop();
		pv_remove(pv);
	}

	// give it a final sync here...
	sync();

	return PV_STATE_EXIT;
}

static pv_state_t _pv_reboot(struct pantavisor *pv)
{
	return pv_shutdown(pv, REBOOT);
}

static pv_state_t _pv_poweroff(struct pantavisor *pv)
{
	return pv_shutdown(pv, POWEROFF);
}

static pv_state_t _pv_error(struct pantavisor *pv)
{
	return PV_STATE_REBOOT;
}

pv_state_func_t *const state_table[MAX_STATES] = {
	_pv_init,     _pv_run,		_pv_wait,     _pv_command,
	_pv_update,   _pv_update_apply, _pv_rollback, _pv_reboot,
	_pv_poweroff, _pv_error,	NULL,	      _pv_factory_upload,
};

static pv_state_t _pv_run_state(pv_state_t state, struct pantavisor *pv)
{
	pv_wdt_kick(pv);
	return state_table[state](pv);
}

int pv_start()
{
	char path[PATH_MAX];
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return 1;

	printf("Pantavisor (TM) (%s) - pantavisor.io\n", pv_build_version);
	SNPRINTF_WTRUNC(pv_user_agent, sizeof(pv_user_agent), PV_USER_AGENT_FMT,
			pv_build_arch, pv_build_version, pv_build_date);

	prctl(PR_SET_NAME, "pantavisor");

	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	setrlimit(RLIMIT_CORE, &core_limit);

	pv_paths_storage_file(path, PATH_MAX, COREPV_FNAME);
	int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY | O_SYNC);
	if (fd < 0)
		printf("open failed for /proc/sys/kernel/core_pattern: %s",
		       strerror(errno));
	else
		write(fd, path, strlen(path));

	pv_state_t state = PV_STATE_INIT;

	while (1) {
		pv_log(DEBUG, "going to state = %s", pv_state_string(state));
		state = _pv_run_state(state, pv);

		if (state == PV_STATE_EXIT)
			return 1;

		if (pv->hard_poweroff)
			state = PV_STATE_POWEROFF;
	}
}

void pv_stop()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	pv_shutdown(pv, REBOOT);
}

void pv_init()
{
	struct pantavisor *pv;

	pv = calloc(1, sizeof(struct pantavisor));
	if (pv)
		global_pv = pv;
}

static int pv_pantavisor_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;

	pv = pv_get_instance();
	if (!pv)
		goto out;
	// Make sure this is initialized
	pv->state = NULL;
	pv->remote = NULL;
	pv->update = NULL;
	pv->online = false;
	pv->remote_mode = false;
	pv->synced = false;
	pv->loading_objects = false;
	pv->hard_poweroff = false;

	// detect cgroup version
	pv->cgroupv = pv_system_get_cgroup_version();
	pv_log(DEBUG, "cgroup version detected '%s'",
	       pv_system_cgroupv_string(pv->cgroupv));
out:
	return 0;
}

struct pv_init pv_init_pantavisor = {
	.init_fn = pv_pantavisor_init,
	.flags = 0,
};
