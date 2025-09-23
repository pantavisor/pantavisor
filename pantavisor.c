/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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
#include <sys/resource.h>

#include <linux/limits.h>
#include <linux/reboot.h>

#include "pantavisor.h"
#include "loop.h"
#include "platforms.h"
#include "volumes.h"
#include "disk/disk.h"
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
#include "logserver/logserver.h"
#include "mount.h"
#include "debug.h"
#include "cgroup.h"
#include "buffer.h"

#include "event/event.h"
#include "event/event_timer.h"
#include "event/event_socket.h"

#include "pantahub/pantahub.h"

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
static struct timer timer_updater_interval;
static struct timer timer_commit;

static const int PV_WAIT_PERIOD = 1;

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
	default:
		return "STATE_UNKNOWN";
	}

	return "STATE_UNKNOWN";
}

typedef pv_state_t pv_state_func_t(struct pantavisor *pv);

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

		pv_logserver_transition(pv->update->pending->rev);

		ph_logger_stop_lenient();
		ph_logger_stop_force();

		pv_state_transition(pv->update->pending, pv->state);
	} else {
		// after a reboot...
		json = pv_storage_get_state_json(pv_bootloader_get_rev());
		sign_state_res_t sres;
		sres = pv_signature_verify(json);
		if (sres != SIGN_STATE_OK) {
			pv_log(ERROR,
			       "state signature verification went wrong");
			pv_update_set_status_msg(
				pv->update, UPDATE_SIGNATURE_FAILED,
				pv_signature_sign_state_str(sres));
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
		pv_update_set_status(pv->update, UPDATE_BAD_CHECKSUM);
		goto out;
	}

	pv_update_set_factory_status();

	// this might be a enum in the future, for now, we only need to know if DONE
	pv->state->done = pv_storage_is_rev_done(pv->state->rev);

	// once state is verified, we can load credentials, in case they are stored in a volume
	if (!pv_update_is_transitioning(pv->update)) {
		// mount bsp volumes
		if (pv_state_start(pv->state)) {
			pv_log(ERROR, "error starting state");
			goto out;
		}

		// load pantahub.config from vol or storage
		if (pv_config_load_creds()) {
			pv_log(ERROR, "creds load failed");
			goto out;
		}

		if (pv_pantahub_init()) {
			pv_log(ERROR,
			       "pantahub client could not be initialized");
			goto out;
		}
	}

	// load configuration that lives in revision
	pv_config_load_update(pv->state->rev, pv->state->bsp.config);

	// reload remote bool after non reboot updates, when we don't load config again
	pv->remote_mode = pv_config_get_bool(PV_CONTROL_REMOTE);
	pv->loading_objects = false;

	// we know if we are in local if the running revision has the local format
	if (pv_storage_is_revision_local(pv->state->rev)) {
		pv_log(DEBUG, "running local revision %s", pv->state->rev);
		pv->remote_mode = false;
		if (pv_config_get_bool(PV_CONTROL_REMOTE_ALWAYS)) {
			pv_log(DEBUG,
			       "remote mode forced on local revision by configuration");
			pv->remote_mode = true;
		}
	}

	if (!pv->remote_mode)
		pv_log(INFO,
		       "running in local mode. Will not consume new updates from Pantahub");

	// only start local ph logger, start cloud services if connected
	pv_logserver_toggle(pv, pv->state->rev);
	ph_logger_toggle(pv->state->rev);

	if (!pv_update_is_transitioning(pv->update)) {
		if (pv_metadata_init()) {
			pv_log(ERROR, "metadata mount failed");
			goto out;
		}
	}

	// trail .pvr/ initialization
	pv_storage_init_trail_pvr();

	// meta data initialization, also to be uploaded as soon as possible when connected
	pv_metadata_init_devmeta(pv);

	timer_start(&timer_commit, pv_config_get_int(PV_UPDATER_COMMIT_DELAY),
		    0, RELATIV_TIMER);
	timer_start(&timer_rollback_remote,
		    pv_config_get_int(PH_UPDATER_NETWORK_TIMEOUT), 0,
		    RELATIV_TIMER);
	timer_start(&timer_wait_delay, PV_WAIT_PERIOD, 0, RELATIV_TIMER);
	timer_start(&timer_updater_interval,
		    pv_config_get_int(PH_UPDATER_INTERVAL), 0, RELATIV_TIMER);

	if (pv_config_get_wdt_mode() <= WDT_STARTUP)
		pv_wdt_stop();

	next_state = PV_STATE_WAIT;
out:
	if (json)
		free(json);

	return next_state;
}

static pv_state_t pv_wait_unclaimed(struct pantavisor *pv)
{
	int need_register = 1;
	char *c = NULL;
	char path[PATH_MAX];

	struct timer_state tstate =
		timer_current_state(&timer_updater_interval);
	if (!tstate.fin)
		return PV_STATE_WAIT;

	if (!pv->state->done) {
		WARN_ONCE(
			"will not allow claiming if not running a DONE revision");
		return PV_STATE_WAIT;
	}

	timer_start(&timer_updater_interval,
		    pv_config_get_int(PH_UPDATER_INTERVAL), 0, RELATIV_TIMER);

	pv_config_load_unclaimed_creds();

	const char *id = pv_config_get_str(PH_CREDS_ID);
	if (id && strcmp(id, "") && pv_ph_device_exists(pv))
		need_register = 0;

	if (need_register) {
		pv_metadata_add_devmeta(
			DEVMETA_KEY_PH_STATE,
			pv_pantahub_state_string(PH_STATE_REGISTER));
		if (!pv_ph_register_self(pv)) {
			pv_ph_release_client(pv);
			return PV_STATE_WAIT;
		}
		pv_config_save_creds();
		pv_ph_release_client(pv);
	}

	if (!pv_ph_device_is_owned(pv, &c)) {
		pv_metadata_add_devmeta(
			DEVMETA_KEY_PH_STATE,
			pv_pantahub_state_string(PH_STATE_CLAIM));
		pv_log(INFO, "device challenge: '%s'", c);
		pv_ph_update_hint_file(pv, c);
	} else {
		pv_metadata_add_devmeta(
			DEVMETA_KEY_PH_STATE,
			pv_pantahub_state_string(PH_STATE_SYNC));
		pv_log(INFO, "device has been claimed, proceeding normally");
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

	return PV_STATE_WAIT;
}

static pv_state_t pv_wait_update()
{
	struct pantavisor *pv = pv_get_instance();
	plat_goal_state_t goal_state;

	// if an update is going on at this point, it means we still have to finish it
	if (pv->update && pv->update->status != UPDATE_APPLIED) {
		if (pv_update_is_trying(pv->update)) {
			goal_state = pv_state_check_goals(pv->state);

			switch (goal_state) {
			case PLAT_GOAL_UNACHIEVED:
				return PV_STATE_WAIT;
			case PLAT_GOAL_ACHIEVED:
				timer_start(&timer_commit,
					    pv_config_get_int(
						    PV_UPDATER_COMMIT_DELAY),
					    0, RELATIV_TIMER);
				// progress update state to testing
				pv_update_test(pv);
				break;
			case PLAT_GOAL_TIMEDOUT:
				pv_log(ERROR,
				       "timed out before all goals were met. Rolling back...");
				pv_update_set_status(pv->update,
						     UPDATE_STATUS_GOAL_FAILED);
				return PV_STATE_ROLLBACK;
			default:
				pv_log(ERROR,
				       "could not check groups goals. Rolling back...");
				return PV_STATE_ROLLBACK;
			}
		}
		// if the update is being tested, we might have to wait
		if (pv_update_is_testing(pv->update)) {
			// progress if possible the state of testing update
			struct timer_state tstate =
				timer_current_state(&timer_commit);
			if (!tstate.fin) {
				pv_log(INFO,
				       "committing new update in %jd seconds",
				       (intmax_t)tstate.sec);
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
		if (pv_update_is_local(pv->update)) {
			// we don't want to rollback local revisions because of failing Hub comms
			// which could happen when PV_CONTROL_REMOTE_ALWAYS=1
			return PV_STATE_WAIT;
		} else if (pv_update_is_trying(pv->update)) {
			// this could mean the trying update cannot connect to ph
			tstate = timer_current_state(&timer_rollback_remote);
			if (tstate.fin) {
				pv_log(ERROR,
				       "timed out before getting any response from cloud. Rolling back...");
				pv_update_set_status(pv->update,
						     UPDATE_HUB_NOT_REACHABLE);
				return PV_STATE_ROLLBACK;
			}
			pv_log(WARN,
			       "no connection. Will rollback in %jd seconds",
			       (intmax_t)tstate.sec);
			// or we directly rollback is connection is not stable during testing
		} else if (pv_update_is_testing(pv->update)) {
			pv_log(ERROR,
			       "connection with cloud not stable during testing, Rolling back...");
			pv_update_set_status(pv->update, UPDATE_HUB_NOT_STABLE);
			return PV_STATE_ROLLBACK;
		}
		// if there is no connection and no rollback yet, we avoid the rest of network operations
		return PV_STATE_WAIT;
	}

	// start or stop ph logger depending on network and configuration
	ph_logger_toggle(pv->state->rev);

	// ph client state machine
	pv_pantahub_step();

	// check for new remote update
	tstate = timer_current_state(&timer_updater_interval);
	if (tstate.fin) {
		if (pv_updater_check_for_updates(pv) > 0) {
			pv_metadata_add_devmeta(
				DEVMETA_KEY_PH_STATE,
				pv_pantahub_state_string(PH_STATE_UPDATE));
			return PV_STATE_UPDATE;
		}
		timer_start(&timer_updater_interval,
			    pv_config_get_int(PH_UPDATER_INTERVAL), 0,
			    RELATIV_TIMER);
	}

	if (pv->synced)
		pv_metadata_add_devmeta(
			DEVMETA_KEY_PH_STATE,
			pv_pantahub_state_string(PH_STATE_IDLE));

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
		    pv_update_is_testing(pv->update)) {
			pv_update_set_status(pv->update,
					     UPDATE_CONTAINER_FAILED);
			next_state = PV_STATE_ROLLBACK;
		} else
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
			       "network operations are taking %jd seconds!",
			       (intmax_t)(5 + tstate.sec));
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

	// check state of debug tools
	pv_debug_check_ssh_running();

	// this is set in the ctrl_listener event
	if (pv->cmd)
		next_state = PV_STATE_COMMAND;

out:
	if (pv_debug_run_shell())
		next_state = PV_STATE_REBOOT;

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
	case CMD_LOCAL_RUN_COMMIT:
		if (pv->update && pv->update->status != UPDATE_APPLIED) {
			pv_log(WARN,
			       "ignoring local run commit command because an update is in progress");
			goto out;
		} else if (pv->update && pv->update->status == UPDATE_APPLIED) {
			pv_log(INFO,
			       "aborting local run commit to allow local run commit request to proceed");
			pv_update_finish(pv);
		}

		pv_log(DEBUG,
		       "install run commit received. Processing %s json...",
		       cmd->payload);
		pv->update = pv_update_get_step_local(cmd->payload);
		pv_update_set_needs_commit(pv->update);
		if (pv->update)
			next_state = PV_STATE_UPDATE;
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
	case CMD_ENABLE_SSH:
		pv_log(DEBUG, "enable SSH command received");
		pv_config_override_value("debug.ssh", "1");
		break;
	case CMD_DISABLE_SSH:
		pv_log(DEBUG, "disable SSH command received");
		pv_config_override_value("debug.ssh", "0");
		break;
	case CMD_GO_REMOTE:
		pv_log(DEBUG, "go remote command received");
		if (!pv_config_get_bool(PV_CONTROL_REMOTE)) {
			pv_log(WARN, "remote mode is disabled by config");
			goto out;
		}
		pv->remote_mode = true;
		break;
	case CMD_DEFER_REBOOT:
		if (!pv_config_get_bool(PV_DEBUG_SHELL)) {
			pv_log(WARN,
			       "defer reboot command received but debug shell is not active");
			goto out;
		}
		if (strlen(cmd->payload) == 0)
			goto out;

		pv_log(DEBUG, "defer reboot command received, new timeout '%s'",
		       cmd->payload);

		pv_debug_defer_reboot_shell(cmd->payload);
		break;
	default:
		pv_log(WARN, "unknown command received. Ignoring...");
	}
out:
	// free processing command so we can take further ones
	pv_ctrl_free_cmd(pv->cmd);
	pv->cmd = NULL;
	return next_state;
}

static pv_state_t _pv_update_apply(struct pantavisor *pv)
{
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE,
				pv_pantahub_state_string(PH_STATE_UPDATE));

	// download and install pending step
	if (pv_update_download(pv) || pv_update_install(pv)) {
		pv_log(ERROR, "update has failed, continue...");
		pv_update_finish(pv);
		return PV_STATE_WAIT;
	}
	pv_update_set_status(pv->update, UPDATE_APPLIED);

	return PV_STATE_WAIT;
}

static pv_state_t _pv_update(struct pantavisor *pv)
{
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE,
				pv_pantahub_state_string(PH_STATE_UPDATE));

	// download and install pending step
	if (pv_update_download(pv) || pv_update_install(pv)) {
		pv_log(ERROR, "update has failed, continue...");
		pv_update_finish(pv);
		return PV_STATE_WAIT;
	}

	// after installing, try to only stop the platforms that we need for the new update
	if (pv_state_stop_platforms(pv->state, pv->update->pending)) {
		pv_log(INFO, "update requires reboot");
		pv_update_set_status(pv->update, UPDATE_REBOOT);
		return PV_STATE_REBOOT;
	}

	pv_update_set_status(pv->update, UPDATE_TRANSITION);

	if (pv_update_get_needs_commit(pv->update))
		return PV_STATE_REBOOT;

	pv_log(INFO, "update does not require reboot");
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
	if (pv->update)
		pv_update_finish(pv);

	return PV_STATE_REBOOT;
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

	init_mode_t init_mode = pv_config_get_system_init_mode();

	pv_log(INFO, "preparing '%s'...", shutdown_type_string(t));
	if (init_mode == IM_APPENGINE)
		pv_log(INFO,
		       "will not actually perform '%s' as we are in appengine mode",
		       shutdown_type_string(t));

	if ((REBOOT == t) && (pv_config_get_wdt_mode() >= WDT_SHUTDOWN))
		pv_wdt_start();

	// give it a final sync here...
	sync();

	// stop childs leniently
	pv_state_stop_lenient(pv->state);
	ph_logger_stop_lenient();

	// force stop childs
	pv_state_stop_force(pv->state);
	ph_logger_stop_force();
	ph_logger_close();

	pv_pantahub_close();

	// close pvctrl
	pv_ctrl_socket_close(pv->ctrl_fd);

	pv_debug_stop_ssh();
	pv_logserver_stop();

	// unmounting
	pv_volumes_umount_firmware_modules();
	pv_log_umount();
	pv_mount_umount();
	pv_metadata_umount();

	pv_init_umount();
	pv_disk_umount_all(&pv->state->disks);
	pv_storage_umount();

	pv_mount_print();

	// free up memory
	pv_bootloader_remove();
	pv_buffer_close();

	// at this point, we can shutdown if not in appengine
	if (init_mode != IM_APPENGINE) {
		pv_log(INFO,
		       "shutdown complete, performing '%s' in 2 second...",
		       shutdown_type_string(t));
		sleep(2);
		pv_remove(pv);
		pv_event_base_close();
		sync();
		reboot(shutdown_type_reboot_cmd(t));
	} else {
		pv_log(INFO, "shutdown complete...");
		pv_remove(pv);
		sync();
		if (t == POWEROFF) {
			pv_event_base_close();
			exit(3);
		}
	}

	return PV_STATE_EXIT;
}

static pv_state_t _pv_reboot(struct pantavisor *pv)
{
	if (pv_debug_check_timeout_shell())
		return PV_STATE_WAIT;

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
	_pv_poweroff, _pv_error,	NULL,
};

static pv_state_t state = PV_STATE_INIT;
static event_timer_t wait_timer;
static event_socket_t ctrl_listener = { -1, NULL };

static void _pv_run_state_cb(evutil_socket_t fd, short events, void *arg)
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	pv_wdt_kick();

	pv_log(DEBUG, "run event: cb=%p", (void *)_pv_run_state_cb);
	pv_log(DEBUG, "next state: '%s'", pv_state_string(state));
	pv_state_t next_state = state_table[state](pv);

	if (next_state == PV_STATE_EXIT) {
		pv_event_base_loopbreak();
		goto out;
	}

	if (pv->hard_poweroff)
		next_state = PV_STATE_POWEROFF;

	if ((state != PV_STATE_WAIT) && (next_state == PV_STATE_WAIT)) {
		// in case we are starting WAIT for the first time
		pv_event_timer_run(&wait_timer, 2, _pv_run_state_cb);
		pv_event_socket_listen(&ctrl_listener, pv->ctrl_fd,
				       pv_ctrl_socket_read);
		goto out;
	} else if ((state == PV_STATE_WAIT) && (next_state == PV_STATE_WAIT)) {
		// if we are stuck in wAIT
		goto out;
	} else if ((state == PV_STATE_WAIT) && (next_state != PV_STATE_WAIT)) {
		// if we are leaving WAIT
		pv_event_timer_close(&wait_timer);
		pv_event_socket_ignore(&ctrl_listener);
	}

	// all states except WAIT are executed as soon as possible
	pv_event_one_shot(_pv_run_state_cb);
out:
	state = next_state;
}

int pv_start()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return 1;

	SNPRINTF_WTRUNC(pv_user_agent, sizeof(pv_user_agent), PV_USER_AGENT_FMT,
			pv_build_arch, pv_build_version, pv_build_date);

	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	setrlimit(RLIMIT_CORE, &core_limit);

	if (pv_event_base_init() < 0)
		return 1;

	state = PV_STATE_INIT;
	pv_event_one_shot(_pv_run_state_cb);
	pv_event_base_loop();
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
		return -1;
	// Make sure this is initialized
	pv->state = NULL;
	pv->remote = NULL;
	pv->update = NULL;
	pv->online = false;
	pv->remote_mode = false;
	pv->synced = false;
	pv->loading_objects = false;
	pv->hard_poweroff = false;

	pv_cgroup_print();

	ph_logger_init();

	return 0;
}

struct pv_init pv_init_pantavisor = {
	.init_fn = pv_pantavisor_init,
	.flags = 0,
};
