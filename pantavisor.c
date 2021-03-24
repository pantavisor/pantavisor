/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <linux/limits.h>
#include <linux/reboot.h>

#include "utils.h"
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
#include "metadata.h"
#include "storage.h"
#include "tsh.h"
#include "ph_logger/ph_logger.h"

#define MODULE_NAME             "controller"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define CMDLINE_OFFSET	7

static struct pantavisor* global_pv;

struct pantavisor* pv_get_instance()
{
	return global_pv;
}

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

	ret = pv_metadata_factory_meta(pv);
	if (ret)
		return STATE_FACTORY_UPLOAD;
	return STATE_WAIT;
}

static pv_state_t _pv_init(struct pantavisor *pv)
{
	pv_log(DEBUG, "%s():%d", __func__, __LINE__);

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
		pv_state_transfer(pv->update->pending, pv->state);
	} else
		// after a reboot...
		pv->state = pv_storage_get_state(pv, pv_bootloader_get_rev());
	if (!pv->state)
	{
		pv_log(ERROR, "state could not be loaded");
		return STATE_ROLLBACK;
	}

	// only start local ph logger, start cloud services if connected
	ph_logger_toggle(pv, pv->state->rev);

	// meta data initialization, also to be uploaded as soon as possible when connected
	pv_storage_meta_set_objdir(pv);
	pv_metadata_parse_devmeta(pv);

	pv_log(DEBUG, "running pantavisor with runlevel %d", runlevel);

	// start up volumes and platforms
	if (pv_volumes_mount(pv, runlevel) < 0) {
		pv_log(ERROR, "error mounting volumes");
		return STATE_ROLLBACK;
	}

	if (pv_storage_make_config(pv) < 0) {
		pv_log(ERROR, "error making config");
		return STATE_ROLLBACK;
	}

	if (pv_platforms_start(pv, runlevel) < 0) {
		pv_log(ERROR, "error starting platforms");
		return STATE_ROLLBACK;
	}

	// set active only after plats have been started
	pv_storage_set_active(pv);

	// set initial wait delay and rollback count values
	clock_gettime(CLOCK_MONOTONIC, &tp);
	wait_delay = 0;
	commit_delay = 0;
	rollback_time = tp.tv_sec + pv_config_get_updater_network_timeout();

	return STATE_WAIT;
}

static pv_state_t _pv_unclaimed(struct pantavisor *pv)
{
	int need_register = 1;
	char *c;

	c = calloc(1, sizeof(char) * 128);

	pv_config_load_creds();

	if ((strcmp(pv_config_get_creds_id(), "") != 0) && pv_ph_device_exists(pv))
		need_register = 0;

	if (need_register) {
		if (!pv_ph_register_self(pv)) {
			pv_ph_release_client(pv);
			if (c)
				free(c);
			return STATE_WAIT;
		}
		pv_config_save_creds();
		pv_ph_release_client(pv);
	}

	if (!pv_ph_device_is_owned(pv, &c)) {
		pv_log(INFO, "device challenge: '%s'", c);
		pv_ph_update_hint_file(pv, c);
	} else {
		pv_log(INFO, "device has been claimed, proceeding normally");
		printf("INFO: pantavisor device has been claimed, proceeding normally\n");
		pv->unclaimed = false;
		pv_config_save_creds();
		pv_ph_release_client(pv);
		open("/pv/challenge", O_TRUNC | O_WRONLY);
	}

	pv_ph_update_hint_file(pv, NULL);

	if (c)
		free(c);

	return STATE_FACTORY_UPLOAD;
}

static int pv_meta_update_to_ph(struct pantavisor *pv)
{
	if (!pv)
		return 0;
	// update meta
	pv_metadata_upload_devmeta(pv);
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

	// start or stop ph logger depending on network and configuration
	ph_logger_toggle(pv, pv->state->rev);

	// update meta info
	if (!pv_metadata_factory_meta_done(pv)) {
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
			commit_delay = tp.tv_sec + pv_config_get_updater_commit_delay();
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
	if (pv_wait_delay_timedout(pv_config_get_updater_interval())) {
		// check if device is unclaimed
		if (pv->unclaimed) {
			next_state = STATE_UNCLAIMED;
			goto out;
		}

		// rest of network wait stuff: connectivity check. update management,
		// meta data uppload, ph logger push start...
		next_state = pv_wait_network(pv);
		if (next_state != STATE_WAIT)
			goto out;
	}

	// check if we need to run garbage collector
	if (pv_config_get_storage_gc_threshold() && pv_storage_threshold_reached(pv)) {
		pv_storage_gc_run(pv);
	}

	// receive new command. Set 2 secs as the select max blocking time, so we can do the
	// rest of WAIT operations
	pv->cmd = pv_ctrl_socket_wait(pv->ctrl_fd, 2);
	if (pv->cmd)
		next_state = STATE_COMMAND;

out:
	return next_state;
}

static pv_state_t _pv_command(struct pantavisor *pv)
{
	char *rev;
	struct pv_cmd *cmd = pv->cmd;
	struct pv_state *new;
	pv_state_t next_state = STATE_WAIT;

	if (!cmd)
		return STATE_WAIT;

	switch (cmd->op) {
	case CMD_TRY_ONCE:
		rev = cmd->payload;

		// lets not tryonce factory
		if (!strncmp(rev, "0", sizeof("0")))
			goto out;

		// load try state
		new = pv_storage_get_state(pv, rev);
		if (!new) {
			pv_log(DEBUG, "invalid rev requested %s", rev);
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
		pv_storage_meta_link_boot(pv, NULL);
		pv_storage_meta_set_tryonce(pv, 1);
		next_state = STATE_RUN;
		break;
	case CMD_UPDATE_METADATA:
		pv_log(DEBUG, "metadata command with payload '%s' received. Uploading metadata...",
			cmd->payload);
		pv_ph_upload_metadata(pv, cmd->payload);
		break;
	case CMD_REBOOT_DEVICE:
		if (pv->update) {
			pv_log(WARN, "ignoring reboot command because an update is in progress");
			goto out;
		}

		pv_log(DEBUG, "reboot command with message '%s' received. Rebooting...",
			cmd->payload);
		next_state = STATE_REBOOT;
		break;
	case CMD_POWEROFF_DEVICE:
		if (pv->update) {
			pv_log(WARN, "ignoring poweroff command because an update is in progress");
			goto out;
		}

		pv_log(DEBUG, "poweroff command with message '%s' received. Powering off...",
			cmd->payload);
		next_state = STATE_POWEROFF;
		break;
	case CMD_INSTALL_JSON:
		pv_log(DEBUG, "install json received");
		break;
	default:
		pv_log(WARN, "unknown command received. Ignoring...");
	}
out:
	pv_ctrl_free_cmd(pv->cmd);
	pv->cmd = NULL;
	return next_state;
}

static pv_state_t _pv_update(struct pantavisor *pv)
{
	// download and install pending step
	if (pv_update_install(pv) < 0) {
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
	if (pv->state && strncmp(pv->state->rev, "0", sizeof("0")))
		return STATE_ERROR;

	// rollback means current update needs to be reported to PH as FAILED
	if (pv->update)
		pv_update_set_status(pv, UPDATE_FAILED);

	pv_bootloader_set_rolledback();

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
	umount(pv_config_get_storage_mntpoint());
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
	umount(pv_config_get_storage_mntpoint());
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

int pv_start()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return 1;

	pv_state_t state = STATE_INIT;

	while (1) {
		pv_log(DEBUG, "going to state = %s", pv_state_string(state));
		state = _pv_run_state(state, pv);

		if (state == STATE_EXIT)
			return 1;
	}
}

static void pv_remove(struct pantavisor *pv)
{

	pv_log(DEBUG, "removing pantavisor");

	if (pv->conn)
		free(pv->conn);

	pv_update_free(pv->update);
	pv->update = NULL;
	pv_state_free(pv->state);
	pv->state = NULL;
	pv_ctrl_free_cmd(pv->cmd);
	pv_trail_remote_remove(pv);
	pv_config_free();

	free(pv);
	pv = NULL;
}

void pv_stop()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	pv_ctrl_socket_close(pv->ctrl_fd);

	pv_bootloader_remove();
	pv_remove(pv);
}

void pv_init()
{
	int ret;
	struct pantavisor *pv;

	printf("Pantavisor (TM) (%s) - www.pantahub.com\n", pv_build_version);
	sprintf(pv_user_agent, PV_USER_AGENT_FMT, pv_build_arch, pv_build_version, pv_build_date);

	prctl(PR_SET_NAME, "pantavisor");
	pv = calloc(1, sizeof(struct pantavisor));
	if (pv)
		global_pv = pv;

	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	setrlimit(RLIMIT_CORE, &core_limit);

	char *core = "/storage/corepv";
	int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY | O_SYNC);
	if (fd)
		write(fd, core, strlen(core));

	// Enter state machine
	ret = pv_start();

	// Clean exit -> reboot
	exit(ret);
}

static int pv_pantavisor_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	int ret = -1;

	pv = pv_get_instance();
	if (!pv)
		goto out;
	// Make sure this is initialized
	pv->state = NULL;
	pv->remote = NULL;
	pv->update = NULL;
	pv->online = false;
	ret = 0;
out:
	return 0;
}

struct pv_init pv_init_pantavisor = {
	.init_fn = pv_pantavisor_init,
	.flags = 0,
};
