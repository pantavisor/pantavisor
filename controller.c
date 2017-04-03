#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <netdb.h>

#include <sys/reboot.h>
#include <linux/limits.h>
#include <linux/reboot.h>

#include "utils.h"
#include "systemc.h"
#include "loop.h"
#include "platforms.h"
#include "controller.h"
#include "updater.h"
#include "volumes.h"
#include "pantahub.h"
#include "bootloader.h"

#define MODULE_NAME		"controller"
#define sc_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define SC_CONFIG_FILENAME	"/systemc/device.config"
#define CMDLINE_OFFSET	7

static int counter;
static int total;

typedef enum {
	STATE_INIT,
	STATE_RUN,
	STATE_WAIT,
	STATE_UNCLAIMED,
	STATE_UPDATE,
	STATE_ROLLBACK,
	STATE_REBOOT,
	STATE_ERROR,
	STATE_EXIT,
	MAX_STATES
} sc_state_t;

typedef sc_state_t sc_state_func_t(struct systemc *sc);

static int sc_step_get_prev(struct systemc *sc)
{
	if (!sc)
		return -1;

	if (sc->state)
		return (sc->state->rev - 1);

	return -1;
}

static sc_state_t _sc_init(struct systemc *sc)
{
	sc_log(DEBUG, "%s():%d", __func__, __LINE__);
	int fd, ret, bytes;
	int step_rev = 0, step_try = 0, sc_boot = -1;
	int bl_rev = 0;
	char *buf;
	char *token;
	char pconfig_p[256];
	struct systemc_config *c;
	struct stat st;

	// Initialize flags
	sc->flags = 0;

        c = malloc(sizeof(struct systemc_config));

        if (sc_config_from_file(SC_CONFIG_FILENAME, c) < 0) {
		sc_log(FATAL, "unable to parse systemc config");
		return STATE_EXIT;
	}

	if (c->loglevel)
		sc_log_set_level(c->loglevel);

        sc_log(DEBUG, "c->storage.path = '%s'\n", c->storage.path);
        sc_log(DEBUG, "c->storage.fstype = '%s'\n", c->storage.fstype);
        sc_log(DEBUG, "c->storage.opts = '%s'\n", c->storage.opts);
        sc_log(DEBUG, "c->storage.mntpoint = '%s'\n", c->storage.mntpoint);

	// Create storage mountpoint and mount device
        mkdir_p(c->storage.mntpoint, 0644);

	// Check that storage device has been enumerated and wait if not there yet
	// (RPi2 for example is too slow to scan the MMC devices in time)
	for (int wait = 5; wait > 0; wait--) {
		if (stat(c->storage.path, &st) == 0)
			break;
		sc_log(INFO, "trail storage not yet available, waiting...");
		sleep(1);
		continue;
	}

        ret = mount(c->storage.path, c->storage.mntpoint, c->storage.fstype, 0, NULL);
        if (ret < 0)
                exit_error(errno, "Could not mount trails storage");

	sprintf(pconfig_p, "%s/config/pantahub.config", c->storage.mntpoint);
        if (ph_config_from_file(pconfig_p, c) < 0) {
		sc_log(FATAL, "unable to parse pantahub config");
		return STATE_EXIT;
	}

	sc_log(DEBUG, "c->creds.host = '%s'\n", c->creds.host);
        sc_log(DEBUG, "c->creds.port = '%d'\n", c->creds.port);
        sc_log(DEBUG, "c->creds.id = '%s'\n", c->creds.id);
        sc_log(DEBUG, "c->creds.prn = '%s'\n", c->creds.prn);
        sc_log(DEBUG, "c->creds.secret = '%s'\n", c->creds.secret);

	// Make pantavisor control area
	if (stat("/tmp/pantavisor", &st) != 0)
		mkdir_p("/tmp/pantavisor", 0644);

	if (strcmp(c->creds.prn, "") == 0) {
		fd = open("/tmp/pantavisor/device-id", O_CREAT | O_SYNC | O_WRONLY, 0644);
		close(fd);
		fd = open("/tmp/pantavisor/challenge", O_CREAT | O_SYNC | O_WRONLY, 0644);
		close(fd);
		sc->flags |= DEVICE_UNCLAIMED;
	}

	// Set config
	sc->config = c;

	// Get current step revision from cmdline
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -1;

	buf = calloc(1, sizeof(char) * (1024 + 1));
	bytes = read(fd, buf, sizeof(char)*1024);
	close(fd);

	token = strtok(buf, " ");
	while (token) {
		if (strncmp("sc_rev=", token, CMDLINE_OFFSET) == 0)
			step_rev = atoi(token + CMDLINE_OFFSET);
		else if (strncmp("sc_try=", token, CMDLINE_OFFSET) == 0)
			step_try = atoi(token + CMDLINE_OFFSET);
		else if (strncmp("sc_boot=", token, CMDLINE_OFFSET) == 0)
			sc_boot = atoi(token + CMDLINE_OFFSET + 1);
		token = strtok(NULL, " ");
	}
	free(buf);

	// Make sure this is initialized
	sc->state = 0;
	sc->remote = 0;
	sc->update = 0;
	sc->last = -1;

	// Setup PVK hints in case of legacy flash A/B kernel
	if (sc_boot != -1 && !strcmp(sc->config->bl_type, "uboot-pvk")) {
		step_rev = sc_bl_pvk_get_rev(sc, sc_boot);
		step_try = sc_bl_get_try(sc);
		if (step_try != step_rev)
			step_try = 0;
	}

	sc_log(DEBUG, "%s():%d step_try=%d, step_rev=%d\n", __func__, __LINE__, step_try, step_rev);

	int boot_rev = -1;
	if (step_try == 0) {
		boot_rev = step_rev;
	} else if (step_try == step_rev) {
		boot_rev = step_try;
		sc->state = sc_get_state(sc, boot_rev);
		sc_trail_update_start(sc, 1);
		sc->update->status = UPDATE_TRY;
	}

	bl_rev = sc_bl_get_try(sc);
	if (bl_rev && (bl_rev != boot_rev)) {
		if (!sc->state)
			sc->state = sc_get_state(sc, bl_rev);
		sc_trail_update_start(sc, 1);
		sc->update->status = UPDATE_FAILED;
		sc_state_free(sc->state);
		sc->state = 0;
	}

	if (!sc->state)
		sc->state = sc_get_state(sc, boot_rev);

	if (bl_rev > 0)
		sc_bl_clear_update(sc);

	if (!sc->state) {
		sc_log(ERROR, "invalid state requested, please reconfigure");
		return STATE_ERROR;
	}

	// FIXME: somewhere here load update from disk if in progress, maybe with try?

	total = 0;

        return STATE_RUN;
}

static sc_state_t _sc_run(struct systemc *sc)
{
	sc_log(DEBUG, "%s():%d\n", __func__, __LINE__);
	int ret;

	if (sc_volumes_mount(sc) < 0)
		return STATE_ROLLBACK;

	ret = sc_platforms_start_all(sc);
	if (ret < 0) {
		sc_log(ERROR, "error starting platforms");
		return STATE_ROLLBACK;
	}

	total++;
	sc_log(INFO, "started %d platforms", ret);

	// update current in bl
	sc_bl_set_current(sc, sc->state->rev);

	counter = 0;

	return STATE_WAIT;
}

static sc_state_t _sc_unclaimed(struct systemc *sc)
{
	int need_register = 1;
	struct stat st;
	char config_path[256];
	char *c = malloc(sizeof(char) * 128);

	if (!sc_ph_is_available(sc))
		return STATE_WAIT;

	sprintf(config_path, "%s/config/unclaimed.config", sc->config->storage.mntpoint);
	if (stat(config_path, &st) == 0)
		ph_config_from_file(config_path, sc->config);

	if ((strcmp(sc->config->creds.id, "") != 0) && sc_ph_device_exists(sc))
		need_register = 0;

	if (need_register && sc_ph_register_self(sc))
		ph_config_to_file(sc->config, config_path);

	if (!sc_ph_device_is_owned(sc, &c)) {
		sc_log(INFO, "device challenge: '%s'", c);
		sc_ph_update_hint_file(sc, c);
	} else {
		sc_log(INFO, "device has been claimed, proceeding normally");
		sprintf(config_path, "%s/config/pantahub.config", sc->config->storage.mntpoint);
		ph_config_to_file(sc->config, config_path);
		sc_ph_release_client(sc);
		sc->flags &= ~DEVICE_UNCLAIMED;
	}

	if (c)
		free(c);

	return STATE_WAIT;
}

static sc_state_t _sc_wait(struct systemc *sc)
{
	int ret;

	sleep(5);

	if (sc->flags & DEVICE_UNCLAIMED)
		return STATE_UNCLAIMED;

	// FIXME: if update, wait a few times then error
	if (!sc_ph_is_available(sc)) {
		counter++;
		if (counter > 20)
			return STATE_ROLLBACK;
		return STATE_WAIT;
	}

	counter = 0;

	// FIXME: should use sc_bl_*() helpers
	// if online update pending to clear, commit update to cloud
	if (sc->update && sc->update->status == UPDATE_TRY) {
		sc_bl_set_current(sc, sc->state->rev);
		sc->update->status = UPDATE_DONE;
		sc_trail_update_finish(sc);
	} else if (sc->update && sc->update->status == UPDATE_FAILED) {
		// We come from a forced rollback
		sc_bl_set_current(sc, sc->state->rev);
		sc->update->status = UPDATE_FAILED;
		sc_trail_update_finish(sc);
	}
	sc->last = sc->state->rev;

	ret = sc_trail_check_for_updates(sc);
	if (ret) {
		sc_log(INFO, "updates found");
		return STATE_UPDATE;
	}

	return STATE_WAIT;
}

static sc_state_t _sc_update(struct systemc *sc)
{
	int ret;

	// queue locally and in cloud, block step
	// FIXME: requires sc_trail_update_finish() call after RUN or boot
	ret = sc_trail_update_start(sc, 0);
	if (ret < 0) {
		sc_log(INFO, "unable to queue update, abandoning it");
		return STATE_WAIT;
	}

	// download and install pending step
	ret = sc_trail_update_install(sc);
	if (ret < 0) {
		sc_log(ERROR, "update has failed, rollback");
		sc_trail_update_finish(sc);
		return STATE_ROLLBACK;
	}

	sc_log(WARN, "New trail state accepted, stopping current state.");

	// stop current step
	if (sc_platforms_stop_all(sc) < 0)
		return STATE_ERROR;
	if (sc_volumes_unmount(sc) < 0)
		return STATE_ERROR;

	// Release current step
	sc_release_state(sc);

	if (sc->update->need_reboot) {
		sc_log(WARN, "Update requires reboot, rebooting...");
		return STATE_REBOOT;
	}

	sc_log(WARN, "State update applied, starting new revision.", ret);

	// Load installed step
	sc->state = sc_get_state(sc, ret);

	if (sc->state == NULL)
		return STATE_ROLLBACK;

	return STATE_RUN;
}

static sc_state_t _sc_rollback(struct systemc *sc)
{
	int ret = 0;
	sc_log(DEBUG, "%s():%d\n", __func__, __LINE__);

	// We shouldnt get a rollback event on rev 0
	if (sc->state->rev == 0)
		return STATE_ERROR;

	// If we rollback, it means the considered OK update (kernel)
	// actually failed to start platforms or mount volumes
	sc->update->status = UPDATE_FAILED;

	if (sc->state) {
		ret = sc_platforms_stop_all(sc);
		if (ret < 0)
			return STATE_ERROR;

		ret = sc_volumes_unmount(sc);
		if (ret < 0)
			return STATE_ERROR;

		counter = 0;
		sc_release_state(sc);
	}

	if (sc->last == -1)
		sc->last = sc->state->rev - 1;

	sc->state = sc_get_state(sc, sc->last);
	if (sc->state)
		sc_log(INFO, "loaded previous step %d\n", sc->last);

	return STATE_RUN;
}

static sc_state_t _sc_reboot(struct systemc *sc)
{
	sc_log(DEBUG, "%s():%d", __func__, __LINE__);

	sc_trail_update_finish(sc);
	sync();
	sc_log(INFO, "rebooting...");
	sleep(2);
	reboot(LINUX_REBOOT_CMD_RESTART);

	return STATE_EXIT;
}

static sc_state_t _sc_error(struct systemc *sc)
{
	sc_log(DEBUG, "%s():%d\n", __func__, __LINE__);
	sleep(5);
	return STATE_ERROR;
}

sc_state_func_t* const state_table[MAX_STATES] = {
	_sc_init,
	_sc_run,
	_sc_wait,
	_sc_unclaimed,
	_sc_update,
	_sc_rollback,
	_sc_reboot,
	_sc_error,
	NULL
};

static sc_state_t _sc_run_state(sc_state_t state, struct systemc *sc)
{
	return state_table[state](sc);
}

int sc_controller_start(struct systemc *sc)
{
	sc_log(DEBUG, "%s():%d", __func__, __LINE__);

	sc_state_t state = STATE_INIT;

	while (1) {
		sc_log(DEBUG, "going to state = %d", state);
		state = _sc_run_state(state, sc);

		if (state == STATE_EXIT)
			return 1;
	}
}
