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

#define MODULE_NAME		"controller"
#define sc_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define CONFIG_FILENAME	"/systemc/device.config"
#define CMDLINE_OFFSET	7

static int counter;
static int total;

typedef enum {
	STATE_INIT,
	STATE_RUN,
	STATE_WAIT,
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

//FIXME: should attempt connect() on dedicated api.pantacor.com endpoint
static int sc_network_is_up(void)
{
	struct hostent *ent;
	char *hostname = "pantacor.com";
	
	ent = gethostbyname(hostname);

	if (ent == NULL)
		return 0;

	return 1;
}

static sc_state_t _sc_init(struct systemc *sc)
{
	sc_log(DEBUG, "%s():%d", __func__, __LINE__);
	int fd, ret, bytes;
	int step_rev = -1;
	int step_try = 0;
	int bl_rev = -1;
	char *buf;
	char *token;
	struct systemc_config *c;

        c = malloc(sizeof(struct systemc_config));

        if (config_from_file(CONFIG_FILENAME, c) < 0) {
		sc_log(FATAL, "unable to parse config");
		return STATE_EXIT;
	}

	if (c->loglevel)
		sc_log_set_level(c->loglevel);

        sc_log(DEBUG, "c->storage.path = '%s'\n", c->storage.path);
        sc_log(DEBUG, "c->storage.fstype = '%s'\n", c->storage.fstype);
        sc_log(DEBUG, "c->storage.opts = '%s'\n", c->storage.opts);
        sc_log(DEBUG, "c->storage.mntpoint = '%s'\n", c->storage.mntpoint);
        sc_log(DEBUG, "c->creds.host = '%s'\n", c->creds.host);
        sc_log(DEBUG, "c->creds.port = '%d'\n", c->creds.port);
        sc_log(DEBUG, "c->creds.id = '%s'\n", c->creds.id);
        sc_log(DEBUG, "c->creds.abrn = '%s'\n", c->creds.abrn);
        sc_log(DEBUG, "c->creds.secret = '%s'\n", c->creds.secret);

	// Create storage mountpoint and mount device
        mkdir_p(c->storage.mntpoint, 0644);
        ret = mount(c->storage.path, c->storage.mntpoint, c->storage.fstype, 0, NULL);
        if (ret < 0)
                exit_error(errno, "Could not mount trails storage");

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
		token = strtok(NULL, " ");
	}
	free(buf);

	// Get current from disk if not specified in command line
	if ((step_rev < 0) && (step_try < 0)) {
		sc->state = sc_get_current_state(sc);
		if (sc->state)
			return STATE_RUN;
	}

	// If no current link, find latest
	if (step_rev < 0) {
		struct dirent **dirs;
		char basedir[PATH_MAX];

		sprintf(basedir, "%s/trails/", sc->config->storage.mntpoint);

		int n = scandir(basedir, &dirs, NULL, alphasort);
		while (n--) {
			char *tmp = dirs[n]->d_name;

			while (*tmp && isdigit(*tmp))
				tmp++;

			if(tmp[0] != '\0')
				continue;

			sc_log(INFO, "default to newest step_rev: '%s'", dirs[n]->d_name);
			step_rev = atoi(dirs[n]->d_name);
			break;
		}
	}
	
	// Make sure this is not initialized
	sc->remote = 0;
	sc->update = 0;

	// Coming from reboot update?
	if (step_try > 0) {
		sc->last = step_rev;
		step_rev = step_try;	
	}

	sc_bl_get_update(sc, &bl_rev);

	if (step_try > 0) {
		// Load update attempt
		sc->state = sc_get_state(sc, step_rev);
		sc_trail_update_start(sc, 1);
		sc->update->status = UPDATE_TRY;
		if (bl_rev > 0)
			sc_bl_clear_update(sc);
	} else if (bl_rev > 0) {
		// Load stale update
		sc->state = sc_get_state(sc, bl_rev);
		sc_trail_update_start(sc, 1);
		sc->update->status = UPDATE_FAILED;
		sc->update->need_finish = 1;
	}

	sc->state = sc_get_state(sc, bl_rev);

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
		return STATE_ERROR;
	}

	total++;
	sc_log(INFO, "started %d platforms", ret);
	
	counter = 0;

	return STATE_WAIT;
}

static sc_state_t _sc_wait(struct systemc *sc)
{
	int ret;
	int fd;
	char s[256];

	sc_log(DEBUG, "%s():%d\n", __func__, __LINE__);

	sleep(10);
	counter++;

	// FIXME: if update, wait a few times then error
	if (!sc_network_is_up()) {
		counter++;
		if (counter > 10)
			return STATE_ROLLBACK;
		return STATE_WAIT;
	}

	// FIXME: should use sc_bl_*() helpers
	// if online update pending to clear, commit update to cloud
	if (sc->update && sc->update->status == UPDATE_TRY) {
		sprintf(s, "%s/boot/uboot.txt", sc->config->storage.mntpoint);
		fd = open(s, O_RDWR | O_TRUNC | O_SYNC);
		memset(s, 0, sizeof(s));
		sprintf(s, "sc_rev=%d", sc->state->rev);
		write(fd, s, strlen(s) + 1);
		sync();
		close(fd);
		sc->update->status = UPDATE_DONE;
		sc_trail_update_finish(sc);
	}
	sc->last = sc->state->rev;

	// If stale failed update in flash, commit update to cloud
	if (sc->update && sc->update->need_finish) {
		sc_trail_update_finish(sc);
		sc_bl_clear_update(sc);
	}

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

	sc_log(DEBUG, "%s():%d\n", __func__, __LINE__);

	// queue locally and in cloud, block step
	// FIXME: requires sc_trail_update_finish() call after RUN or boot
	ret = sc_trail_update_start(sc, 0);
	if (ret < 0) {
		sc_log(WARN, "unable to queue update, abandoning it");
		return STATE_WAIT;
	}

	// download and install pending step
	ret = sc_trail_update_install(sc);
	if (ret < 0) {
		sc_log(ERROR, "update has failed, rollback");
		sc_trail_update_finish(sc);
		return STATE_ROLLBACK;
	}

	sc_log(INFO, "update applied, new rev = '%d', stopping current...", ret);

	// stop current step
	if (sc_platforms_stop_all(sc) < 0)
		return STATE_ERROR;
	if (sc_volumes_unmount(sc) < 0)
		return STATE_ERROR;

	// Release current step
	sc_release_state(sc);

	if (sc->update->need_reboot) {
		sc_log(INFO, "rebooting...");
		return STATE_REBOOT;
	}

	sc_log(INFO, "update applied, new rev = '%d', starting...", ret);

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
	sleep(1);
	return STATE_ERROR;
}

sc_state_func_t* const state_table[MAX_STATES] = {
	_sc_init,
	_sc_run,
	_sc_wait,
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
