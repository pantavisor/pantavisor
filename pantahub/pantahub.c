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
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <trest.h>
#include <thttp.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <jsmn/jsmnutil.h>

#include "pantahub/pantahub.h"

#include "trestclient.h"
#include "pantavisor.h"
#include "json.h"
#include "metadata.h"
#include "updater.h"

#include "event/event.h"
#include "event/event_rest.h"

#include "pantahub/pantahub_proto.h"

#include "utils/tsh.h"
#include "utils/str.h"
#include "utils/fs.h"

#define MODULE_NAME "pantahub"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define ENDPOINT_FMT "/devices/%s"

#define REQ_INTERVAL 6

#define PANTAVISOR_EXTERNAL_REGISTER_HANDLER_FMT "/btools/%s.register"


static struct pv_pantahub *global_ph;

const char *_get_state_string(ph_state_t state)
{
	switch (state) {
	case PH_STATE_INIT:
		return "init";
	case PH_STATE_REGISTER:
		return "register";
	case PH_STATE_CLAIM:
		return "claim";
	case PH_STATE_SYNC:
		return "sync";
	case PH_STATE_LOGIN:
		return "login";
	case PH_STATE_WAIT_HUB:
		return "wait Hub";
	case PH_STATE_REPORT:
		return "report";
	case PH_STATE_IDLE:
		return "idle";
	case PH_STATE_PREP_DOWNLOAD:
		return "prep download";
	case PH_STATE_DOWNLOAD:
		return "download";
	default:
		return "unknown";
	}

	return "unknown";
}

struct pv_pantahub *_get_ph_instance()
{
	return global_ph;
}

static void _close_state()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	pv_log(DEBUG, "closing state: %s", _get_state_string(ph->state));

	pv_event_periodic_stop(&ph->request_timer);
	pv_event_periodic_stop(&ph->devmeta_timer);
	pv_event_periodic_stop(&ph->usrmeta_timer);
}

int pv_pantahub_stop()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return -1;

	_close_state();

	pv_pantahub_proto_close();

	pv_event_rest_cleanup();

	free(ph);
	global_ph = NULL;

	return pv_config_unload_creds();
}

static void _run_state_cb(evutil_socket_t fd, short events, void *arg);

static void _next_state(ph_state_t state)
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	if (ph->state == state)
		return;

	_close_state();

	pv_log(DEBUG, "next state: %s", _get_state_string(state));

	ph->state = state;
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE, _get_state_string(state));

	pv_event_one_shot(_run_state_cb);
}

static void _run_state_init()
{
	pv_pantahub_proto_init();

	if (pv_event_rest_init()) {
		pv_log(ERROR, "HTTP REST initialization failed");
		_next_state(PH_STATE_INIT);
	}

	pv_pantahub_evaluate_state();
}

static void _register_builtin_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_register_builtin_cb);

	pv_pantahub_proto_post_device();
}

static void _register_ext()
{
	char path[PATH_MAX];
	int status;

	SNPRINTF_WTRUNC(path, sizeof(path),
			PANTAVISOR_EXTERNAL_REGISTER_HANDLER_FMT,
			pv_config_get_str(PH_CREDS_TYPE));

	if (!pv_fs_path_exist(path)) {
		pv_log(ERROR, "path '%s' does not exist. Rebooting...", path);
		pv_issue_reboot();
		return;
	}

	if (tsh_run(path, 1, &status) < 0) {
		pv_log(ERROR, "registration failed: %s", path);
	}
}

static void _run_state_register()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	switch (pv_config_get_creds_type()) {
	case CREDS_BUILTIN:
		pv_event_periodic_start(&ph->request_timer, REQ_INTERVAL,
					_register_builtin_cb);
		break;
	case CREDS_EXTERNAL:
		_register_ext();
		pv_pantahub_evaluate_state();
		break;
	default:
		pv_log(ERROR,
		       "cannot continue registering device. Rebooting...");
		pv_issue_reboot();
		break;
	}
}

static void _login_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_login_cb);

	pv_pantahub_proto_post_auth();
}

static void _run_state_login()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	pv_event_periodic_start(&ph->request_timer, REQ_INTERVAL, _login_cb);
}

static void _claim_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_claim_cb);

	pv_pantahub_proto_get_device();
}

static void _run_state_claim()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	pv_event_periodic_start(&ph->request_timer, REQ_INTERVAL, _claim_cb);
}

static void _wait_hub_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_wait_hub_cb);

	pv_pantahub_proto_get_trails_status();
}

static void _run_state_wait_hub()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	pv_event_periodic_start(&ph->request_timer, REQ_INTERVAL, _wait_hub_cb);
}

static void _run_state_sync()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	if (!pv_state_is_done(pv->state)) {
		pv_log(WARN,
		       "will not proceed with syncing if not running a DONE revision");
		_next_state(PH_STATE_INIT);
		return;
	}

	// TODO: this is old and blocking, but mainly blocking
	pv_updater_sync();

	pv_pantahub_proto_reset_trails_status();
	_next_state(PH_STATE_WAIT_HUB);
}

static void _usrmeta_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_usrmeta_cb);

	if (!pv_pantahub_proto_is_online())
		return;

	pv_pantahub_proto_get_usrmeta();
}

static void _devmeta_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_devmeta_cb);

	if (!pv_pantahub_proto_is_online())
		return;

	pv_pantahub_proto_set_devmeta();
}

static void _run_state_report()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	// we reset the request failure count to begin testing Hub comms
	pv_pantahub_proto_reset_fail();

	pv_event_periodic_start(&ph->usrmeta_timer,
				pv_config_get_int(PH_METADATA_USRMETA_INTERVAL),
				_usrmeta_cb);
	pv_event_periodic_start(&ph->devmeta_timer,
				pv_config_get_int(PH_METADATA_DEVMETA_INTERVAL),
				_devmeta_cb);
}

static void _updater_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_updater_cb);
	pv_pantahub_proto_get_pending_steps();
}

static void _run_state_idle()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	pv_event_periodic_start(&ph->request_timer,
				pv_config_get_int(PH_UPDATER_INTERVAL),
				_updater_cb);
	pv_event_periodic_start(&ph->usrmeta_timer,
				pv_config_get_int(PH_METADATA_USRMETA_INTERVAL),
				_usrmeta_cb);
	pv_event_periodic_start(&ph->devmeta_timer,
				pv_config_get_int(PH_METADATA_DEVMETA_INTERVAL),
				_devmeta_cb);
}

static void _prep_download_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_prep_download_cb);

	if (pv_pantahub_proto_get_objects_metadata()) {
		_next_state(PH_STATE_IDLE);
		return;
	}
}

static void _run_state_prep_download()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	pv_pantahub_proto_init_object_transfer();

	pv_event_periodic_start(&ph->request_timer, REQ_INTERVAL,
				_prep_download_cb);
	pv_event_periodic_start(&ph->usrmeta_timer,
				pv_config_get_int(PH_METADATA_USRMETA_INTERVAL),
				_usrmeta_cb);
	pv_event_periodic_start(&ph->devmeta_timer,
				pv_config_get_int(PH_METADATA_DEVMETA_INTERVAL),
				_devmeta_cb);
}

static void _download_objects_cb(evutil_socket_t fd, short event, void *arg)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_download_objects_cb);

	if (pv_pantahub_proto_get_objects()) {
		_next_state(PH_STATE_IDLE);
		return;
	}
}

static void _run_state_download()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	pv_pantahub_proto_init_object_transfer();

	pv_event_periodic_start(&ph->request_timer, REQ_INTERVAL,
				_download_objects_cb);
	pv_event_periodic_start(&ph->usrmeta_timer,
				pv_config_get_int(PH_METADATA_USRMETA_INTERVAL),
				_usrmeta_cb);
	pv_event_periodic_start(&ph->devmeta_timer,
				pv_config_get_int(PH_METADATA_DEVMETA_INTERVAL),
				_devmeta_cb);
}

static void _run_state_cb(evutil_socket_t fd, short events, void *arg)
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return;

	switch (ph->state) {
	case PH_STATE_INIT:
		_run_state_init();
		break;
	case PH_STATE_REGISTER:
		_run_state_register();
		break;
	case PH_STATE_LOGIN:
		_run_state_login();
		break;
	case PH_STATE_CLAIM:
		_run_state_claim();
		break;
	case PH_STATE_WAIT_HUB:
		_run_state_wait_hub();
		break;
	case PH_STATE_SYNC:
		_run_state_sync();
		break;
	case PH_STATE_REPORT:
		_run_state_report();
		break;
	case PH_STATE_IDLE:
		_run_state_idle();
		break;
	case PH_STATE_PREP_DOWNLOAD:
		_run_state_prep_download();
		break;
	case PH_STATE_DOWNLOAD:
		_run_state_download();
		break;
	default:
		pv_log(WARN, "state not implemented");
	}
}

int pv_pantahub_start()
{
	pv_log(DEBUG, "starting Pantacor Hub client...");

	global_ph = calloc(1, sizeof(struct pv_pantahub));
	if (!global_ph)
		return -1;

	global_ph->state = PH_STATE_INIT;

	// load pantahub.config from vol or storage
	if (pv_config_load_creds()) {
		pv_log(ERROR, "creds load failed");
		return -1;
	}

	pv_event_one_shot(_run_state_cb);
}

void pv_pantahub_evaluate_state()
{
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	if (!pv_pantahub_proto_is_registered()) {
		_next_state(PH_STATE_REGISTER);
		return;
	}

	if (!pv_pantahub_proto_is_auth()) {
		_next_state(PH_STATE_LOGIN);
		return;
	}

	if (!pv_pantahub_proto_is_device_owned()) {
		_next_state(PH_STATE_CLAIM);
		return;
	}

	if (pv_pantahub_proto_is_trails_unknown()) {
		_next_state(PH_STATE_WAIT_HUB);
		return;
	}

	if (pv_pantahub_proto_is_trails_unsynced()) {
		_next_state(PH_STATE_SYNC);
		return;
	}

	if (!pv->update || pv_update_is_final()) {
		_next_state(PH_STATE_IDLE);
		return;
	}

	if (pv_pantahub_proto_is_any_progress_request_pending()) {
		pv_log(DEBUG,
		       "cannot leave state because still have progress request pending");
		return;
	}

	if (pv_update_is_queued()) {
		_next_state(PH_STATE_PREP_DOWNLOAD);
		return;
	}

	if (pv_update_is_downloading()) {
		_next_state(PH_STATE_DOWNLOAD);
		return;
	}

	if (pv_update_is_inprogress()) {
		_next_state(PH_STATE_REPORT);
		return;
	}
}

bool pv_pantahub_is_reporting()
{
	struct pv_pantahub *ph = _get_ph_instance();
	if (!ph)
		return false;

	if (!pv_pantahub_is_online())
		return false;

	return (ph->state == PH_STATE_REPORT);
}

bool pv_pantahub_is_online()
{
	return pv_pantahub_proto_is_online();
}

bool pv_pantahub_got_any_failure()
{
	return pv_pantahub_proto_got_any_failure();
}

bool pv_pantahub_is_device_claimed()
{
	return pv_pantahub_proto_is_device_owned();
}

bool pv_pantahub_is_progress_queue_empty()
{
	return !pv_pantahub_proto_is_any_progress_request_pending();
}

void pv_pantahub_queue_progress(const char *rev, const char *progress)
{
	if (!pv_pantahub_proto_is_auth()) {
		pv_log(DEBUG,
		       "will not try to put progress as session is not opened yet");
		return;
	}

	pv_pantahub_proto_queue_progress(rev, progress);
}
