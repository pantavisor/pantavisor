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

#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pantahub/pantahub.h"
#include "pantahub/pantahub_msg.h"
#include "pantahub/pantahub_proto.h"
#include "pantahub/pantahub_struct.h"

#include "event/event_rest.h"

#include "config.h"
#include "metadata.h"
#include "objects.h"
#include "paths.h"
#include "storage.h"

#include "update/update.h"

#include "utils/fs.h"
#include "utils/str.h"

#define MODULE_NAME "pantahub_proto"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define AUTH_JSON_LEN 128
#define BODY_MAX_LEN (1 << 21) // 2MiB

#define UNRESPONSIVE_REQUESTS_MAX 256

#define QUERY_PENDING_STEPS                                                    \
	"?progress.status=%7B%22$in%22:%5B%22NEW%22,%22DOWNLOADING%22,%22INPROGRESS%22,%22TESTING%22,%22QUEUED%22%5D%7D"

struct pv_progress {
	char *rev;
	char *body;
};

struct pv_object_transfer {
	const char *id_ref;
	bool active;
	struct dl_list list; // struct pv_object_transfer
};

typedef enum {
	PV_OBJECT_SYNC_PENDING,
	PV_OBJECT_SYNC_NEED_PUT,
	PV_OBJECT_SYNC_DONE
} pv_object_sync_state_t;

struct pv_object_sync {
	char *id;
	char *name;
	char *puturl;
	off_t size;
	bool active;
	pv_object_sync_state_t state;
	struct dl_list list;
};

typedef enum {
	PV_TRAILS_STATUS_UNKNOWN,
	PV_TRAILS_STATUS_UNSYNCED,
	PV_TRAILS_STATUS_SYNCED
} pv_trails_status_t;

struct pv_pantahub_session {
	char *token;
	bool owned;
	bool online;
	short failed_requests;
	bool any_failed_request;

	bool post_device_active;
	bool open_session_active;
	bool get_device_active;
	bool get_usrmeta_active;
	bool set_devmeta_active;
	bool get_trails_status_active;
	bool get_pending_steps_active;
	bool put_progress_active;

	struct pv_progress *next_progress;

	struct dl_list object_transfer_list; // struct pv_object_transfer

	pv_trails_status_t trails_status;

	bool sync_initialized;
	bool post_trail_active;
	bool synced;
	struct dl_list object_sync_list; // struct pv_object_sync
};

static struct pv_pantahub_session session;

void pv_pantahub_proto_init()
{
	session.token = NULL;
	session.owned = false;
	session.online = false;
	session.failed_requests = UNRESPONSIVE_REQUESTS_MAX;
	session.any_failed_request = false;

	session.post_device_active = false;
	session.open_session_active = false;
	session.get_device_active = false;
	session.get_usrmeta_active = false;
	session.set_devmeta_active = false;
	session.get_trails_status_active = false;
	session.get_pending_steps_active = false;
	session.put_progress_active = false;

	session.next_progress = NULL;

	dl_list_init(&session.object_transfer_list);

	session.trails_status = PV_TRAILS_STATUS_UNKNOWN;

	session.sync_initialized = false;
	session.post_trail_active = false;
	session.synced = false;
	dl_list_init(&session.object_sync_list);
}

static void _free_object_transfer_list(struct dl_list *l)
{
	struct pv_object_transfer *o, *tmp;

	if (!l)
		return;

	dl_list_for_each_safe(o, tmp, l, struct pv_object_transfer, list)
	{
		dl_list_del(&o->list);
		free(o);
	}
}

static bool _is_object_transfer_list_empty()
{
	return dl_list_empty(&session.object_transfer_list);
}

static void _add_object_transfer(const char *id_ref)
{
	struct pv_object_transfer *o;

	if (!id_ref)
		return;

	o = calloc(1, sizeof(struct pv_object_transfer));
	if (!o)
		return;

	o->id_ref = id_ref;

	dl_list_add_tail(&session.object_transfer_list, &o->list);
}

static int _init_object_transfer_unrecorded()
{
	char **objects = NULL, **o;

	if (!_is_object_transfer_list_empty())
		return 0;

	pv_update_get_unrecorded_objects(&objects);
	if (!objects) {
		pv_log(WARN, "could not retrieve unrecorded objects");
		return -1;
	}

	o = objects;
	while (*o) {
		_add_object_transfer(*o);
		o++;
	}

	if (objects)
		free(objects);

	return 0;
}

static int _init_object_transfer_unavailable()
{
	char **objects = NULL, **o;

	if (!_is_object_transfer_list_empty())
		return 0;

	pv_update_get_unavailable_objects(&objects);
	if (!objects) {
		pv_log(WARN, "could not retrieve unavailable objects");
		return -1;
	}

	o = objects;
	while (*o) {
		_add_object_transfer(*o);
		o++;
	}

	if (objects)
		free(objects);

	return 0;
}

static struct pv_object_transfer *_search_object_transfer(const char *id_ref)
{
	struct pv_object_transfer *o, *tmp;

	if (!id_ref)
		return NULL;

	dl_list_for_each_safe(o, tmp, &session.object_transfer_list,
			      struct pv_object_transfer, list)
	{
		if (id_ref == o->id_ref)
			return o;
	}

	return NULL;
}

static void _remove_object_transfer(const char *id_ref)
{
	struct pv_object_transfer *o;

	if (!id_ref)
		return;

	o = _search_object_transfer(id_ref);
	if (!o)
		return;

	dl_list_del(&o->list);
	free(o);
}

void _free_token()
{
	if (session.token)
		free(session.token);
	session.token = NULL;

	pv_log(DEBUG, "removed token");
}

void pv_pantahub_proto_close()
{
	_free_object_transfer_list(&session.object_transfer_list);
	_free_token();
	pv_pantahub_proto_free_sync();
}

void pv_pantahub_proto_reset_fail()
{
	session.any_failed_request = false;
}

void pv_pantahub_proto_reset_trails_status()
{
	session.trails_status = PV_TRAILS_STATUS_UNKNOWN;
}

bool pv_pantahub_proto_is_online()
{
	return session.online;
}

bool pv_pantahub_proto_got_any_failure()
{
	return session.any_failed_request;
}

bool pv_pantahub_proto_is_any_progress_request_pending()
{
	return session.put_progress_active || session.next_progress;
}

bool pv_pantahub_proto_is_trails_unknown()
{
	return (session.trails_status == PV_TRAILS_STATUS_UNKNOWN);
}

bool pv_pantahub_proto_is_trails_unsynced()
{
	return (session.trails_status == PV_TRAILS_STATUS_UNSYNCED);
}

static int _send_by_endpoint(enum evhttp_cmd_type op, const char *endpoint,
			     const char *autotok, const char *token,
			     const char *body,
			     void (*cb)(struct evhttp_request *, void *),
			     void *arg)
{
	char *host;
	int port;

	host = pv_config_get_str(PH_CREDS_PROXY_HOST);
	port = pv_config_get_int(PH_CREDS_PROXY_PORT);
	if (!host) {
		host = pv_config_get_str(PH_CREDS_HOST);
		port = pv_config_get_int(PH_CREDS_PORT);
	}

	return pv_event_rest_send_by_components(
		op, host, port, endpoint, autotok, token, body, NULL, cb, arg);
}

static void _on_request_unresponsive()
{
	char path[PATH_MAX];

	session.any_failed_request = true;

	// this prevents overflow
	if (session.failed_requests < UNRESPONSIVE_REQUESTS_MAX)
		session.failed_requests++;

	// threshold not yet reached
	if (session.failed_requests <=
	    pv_config_get_int(PH_ONLINE_REQUEST_THRESHOLD))
		return;

	if (!pv_pantahub_proto_is_online())
		return;

	pv_log(DEBUG, "Pantacor Hub client is now offline");
	session.online = false;

	// update devmeta key
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_ONLINE, "0");
}

static void _on_request_responsive()
{
	int fd;
	char path[PATH_MAX];

	if (pv_pantahub_proto_is_online())
		goto out;

	pv_log(DEBUG, "Pantacor Hub client is now online");
	session.online = true;

	// update devmeta key
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_ONLINE, "1");
out:
	session.failed_requests = 0;
}

static int _recv_buffer(struct evhttp_request *req, char **body)
{
	int res;

	res = pv_event_rest_recv_buffer(req, body, BODY_MAX_LEN);
	if (res == -1) {
		pv_log(WARN, "did not get any response");
		_on_request_unresponsive();
		return -1;
	}

	_on_request_responsive();

	if (res == 401) {
		pv_log(WARN, "unauthorized");
		_free_token();
		return -1;
	} else if (res != 200) {
		pv_log(WARN, "returned %d", res);
		return -1;
	}

	return 0;
}

static void _recv_post_device_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL;
	struct pv_device device;
	memset(&device, 0, sizeof(device));

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_post_device_cb);

	session.post_device_active = false;

	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "POST device failed");
		goto out;
	}
	if (!body) {
		pv_log(WARN, "POST device received empty body");
		goto out;
	}

	if (pv_pantahub_msg_parse_device(body, &device)) {
		pv_log(WARN, "could not parse device");
		goto out;
	}

	if (!device.id) {
		pv_log(WARN, "POST device returned no id");
		goto out;
	}

	if (!device.prn) {
		pv_log(WARN, "POST device returned no prn");
		goto out;
	}

	if (!device.secret) {
		pv_log(WARN, "POST device returned no secret");
		goto out;
	}

	pv_config_set_creds_id(device.id);
	pv_config_set_creds_prn(device.prn);
	pv_config_set_creds_secret(device.secret);
	pv_config_save_creds();

out:
	if (body)
		free(body);
	pv_pantahub_msg_clean_device(&device);
	pv_pantahub_evaluate_state();
}

void pv_pantahub_proto_post_device()
{
	pv_log(DEBUG, "registering new device...");

	if (session.post_device_active) {
		pv_log(DEBUG, "post device request pending. skipping...");
		return;
	}

	const char *uri = "/devices/";

	if (!_send_by_endpoint(EVHTTP_REQ_POST, uri,
			       pv_config_get_str(PH_FACTORY_AUTOTOK), NULL,
			       NULL, _recv_post_device_cb, NULL))
		session.post_device_active = true;
}

bool pv_pantahub_proto_is_registered()
{
	const char *id = pv_config_get_str(PH_CREDS_ID);
	const char *prn = pv_config_get_str(PH_CREDS_PRN);
	const char *secret = pv_config_get_str(PH_CREDS_SECRET);

	return id && strlen(id) && prn && strlen(prn) && secret &&
	       strlen(secret);
}

static void _recv_post_auth_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL;

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_post_auth_cb);

	session.open_session_active = 0;

	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "POST auth failed");
		goto out;
	}
	if (!body) {
		pv_log(WARN, "POST auth received empty body");
		goto out;
	}

	session.token = pv_pantahub_msg_parse_session_token(body);
	if (session.token)
		pv_log(DEBUG, "got new token");

out:
	if (body)
		free(body);
	pv_pantahub_evaluate_state();
}

void pv_pantahub_proto_post_auth()
{
	pv_log(DEBUG, "opening new session...");

	if (session.token) {
		pv_log(ERROR, "session must be closed first");
		return;
	}

	if (session.open_session_active) {
		pv_log(DEBUG,
		       "open_session_active = true; skip sending another request...");
		return;
	}

	const char *uri = "/auth/login";

	char *body = pv_pantahub_msg_ser_login_json(
		pv_config_get_str(PH_CREDS_PRN),
		pv_config_get_str(PH_CREDS_SECRET));
	if (!body) {
		pv_log(ERROR, "could not serialize session auth JSON");
		return;
	}

	if (!_send_by_endpoint(EVHTTP_REQ_POST, uri, NULL, NULL, body,
			       _recv_post_auth_cb, NULL))
		session.open_session_active = 1;

	free(body);
}

bool pv_pantahub_proto_is_auth()
{
	return session.token;
}

void _save_hint(const char *challenge)
{
	char buf[256], path[PATH_MAX];

	pv_paths_pv_file(path, PATH_MAX, DEVICE_ID_FNAME);
	SNPRINTF_WTRUNC(buf, sizeof(buf), "%s\n",
			pv_config_get_str(PH_CREDS_ID));
	if (pv_fs_file_save(path, buf, 0444))
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	if (!challenge)
		return;

	pv_paths_pv_file(path, PATH_MAX, CHALLENGE_FNAME);
	SNPRINTF_WTRUNC(buf, sizeof(buf), "%s\n", challenge);
	if (pv_fs_file_save(path, buf, 0444))
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));
}

static void _recv_get_device_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL;
	struct pv_device device;
	memset(&device, 0, sizeof(device));

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_get_device_cb);

	session.get_device_active = false;

	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "GET device failed");
		goto out;
	}
	if (!body) {
		pv_log(WARN, "GET device received empty body");
		goto out;
	}

	if (pv_pantahub_msg_parse_device(body, &device)) {
		pv_log(WARN, "could not parse device");
		goto out;
	}

	if (device.owner && strlen(device.owner)) {
		pv_log(DEBUG, "device successfuly claimed");
		pv_metadata_add_devmeta(DEVMETA_KEY_PH_CLAIMED, "1");
		session.owned = true;
		goto out;
	}
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_CLAIMED, "0");

	if (device.challenge) {
		pv_log(DEBUG, "device ID: '%s'", device.id);
		pv_log(DEBUG, "challenge: '%s'", device.challenge);
		_save_hint(device.challenge);
	}
out:
	if (body)
		free(body);
	pv_pantahub_msg_clean_device(&device);
	pv_pantahub_evaluate_state();
}

void pv_pantahub_proto_get_device()
{
	pv_log(DEBUG, "checking device in Hub");

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}
	if (session.get_device_active) {
		pv_log(DEBUG,
		       "get_usrmeta_active = true; skip sending another request...");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/devices/%s",
		 pv_config_get_str(PH_CREDS_ID));

	if (!_send_by_endpoint(EVHTTP_REQ_GET, uri, NULL, session.token, NULL,
			       _recv_get_device_cb, NULL))
		session.get_device_active = true;
}

bool pv_pantahub_proto_is_device_owned()
{
	return session.owned;
}

static void _recv_get_usrmeta_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_recv_get_usrmeta_cb);

	session.get_usrmeta_active = 0;

	char *body = NULL;
	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "GET usrmeta failed");
		goto out;
	}
	if (!body) {
		pv_log(WARN, "GET usrmeta received empty body");
		goto out;
	}

	pv_metadata_parse_usermeta(body);

	pv_log(DEBUG, "usrmeta updated from Hub");
out:
	if (body)
		free(body);
	pv_pantahub_evaluate_state();
}

static void _recv_get_trails_status_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL;

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_get_trails_status_cb);

	session.get_trails_status_active = 0;

	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "GET trails_status failed");
		goto out;
	}
	if (!body) {
		pv_log(WARN, "GET trails_status received empty body");
		goto out;
	}

	if (pv_pantahub_msg_parse_trails(body)) {
		pv_log(DEBUG, "device not yet synced with Hub");
		session.trails_status = PV_TRAILS_STATUS_UNSYNCED;
		goto out;
	}

	pv_log(DEBUG, "device is synced with Hub");
	session.trails_status = PV_TRAILS_STATUS_SYNCED;
out:
	if (body)
		free(body);
	pv_pantahub_evaluate_state();
}

void pv_pantahub_proto_get_trails_status()
{
	pv_log(DEBUG, "checking trails available in Hub");

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}
	if (session.get_trails_status_active) {
		pv_log(DEBUG,
		       "get_usrmeta_active = true; skip sending another request...");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/trails/");

	if (!_send_by_endpoint(EVHTTP_REQ_GET, uri, NULL, session.token, NULL,
			       _recv_get_trails_status_cb, NULL))
		session.get_trails_status_active = 1;
}

void pv_pantahub_proto_get_usrmeta()
{
	pv_log(DEBUG, "requesting usrmeta from Hub");

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}

	if (session.get_usrmeta_active) {
		pv_log(DEBUG,
		       "get_usrmeta_active = true; skip sending another request...");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/devices/%s/user-meta",
		 pv_config_get_str(PH_CREDS_ID));

	if (!_send_by_endpoint(EVHTTP_REQ_GET, uri, NULL, session.token, NULL,
			       _recv_get_usrmeta_cb, NULL))
		session.get_usrmeta_active = 1;
}

static void _recv_set_devmeta_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_recv_set_devmeta_cb);

	session.set_devmeta_active = 0;

	char *body = NULL;
	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "PUT devmeta failed");
		goto out;
	}

	pv_log(DEBUG, "devmeta updated in Hub");
out:
	if (body)
		free(body);
	pv_pantahub_evaluate_state();
}

void pv_pantahub_proto_set_devmeta()
{
	pv_log(DEBUG, "sending devmeta to Hub");

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}

	if (session.set_devmeta_active) {
		pv_log(DEBUG,
		       "set_devmeta_active = true; skip sending another request...");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/devices/%s/device-meta",
		 pv_config_get_str(PH_CREDS_ID));

	char *json = pv_metadata_get_device_meta_string();
	if (!json) {
		pv_log(ERROR, "could not get devmeta JSON");
		return;
	}

	if (!_send_by_endpoint(EVHTTP_REQ_PUT, uri, NULL, session.token, json,
			       _recv_set_devmeta_cb, NULL))
		session.set_devmeta_active = 1;

out:
	free(json);
}

static void _recv_get_pending_steps_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL, *state_json = NULL;
	struct pv_step step;
	memset(&step, 0, sizeof(step));
	pv_log(TRACE, "run event: cb=%p", (void *)_recv_get_pending_steps_cb);

	session.get_pending_steps_active = 0;

	// if there is an update and its not final we dont process more steps
	if (pv_update_get_rev() && !pv_update_is_final()) {
		pv_log(WARN,
		       "update is still not finished. defering to process new steps from hub ...");
		return;
	}

	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "GET pending steps auth failed");
		goto out;
	}
	if (!body) {
		pv_log(WARN, "GET pending steps received empty body");
		goto out;
	}

	state_json = pv_pantahub_msg_parse_next_step(body);
	if (!state_json)
		goto out;

	pv_pantahub_msg_parse_step(state_json, &step);
	if (!step.rev) {
		pv_log(WARN, "could not parse rev from step");
		goto out;
	}

	pv_pantahub_msg_print_step(&step);
	pv_update_start_install(step.rev, step.progress, step.state,
				pv_pantahub_queue_progress);
out:
	pv_pantahub_msg_clean_step(&step);
	if (state_json)
		free(state_json);
	if (body)
		free(body);
	pv_pantahub_evaluate_state();
}

void pv_pantahub_proto_get_pending_steps()
{
	pv_log(DEBUG, "requesting for pending steps from Hub");

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}

	if (session.get_pending_steps_active) {
		pv_log(DEBUG,
		       "get_pending_steps_active; skip sending another request...");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/trails/%s/steps%s",
		 pv_config_get_str(PH_CREDS_ID), QUERY_PENDING_STEPS);

	if (!_send_by_endpoint(EVHTTP_REQ_GET, uri, NULL, session.token, NULL,
			       _recv_get_pending_steps_cb, NULL))
		session.get_pending_steps_active = 1;
}

void pv_pantahub_proto_init_object_transfer()
{
	if (!_is_object_transfer_list_empty())
		pv_log(WARN, "object transfer list found not empty");

	_free_object_transfer_list(&session.object_transfer_list);
}

static void _recv_get_object_metadata_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL;
	int res;
	const char *id_ref = (char *)ctx;

	struct pv_object_metadata object_metadata;
	memset(&object_metadata, 0, sizeof(object_metadata));

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_get_object_metadata_cb);

	_remove_object_transfer(id_ref);

	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "GET object metadata failed");
		goto out;
	}
	if (!body) {
		pv_log(WARN, "GET object metadata received empty body");
		goto out;
	}

	pv_pantahub_msg_parse_object_metadata(body, &object_metadata);
	if (!object_metadata.geturl) {
		pv_log(WARN, "could not parse object metadata");
		goto out;
	}
	pv_pantahub_msg_print_object_metadata(&object_metadata);

	pv_update_set_object_metadata(object_metadata.sha256sum,
				      object_metadata.size,
				      object_metadata.geturl);

	pv_log(DEBUG, "object metadata updated from Hub");
out:
	pv_pantahub_msg_clean_object_metadata(&object_metadata);
	if (body)
		free(body);
	pv_pantahub_evaluate_state();
}

static int _get_object_metadata(const char *id_ref)
{
	pv_log(DEBUG, "requesting object '%s' metadata from Hub", id_ref);

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return -1;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/objects/%s", id_ref);

	return _send_by_endpoint(EVHTTP_REQ_GET, uri, NULL, session.token, NULL,
				 _recv_get_object_metadata_cb, (void *)id_ref);
}

int pv_pantahub_proto_get_objects_metadata()
{
	int ret = -1;
	unsigned int count = 0;
	struct pv_object_transfer *o, *tmp;

	if (_init_object_transfer_unrecorded()) {
		pv_log(WARN,
		       "could not init object transfer list with unrecorded objects");
		return -1;
	}

	dl_list_for_each_safe(o, tmp, &session.object_transfer_list,
			      struct pv_object_transfer, list)
	{
		if (!o->active) {
			if (!_get_object_metadata(o->id_ref))
				o->active = true;
		}

		count++;
		if (count >= pv_config_get_int(PH_UPDATER_TRANSFER_MAX_COUNT))
			break;
	}

	return 0;
}

static void _recv_get_object_chunk_cb(struct evhttp_request *req, void *ctx)
{
	char path[PATH_MAX];
	int res;
	const char *id_ref = (char *)ctx;

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_get_object_chunk_cb);

	pv_storage_set_object_download_path(path, PATH_MAX, id_ref);
	pv_event_rest_recv_chunk_path(req, path);
}

static void _recv_get_object_done_cb(struct evhttp_request *req, void *ctx)
{
	char path[PATH_MAX];
	int res;
	const char *id_ref = (char *)ctx;

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_get_object_done_cb);

	_remove_object_transfer(id_ref);

	pv_storage_set_object_download_path(path, PATH_MAX, id_ref);
	res = pv_event_rest_recv_done_path(req, path);
	if (res == 401) {
		pv_log(WARN, "GET object unauthorized", res);
		_free_token();
		goto out;
	}
	if (res != 200) {
		pv_log(WARN, "GET object returned %d", res);
		goto out;
	}
	pv_log(DEBUG, "object downloaded from Hub");

	if (pv_update_install_object(path)) {
		pv_log(WARN, "object download failed");
		goto out;
	}
out:
	pv_fs_path_remove(path, false);
	pv_pantahub_evaluate_state();
}

static int _get_object(const char *geturl, const char *id_ref)
{
	char path[PATH_MAX];

	if (!geturl || !id_ref)
		return -1;

	pv_storage_set_object_download_path(path, PATH_MAX, id_ref);
	pv_fs_path_remove(path, true);

	pv_log(DEBUG, "requesting object '%s' from Hub", id_ref);

	return pv_event_rest_send_by_url(EVHTTP_REQ_GET, geturl,
					 _recv_get_object_chunk_cb,
					 _recv_get_object_done_cb,
					 (void *)id_ref);
}

int pv_pantahub_proto_get_objects()
{
	int ret = -1;
	unsigned int count = 0;
	char *geturl;
	struct pv_object_transfer *o, *tmp;

	if (_init_object_transfer_unavailable()) {
		pv_log(WARN,
		       "could not init object transfer list with unavailable objects");
		return -1;
	}

	dl_list_for_each_safe(o, tmp, &session.object_transfer_list,
			      struct pv_object_transfer, list)
	{
		if (!o->active) {
			geturl = pv_update_get_object_geturl(o->id_ref);
			if (!_get_object(geturl, o->id_ref))
				o->active = true;
		}

		count++;
		if (count >= pv_config_get_int(PH_UPDATER_TRANSFER_MAX_COUNT))
			break;
	}

	return 0;
}

static struct pv_progress *_new_progress(const char *rev, const char *progress)
{
	struct pv_progress *p;
	p = calloc(1, sizeof(struct pv_progress));
	if (!p)
		return NULL;

	p->rev = strdup(rev);
	p->body = strdup(progress);

	return p;
}

static void _free_progress(struct pv_progress *p)
{
	if (!p)
		return;

	if (p->rev)
		free(p->rev);
	if (p->body)
		free(p->body);
	free(p);
}

static void _put_progress(const char *rev, const char *progress);

static void _recv_put_progress_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(TRACE, "run event: cb=%p", (void *)_recv_put_progress_cb);

	session.put_progress_active = false;
	if (session.next_progress) {
		// we are done with the current progress, so we send request for queued one
		pv_log(DEBUG, "clearing progress queue");
		_put_progress(session.next_progress->rev,
			      session.next_progress->body);
		_free_progress(session.next_progress);
		session.next_progress = NULL;
	}

	char *body = NULL;
	if (_recv_buffer(req, &body)) {
		pv_log(WARN, "PUT progress failed");
		goto out;
	}

	pv_log(DEBUG, "progress updated in Hub");
out:
	if (body)
		free(body);
	pv_pantahub_evaluate_state();
}

static void _put_progress(const char *rev, const char *progress)
{
	if (!rev || !progress)
		return;

	pv_log(DEBUG, "sending progress to Hub");

	if (!session.token) {
		pv_log(WARN, "session must be opened first");
		return;
	}

	char uri[4096];
	snprintf(uri, sizeof(uri), "/trails/%s/steps/%s/progress",
		 pv_config_get_str(PH_CREDS_ID), rev);

	if (!_send_by_endpoint(EVHTTP_REQ_PUT, uri, NULL, session.token,
			       progress, _recv_put_progress_cb, NULL))
		session.put_progress_active = true;
}

void pv_pantahub_proto_queue_progress(const char *rev, const char *progress)
{
	struct pv_progress *p;

	if (!rev || !progress)
		return;

	if (!session.put_progress_active) {
		_put_progress(rev, progress);
		// put failed, but we have another progress in queue
		if (!session.put_progress_active && session.next_progress) {
			pv_log(DEBUG, "clearing progress queue");
			_put_progress(session.next_progress->rev,
				      session.next_progress->body);
			_free_progress(session.next_progress);
			session.next_progress = NULL;
		}
	} else {
		pv_log(DEBUG, "queueing progress");
		// discard any queued progress to make room for new one
		_free_progress(session.next_progress);
		session.next_progress = _new_progress(rev, progress);
	}
}

/* --- sync functions --- */

static void _free_object_sync_list()
{
	struct pv_object_sync *o, *tmp;

	dl_list_for_each_safe(o, tmp, &session.object_sync_list,
			      struct pv_object_sync, list)
	{
		dl_list_del(&o->list);
		if (o->id)
			free(o->id);
		if (o->name)
			free(o->name);
		if (o->puturl)
			free(o->puturl);
		free(o);
	}
}

void pv_pantahub_proto_free_sync()
{
	_free_object_sync_list();
	session.sync_initialized = false;
	session.post_trail_active = false;
	session.synced = false;
}

void pv_pantahub_proto_init_sync()
{
	struct pantavisor *pv;
	struct pv_object *o;
	struct pv_object_sync *s;
	char objpath[PATH_MAX];
	struct stat st;

	if (session.sync_initialized)
		return;

	pv = pv_get_instance();
	if (!pv || !pv->state) {
		pv_log(ERROR, "no pantavisor state available");
		return;
	}

	pv_objects_iter_begin(pv->state, o)
	{
		pv_paths_storage_object(objpath, PATH_MAX, o->id);
		if (stat(objpath, &st) < 0) {
			pv_log(WARN, "could not stat object '%s'", o->id);
			continue;
		}

		s = calloc(1, sizeof(struct pv_object_sync));
		if (!s)
			continue;

		s->id = strdup(o->id);
		s->name = strdup(o->name);
		s->size = st.st_size;
		s->state = PV_OBJECT_SYNC_PENDING;
		s->active = false;
		s->puturl = NULL;

		dl_list_add_tail(&session.object_sync_list, &s->list);
	}
	pv_objects_iter_end;

	session.sync_initialized = true;
	pv_log(DEBUG, "sync initialized");
}

static void _recv_post_object_cb(struct evhttp_request *req, void *ctx)
{
	struct pv_object_sync *s = (struct pv_object_sync *)ctx;
	char *body = NULL;
	int res;

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_post_object_cb);

	s->active = false;

	if (!req) {
		pv_log(WARN, "POST object '%s': no response", s->id);
		_on_request_unresponsive();
		goto out;
	}

	res = pv_event_rest_recv_buffer(req, &body, BODY_MAX_LEN);
	if (res == -1) {
		pv_log(WARN, "POST object '%s': no response", s->id);
		_on_request_unresponsive();
		goto out;
	}

	_on_request_responsive();

	if (res == 409) {
		pv_log(INFO, "object '%s' already owned by user, skipping",
		       s->id);
		s->state = PV_OBJECT_SYNC_DONE;
	} else if (res == 200) {
		char *puturl = pv_pantahub_msg_parse_object_puturl(body);
		if (!puturl) {
			pv_log(WARN,
			       "POST object '%s': no puturl in response",
			       s->id);
			goto out;
		}
		if (s->puturl)
			free(s->puturl);
		s->puturl = puturl;
		s->state = PV_OBJECT_SYNC_NEED_PUT;
		pv_log(DEBUG, "object '%s' registered, need PUT", s->id);
	} else if (res == 401) {
		pv_log(WARN, "POST object '%s': unauthorized", s->id);
		_free_token();
		pv_pantahub_evaluate_state();
	} else {
		pv_log(WARN, "POST object '%s': returned %d, will retry",
		       s->id, res);
	}

out:
	if (body)
		free(body);
}

int pv_pantahub_proto_post_objects()
{
	struct pv_object_sync *o, *tmp;
	unsigned int count = 0;
	bool all_done = true;
	char uri[512];
	char body[512];

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return -1;
	}

	dl_list_for_each_safe(o, tmp, &session.object_sync_list,
			      struct pv_object_sync, list)
	{
		if (o->state == PV_OBJECT_SYNC_PENDING) {
			all_done = false;
			if (!o->active) {
				SNPRINTF_WTRUNC(body, sizeof(body),
						"{ \"objectname\": \"%s\","
						" \"size\": \"%jd\","
						" \"sha256sum\": \"%s\""
						" }",
						o->name, (intmax_t)o->size,
						o->id);

				snprintf(uri, sizeof(uri), "/objects/");

				if (!_send_by_endpoint(EVHTTP_REQ_POST, uri,
						       NULL, session.token,
						       body,
						       _recv_post_object_cb,
						       o)) {
					o->active = true;
					count++;
					if (count >= (unsigned int)pv_config_get_int(
							     PH_UPDATER_TRANSFER_MAX_COUNT))
						break;
				}
			} else {
				count++;
			}
		} else if (o->state == PV_OBJECT_SYNC_NEED_PUT) {
			all_done = false;
		}
	}

	return all_done ? 1 : 0;
}

static void _recv_put_object_cb(struct evhttp_request *req, void *ctx)
{
	struct pv_object_sync *s = (struct pv_object_sync *)ctx;
	int res;

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_put_object_cb);

	s->active = false;

	if (!req) {
		pv_log(WARN, "PUT object '%s': no response", s->id);
		_on_request_unresponsive();
		return;
	}

	res = pv_event_rest_recv_buffer(req, NULL, 0);
	if (res == -1) {
		pv_log(WARN, "PUT object '%s': no response", s->id);
		_on_request_unresponsive();
		return;
	}

	_on_request_responsive();

	if (res == 200) {
		pv_log(INFO, "object '%s' uploaded", s->id);
		s->state = PV_OBJECT_SYNC_DONE;
	} else if (res == 401) {
		pv_log(WARN, "PUT object '%s': unauthorized", s->id);
		_free_token();
		pv_pantahub_evaluate_state();
	} else {
		pv_log(WARN,
		       "PUT object '%s': returned %d, will retry (puturl may have expired)",
		       s->id, res);
		/* reset to PENDING so we re-register and get a fresh puturl */
		s->state = PV_OBJECT_SYNC_PENDING;
		if (s->puturl) {
			free(s->puturl);
			s->puturl = NULL;
		}
	}
}

int pv_pantahub_proto_put_objects()
{
	struct pv_object_sync *o, *tmp;
	unsigned int count = 0;
	bool all_done = true;
	char objpath[PATH_MAX];

	dl_list_for_each_safe(o, tmp, &session.object_sync_list,
			      struct pv_object_sync, list)
	{
		if (o->state != PV_OBJECT_SYNC_DONE)
			all_done = false;

		if (o->state == PV_OBJECT_SYNC_NEED_PUT && !o->active) {
			pv_paths_storage_object(objpath, PATH_MAX, o->id);

			if (!pv_event_rest_send_file_by_url(
				    o->puturl, objpath, o->size,
				    _recv_put_object_cb, o)) {
				o->active = true;
				count++;
				if (count >= (unsigned int)pv_config_get_int(
						     PH_UPDATER_TRANSFER_MAX_COUNT))
					break;
			}
		}
	}

	return all_done ? 1 : 0;
}

static void _recv_post_trail_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL;
	int res;

	pv_log(TRACE, "run event: cb=%p", (void *)_recv_post_trail_cb);

	session.post_trail_active = false;

	if (!req) {
		pv_log(WARN, "POST /trails/: no response");
		_on_request_unresponsive();
		return;
	}

	res = pv_event_rest_recv_buffer(req, &body, BODY_MAX_LEN);
	if (res == -1) {
		pv_log(WARN, "POST /trails/: no response");
		_on_request_unresponsive();
		goto out;
	}

	_on_request_responsive();

	if (res == 200) {
		pv_log(INFO, "factory revision pushed to Hub");
		session.synced = true;
	} else if (res == 401) {
		pv_log(WARN, "POST /trails/: unauthorized");
		_free_token();
		pv_pantahub_evaluate_state();
	} else {
		pv_log(WARN, "POST /trails/: returned %d, will retry", res);
	}

out:
	if (body)
		free(body);
}

void pv_pantahub_proto_post_trail()
{
	struct pantavisor *pv;
	char *json;

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}

	if (session.post_trail_active) {
		pv_log(DEBUG, "post_trail already active, skipping");
		return;
	}

	pv = pv_get_instance();
	if (!pv || !pv->state) {
		pv_log(ERROR, "no pantavisor state available");
		return;
	}

	json = pv_storage_get_state_json(pv->state->rev);
	if (!json) {
		pv_log(ERROR, "could not read state json");
		return;
	}

	if (!_send_by_endpoint(EVHTTP_REQ_POST, "/trails/", NULL,
			       session.token, json, _recv_post_trail_cb,
			       NULL)) {
		session.post_trail_active = true;
		pv_log(DEBUG, "POST /trails/ sent");
	}

	free(json);
}

bool pv_pantahub_proto_is_synced()
{
	return session.synced;
}
