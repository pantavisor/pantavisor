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
#include <unistd.h>

#include "pantahub/pantahub.h"
#include "pantahub/pantahub_msg.h"
#include "pantahub/pantahub_proto.h"
#include "pantahub/pantahub_struct.h"

#include "event/event_rest.h"

#include "config.h"
#include "metadata.h"
#include "paths.h"
#include "storage.h"

#include "update/update.h"

#include "utils/fs.h"
#include "utils/str.h"

#define MODULE_NAME "pantahub_proto"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define AUTH_JSON_LEN 128
#define BODY_MAX_LEN (1 << 21) // 2MiB

#define UNRESPONSIVE_REQUESTS_MAX 256

#define QUERY_PENDING_STEPS                                                    \
	"?progress.status=%7B%22$in%22:%5B%22NEW%22,%22DOWNLOADING%22,%22INPROGRESS%22,%22TESTING%22,%22QUEUED%22%5D%7D"

typedef enum {
	PV_TRAILS_STATUS_UNKNOWN,
	PV_TRAILS_STATUS_UNSYNCED,
	PV_TRAILS_STATUS_SYNCED
} pv_trails_status_t;

struct pv_object_transfer {
	char *id;
	bool active;
	struct dl_list list; // struct pv_object_transfer
};

struct pv_pantahub_session {
	char *token;
	bool online;
	short failed_requests;
	bool any_failed_request;

	char *current_progress;
	char *current_uri;
	char *next_progress;
	char *next_uri;

	bool get_usrmeta_active;
	bool set_devmeta_active;
	bool get_trails_status_active;
	bool get_pending_steps_active;
	bool open_session_active;

	pv_trails_status_t trails_status;

	struct dl_list object_transfer_list; // struct pv_object_transfer
};

static struct pv_pantahub_session session;

void pv_pantahub_proto_init()
{
	session.token = NULL;
	session.online = false;
	session.failed_requests = UNRESPONSIVE_REQUESTS_MAX;
	session.any_failed_request = false;

	session.trails_status = PV_TRAILS_STATUS_UNKNOWN;

	dl_list_init(&session.object_transfer_list);
}

static void _free_object_transfer(struct pv_object_transfer *o)
{
	if (!o)
		return;

	if (o->id)
		free(o->id);
}

static void _free_object_transfer_list(struct dl_list *l)
{
	struct pv_object_transfer *o, *tmp;

	if (!l)
		return;

	dl_list_for_each_safe(o, tmp, l, struct pv_object_transfer, list)
	{
		dl_list_del(&o->list);
		_free_object_transfer(o);
	}
}

static bool _is_object_transfer_list_empty()
{
	return dl_list_empty(&session.object_transfer_list);
}

static void _add_object_transfer(const char *id)
{
	struct pv_object_transfer *o;

	if (!id)
		return;

	o = calloc(1, sizeof(struct pv_object_transfer));
	if (!o)
		return;

	o->id = strdup(id);

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

static struct pv_object_transfer *_search_object_transfer(const char *id)
{
	struct pv_object_transfer *o, *tmp;

	if (!id)
		return NULL;

	dl_list_for_each_safe(o, tmp, &session.object_transfer_list,
			      struct pv_object_transfer, list)
	{
		if (pv_str_matches(id, strlen(id), o->id, strlen(o->id)))
			return o;
	}

	return NULL;
}

static void _remove_object_transfer(const char *id)
{
	struct pv_object_transfer *o;

	if (!id)
		return;

	o = _search_object_transfer(id);
	if (!o)
		return;

	dl_list_del(&o->list);
	_free_object_transfer(o);
}

void pv_pantahub_proto_close()
{
	_free_object_transfer_list(&session.object_transfer_list);
	pv_pantahub_proto_close_session();
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
	return session.current_progress || session.next_progress;
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
			     const char *token, const char *body,
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

	return pv_event_rest_send_by_components(op, host, port, endpoint, token,
						body, NULL, cb, arg);
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
		pv_pantahub_proto_close_session();
		return -1;
	} else if (res != 200) {
		pv_log(WARN, "returned %d", res);
		return -1;
	}

	return 0;
}

static void _recv_post_auth_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL;

	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_post_auth_cb);

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
		pv_log(DEBUG, "new session opened");

out:
	if (body)
		free(body);
}

void pv_pantahub_proto_open_session()
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

	// on success remember active
	if (!_send_by_endpoint(EVHTTP_REQ_POST, uri, NULL, body,
			       _recv_post_auth_cb, NULL))
		session.open_session_active = 1;

	free(body);
}

bool pv_pantahub_proto_is_session_open()
{
	return session.token;
}

void pv_pantahub_proto_close_session()
{
	if (session.token)
		free(session.token);
	session.token = NULL;

	pv_log(DEBUG, "session closed");
}

static void _recv_get_usrmeta_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_usrmeta_cb);

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
}

static void _recv_get_trails_status_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL, *state_json = NULL;
	struct pv_step step;
	memset(&step, 0, sizeof(step));

	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_trails_status_cb);

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

	if (!_send_by_endpoint(EVHTTP_REQ_GET, uri, session.token, NULL,
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

	if (!_send_by_endpoint(EVHTTP_REQ_GET, uri, session.token, NULL,
			       _recv_get_usrmeta_cb, NULL))
		session.get_usrmeta_active = 1;
}

static void _recv_set_devmeta_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_set_devmeta_cb);

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

	if (!_send_by_endpoint(EVHTTP_REQ_PUT, uri, session.token, json,
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
	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_pending_steps_cb);

	session.get_pending_steps_active = 0;

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
				pv_pantahub_put_progress);
out:
	pv_pantahub_msg_clean_step(&step);
	if (state_json)
		free(state_json);
	if (body)
		free(body);
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

	if (!_send_by_endpoint(EVHTTP_REQ_GET, uri, session.token, NULL,
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
	const char *id = (char *)ctx;

	struct pv_object_metadata object_metadata;
	memset(&object_metadata, 0, sizeof(object_metadata));

	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_object_metadata_cb);

	_remove_object_transfer(id);

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
}

static void _get_object_metadata(const char *id)
{
	pv_log(DEBUG, "requesting object '%s' metadata from Hub", id);

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/objects/%s", id);

	_send_by_endpoint(EVHTTP_REQ_GET, uri, session.token, NULL,
			  _recv_get_object_metadata_cb, (void *)id);
}

int pv_pantahub_proto_get_objects_metadata()
{
	int ret = -1;
	unsigned int count = 0;
	struct pv_object_transfer *o, *tmp;

	if (_init_object_transfer_unrecorded()) {
		pv_log(WARN,
		       "could not init object trasfer list with unrecorded objects");
		return -1;
	}

	dl_list_for_each_safe(o, tmp, &session.object_transfer_list,
			      struct pv_object_transfer, list)
	{
		if (!o->active) {
			_get_object_metadata(o->id);
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
	const char *id = (char *)ctx;

	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_object_chunk_cb);

	pv_storage_set_object_download_path(path, PATH_MAX, id);
	pv_event_rest_recv_chunk_path(req, path);
}

static void _recv_get_object_done_cb(struct evhttp_request *req, void *ctx)
{
	char path[PATH_MAX];
	int res;
	const char *id = (char *)ctx;

	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_object_done_cb);

	_remove_object_transfer(id);

	pv_storage_set_object_download_path(path, PATH_MAX, id);
	res = pv_event_rest_recv_done_path(req, path);
	if (res == 401) {
		pv_log(WARN, "GET object unauthorized", res);
		pv_pantahub_proto_close_session();
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
}

void _get_object(const char *geturl, const char *id)
{
	char path[PATH_MAX];

	if (!geturl || !id)
		return;

	pv_storage_set_object_download_path(path, PATH_MAX, id);
	pv_fs_path_remove(path, true);

	pv_log(DEBUG, "requesting object '%s' from Hub", id);

	pv_event_rest_send_by_url(EVHTTP_REQ_GET, geturl,
				  _recv_get_object_chunk_cb,
				  _recv_get_object_done_cb, (void *)id);
}

int pv_pantahub_proto_get_objects()
{
	int ret = -1;
	unsigned int count = 0;
	char *geturl;
	struct pv_object_transfer *o, *tmp;

	if (_init_object_transfer_unavailable()) {
		pv_log(WARN,
		       "could not init object trasfer list with unavailable objects");
		return -1;
	}

	dl_list_for_each_safe(o, tmp, &session.object_transfer_list,
			      struct pv_object_transfer, list)
	{
		if (!o->active) {
			geturl = pv_update_get_object_geturl(o->id);
			_get_object(geturl, o->id);
			o->active = true;
		}

		count++;
		if (count >= pv_config_get_int(PH_UPDATER_TRANSFER_MAX_COUNT))
			break;
	}

	return 0;
}

static void _recv_put_progress_cb(struct evhttp_request *req, void *ctx);

static void _send_current_progress()
{
	if (!session.token) {
		pv_log(WARN,
		       "session must be opened first; not sending request (%p)%s",
		       session.current_uri, session.current_uri);
		return;
	}
	pv_log(DEBUG, "sending current progress request (%p)%s",
	       session.current_uri, session.current_uri);
	_send_by_endpoint(EVHTTP_REQ_PUT, session.current_uri, session.token,
			  session.current_progress, _recv_put_progress_cb,
			  NULL);
}

static void _recv_put_progress_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_put_progress_cb);

	pv_log(DEBUG, "finished progress request (%p)%s", session.current_uri,
	       session.current_uri);

	// clean up the current request now that we finished
	free(session.current_progress);
	session.current_progress = NULL;
	free(session.current_uri);
	session.current_uri = NULL;

	// process a potential next request right away
	if (session.next_progress) {
		session.current_progress = session.next_progress;
		session.current_uri = session.next_uri;
		session.next_progress = session.next_uri = NULL;
		pv_log(DEBUG, "dequeued next progress request (%p)%s",
		       session.current_uri, session.current_uri);

		// send current progress
		_send_current_progress();
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
}

void pv_pantahub_proto_put_progress(const char *rev, const char *progress)
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

	// first check if there is no current, but a next. if so we move next to current

	// if there is nothing going on we can fire something.
	if (session.current_progress == NULL) {
		if (session.next_progress != NULL) {
			session.current_progress = session.next_progress;
			session.current_uri = session.next_uri;
			session.next_progress = strdup(progress);
			session.next_uri = strdup(uri);
			pv_log(DEBUG,
			       "dequeued next progress request %s (queued new: %s)",
			       session.current_uri, session.next_uri);
		} else {
			session.current_progress = strdup(progress);
			session.current_uri = strdup(uri);
		}

		_send_current_progress();

	} else {
		if (session.next_progress) {
			free(session.next_progress);
			free(session.next_uri);
			session.next_progress = session.next_uri = NULL;
		}
		session.next_progress = strdup(progress);
		session.next_uri = strdup(uri);
		pv_log(DEBUG,
		       "queued next progress request (%p)%s (active: (%p)%s)",
		       session.next_uri, session.next_uri, session.current_uri,
		       session.current_uri);
	}
}
