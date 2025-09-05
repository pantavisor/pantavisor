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
#include <string.h>

#include "pantahub/pantahub.h"
#include "pantahub/pantahub_msg.h"
#include "pantahub/pantahub_proto.h"
#include "pantahub/pantahub_struct.h"

#include "event/event_rest.h"

#include "metadata.h"
#include "update/update.h"

#include "utils/str.h"

#define MODULE_NAME "pantahub_proto"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define AUTH_JSON_LEN 128
#define BODY_MAX_LEN (1 << 21) // 2MiB

typedef struct {
	char *token;
} pantahub_session_t;

static pantahub_session_t session = { 0 };

static void _recv_post_auth_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_post_auth_cb);

	char *body = NULL;
	int res = pv_event_rest_recv(req, ctx, &body, BODY_MAX_LEN);
	if (res != 200) {
		pv_log(WARN, "POST auth returned %d", res);
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

	const char *uri = "/auth/login";

	char *body = pv_pantahub_msg_ser_login_json(
		pv_config_get_str(PH_CREDS_PRN),
		pv_config_get_str(PH_CREDS_SECRET));
	if (!body) {
		pv_log(ERROR, "could not serialize session auth JSON");
		return;
	}

	pv_event_rest_send(EVHTTP_REQ_POST, uri, NULL, body,
			   _recv_post_auth_cb);
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

static void _recv_put_progress_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_put_progress_cb);

	char *body = NULL;
	int res = pv_event_rest_recv(req, ctx, &body, BODY_MAX_LEN);
	if (res == 401) {
		pv_log(WARN, "PUT progress unauthorized", res);
		pv_pantahub_proto_close_session();
		goto out;
	}
	if (res != 200) {
		pv_log(WARN, "PUT progress returned %d", res);
		goto out;
	}

	pv_log(DEBUG, "progress updated in Hub");
out:
	if (body)
		free(body);
}

static void _put_progress(const char *progress)
{
	char *rev;

	if (!progress)
		return;

	rev = pv_update_get_rev();
	if (!rev)
		return;

	pv_log(DEBUG, "sending progress '%s' from rev '%s' to Hub", progress,
	       rev);

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/trails/%s/steps/%s/progress",
		 pv_config_get_str(PH_CREDS_ID), rev);

	pv_event_rest_send(EVHTTP_REQ_PUT, uri, session.token, progress,
			   _recv_put_progress_cb);
}

static void _recv_get_pending_steps_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL, *state_json = NULL, *progress = NULL;
	pv_step_t step;
	memset(&step, 0, sizeof(step));

	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_pending_steps_cb);

	int res = pv_event_rest_recv(req, ctx, &body, BODY_MAX_LEN);
	if (res == 401) {
		pv_log(WARN, "GET pending steps unauthorized", res);
		pv_pantahub_proto_close_session();
		goto out;
	}
	if (res != 200) {
		pv_log(WARN, "GET pending steps returned %d", res);
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

	progress = pv_update_start_install(step.rev, step.msg, step.progress,
					   step.state);
	_put_progress(progress);

out:
	pv_pantahub_msg_clean_step(&step);
	if (progress)
		free(progress);
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

	char uri[256];
	snprintf(uri, sizeof(uri), "/trails/%s/steps",
		 pv_config_get_str(PH_CREDS_ID));

	pv_event_rest_send(EVHTTP_REQ_GET, uri, session.token, NULL,
			   _recv_get_pending_steps_cb);
}

static void _recv_get_usrmeta_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_usrmeta_cb);

	char *body = NULL;
	int res = pv_event_rest_recv(req, ctx, &body, BODY_MAX_LEN);
	if (res == 401) {
		pv_log(WARN, "GET usrmeta unauthorized", res);
		pv_pantahub_proto_close_session();
		goto out;
	}
	if (res != 200) {
		pv_log(WARN, "GET usrmeta returned %d", res);
		goto out;
	}
	if (!body) {
		pv_log(WARN, "GET usrmeta received empty body");
		goto out;
	}

	pv_metadata_parse_usermeta(body);

	pv_log(DEBUG, "usmeta updated from Hub");
out:
	if (body)
		free(body);
}

void pv_pantahub_proto_get_usrmeta()
{
	pv_log(DEBUG, "requesting usrmeta from Hub");

	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/devices/%s/user-meta",
		 pv_config_get_str(PH_CREDS_ID));

	pv_event_rest_send(EVHTTP_REQ_GET, uri, session.token, NULL,
			   _recv_get_usrmeta_cb);
}

static void _recv_set_devmeta_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_set_devmeta_cb);

	char *body = NULL;
	int res = pv_event_rest_recv(req, ctx, &body, BODY_MAX_LEN);
	if (res == 401) {
		pv_log(WARN, "PUT devmeta unauthorized", res);
		pv_pantahub_proto_close_session();
		goto out;
	}
	if (res != 200) {
		pv_log(WARN, "PUT devmeta returned %d", res);
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

	char uri[256];
	snprintf(uri, sizeof(uri), "/devices/%s/device-meta",
		 pv_config_get_str(PH_CREDS_ID));

	char *json = pv_metadata_get_device_meta_string();
	if (!json) {
		pv_log(ERROR, "could not get devmeta JSON");
		return;
	}

	pv_event_rest_send(EVHTTP_REQ_PUT, uri, session.token, json,
			   _recv_set_devmeta_cb);

out:
	free(json);
}

static void _recv_get_object_metadata_cb(struct evhttp_request *req, void *ctx)
{
	char *body = NULL, *progress = NULL;
	int res;

	pv_object_metadata_t object_metadata;
	memset(&object_metadata, 0, sizeof(object_metadata));

	pv_log(DEBUG, "run event: cb=%p", (void *)_recv_get_object_metadata_cb);

	res = pv_event_rest_recv(req, ctx, &body, BODY_MAX_LEN);
	if (res == 401) {
		pv_log(WARN, "GET object metadata unauthorized", res);
		pv_pantahub_proto_close_session();
		goto out;
	}
	if (res != 200) {
		pv_log(WARN, "GET object metadata returned %d", res);
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

	progress = pv_update_set_object_metadata(object_metadata.sha256sum,
						 object_metadata.size,
						 object_metadata.geturl);
	_put_progress(progress);

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

	pv_event_rest_send(EVHTTP_REQ_GET, uri, session.token, NULL,
			   _recv_get_object_metadata_cb);
}

int pv_pantahub_proto_get_objects_metadata()
{
	int ret = -1;
	char *progress = NULL;
	char **objects = NULL, **o;

	progress = pv_update_get_unrecorded_objects(&objects);
	_put_progress(progress);
	if (!objects) {
		pv_log(WARN, "could not retrieve unrecorded objects");
		goto out;
	}

	o = objects;
	while (*o) {
		_get_object_metadata(*o);
		o++;
	}
	ret = 0;

out:
	if (progress)
		free(progress);
	if (objects)
		free(objects);

	return ret;
}

void _get_object(const char *id)
{
}

int pv_pantahub_proto_get_objects()
{
	int ret = -1;
	char *progress = NULL;
	char **objects = NULL, **o;

	progress = pv_update_get_unavailable_objects(&objects);
	_put_progress(progress);
	if (!objects) {
		pv_log(WARN, "could not retrieve unavailable objects");
		goto out;
	}

	o = objects;
	while (*o) {
		_get_object(*o);
		o++;
	}
	ret = 0;

out:
	if (progress)
		free(progress);
	if (objects)
		free(objects);

	return ret;
}
