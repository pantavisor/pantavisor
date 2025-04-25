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

#include <jsmn/jsmnutil.h>

#include "pantahub/pantahub_proto.h"
#include "pantahub/pantahub_rest.h"

#include "metadata.h"

#include "utils/json.h"
#include "utils/str.h"

#define MODULE_NAME "pantahub_proto"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

typedef struct {
	char *token;
} pantahub_session_t;

static pantahub_session_t session = { 0 };

static void _parse_post_auth_body(const char *json)
{
	int tokc;
	jsmntok_t *tokv = NULL;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		goto out;
	}

	session.token = pv_json_get_value(json, "token", tokv, tokc);

out:
	if (tokv)
		free(tokv);
}

static void _recv_post_auth_cb(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "POST auth response received");

	char buffer[1024];
	memset(&buffer, 0, sizeof(buffer));
	if (pv_pantahub_rest_recv(req, ctx, &buffer[0], 1024) == 200)
		_parse_post_auth_body(buffer);

	if (session.token)
		pv_log(DEBUG, "new session opened");
}

void pv_pantahub_proto_open_session(struct event_base *base)
{
	if (session.token) {
		pv_log(ERROR, "session must be closed first");
		return;
	}

	pv_log(DEBUG, "opening new session...");

	char uri[256];
	SNPRINTF_WTRUNC(uri, sizeof(uri), "/auth/login");

	struct pv_json_ser js;
	pv_json_ser_init(&js, 1024);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "username");
		pv_json_ser_string(&js, pv_config_get_str(PH_CREDS_PRN));
		pv_json_ser_key(&js, "password");
		pv_json_ser_string(&js, pv_config_get_str(PH_CREDS_SECRET));
		pv_json_ser_object_pop(&js);
	}

	char *body = pv_json_ser_str(&js);
	if (!body) {
		pv_log(ERROR, "could not serialize session auth JSON");
		return;
	}

	pv_pantahub_rest_send(base, EVHTTP_REQ_POST, uri, NULL, body,
			      _recv_post_auth_cb);
	free(body);
}

bool pv_pantahub_proto_is_session_open()
{
	return session.token;
}

void pv_pantahub_proto_close_session()
{
	pv_log(DEBUG, "closing session");

	if (session.token)
		free(session.token);
	session.token = NULL;
}

typedef struct {
	char *usrmeta;
	char *devmeta;
} pantahub_cache_t;

static pantahub_cache_t cache = { 0 };

static bool _is_in_cache(const char *in, char *cache)
{
	return cache && in && pv_str_matches(cache, strlen(cache), in, strlen(in));
}

static void _save_cache(const char *in, char **cache)
{
	if (*cache)
		free(*cache);
	*cache = strdup(in);
}

static void _recv_get_usrmeta_cb(struct evhttp_request *req, void *ctx)
{
	char buffer[1024];
	memset(&buffer, 0, sizeof(buffer));
	if (pv_pantahub_rest_recv(req, ctx, &buffer[0], 1024) != 200) {
		pv_log(DEBUG, "GET usrmeta bad response");
		return;
	}

	if (_is_in_cache(buffer, cache.usrmeta)) {
		return;
	}
	pv_log(DEBUG, "usrmeta changed since last update from Hub");
	pv_metadata_parse_usermeta(buffer);
	_save_cache(buffer, &cache.usrmeta);
	pv_log(DEBUG, "usrmeta cache saved");
}

void pv_pantahub_proto_get_usrmeta(struct event_base *base)
{
	if (!session.token) {
		pv_log(ERROR, "session must be opened first");
		return;
	}

	char uri[256];
	snprintf(uri, sizeof(uri), "/devices/%s/user-meta",
		 pv_config_get_str(PH_CREDS_ID));

	pv_pantahub_rest_send(base, EVHTTP_REQ_GET, uri, session.token, NULL, _recv_get_usrmeta_cb);
}

static void _recv_set_devmeta_cb(struct evhttp_request *req, void *ctx)
{
	char buffer[1024];
	memset(&buffer, 0, sizeof(buffer));
	if (pv_pantahub_rest_recv(req, ctx, &buffer[0], 1024) != 200) {
		pv_log(DEBUG, "PUT devmeta bad response");
		return;
	}

	pv_log(DEBUG, "devmeta updated in Hub");
	_save_cache(buffer, &cache.devmeta);
	pv_log(DEBUG, "devmeta cache saved");
}

void pv_pantahub_proto_set_devmeta(struct event_base *base)
{
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

	if (_is_in_cache(json, cache.devmeta))
		goto out;
	pv_log(DEBUG, "devmeta changed since last update to Hub");
	pv_pantahub_rest_send(base, EVHTTP_REQ_PUT, uri, session.token, json, _recv_set_devmeta_cb);

out:
	free(json);
}
