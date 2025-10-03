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

#include <fcntl.h>
#include <thttp.h>
#include <trest.h>
#include <unistd.h>

#include <mbedtls/sha256.h>

#include <sys/stat.h>

#include "metadata.h"
#include "objects.h"
#include "paths.h"
#include "storage.h"
#include "trestclient.h"
#include "updater.h"

#include "pantahub/pantahub.h"

#include "utils/str.h"

#define MODULE_NAME "updater"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void pv_trail_remote_free(struct trail_remote *trail)
{
	if (!trail)
		return;

	pv_log(DEBUG, "removing trail");

	free(trail);
}

void pv_trail_remote_remove(struct pantavisor *pv)
{
	pv_trail_remote_free(pv->remote);
	pv->remote = NULL;
}

static int trail_remote_init(struct pantavisor *pv)
{
	struct trail_remote *remote = NULL;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;
	trest_ptr client = 0;
	size_t size = -1;

	const char *id = pv_config_get_str(PH_CREDS_ID);
	if (pv->remote || !id)
		return 0;

	client = pv_get_trest_client(pv, NULL);

	if (!client) {
		pv_log(INFO, "unable to create device client");
		goto err;
	}

	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "unable to auth device client");
		goto err;
	}

	remote = calloc(1, sizeof(struct trail_remote));
	remote->client = client;

	pv->remote = remote;

	return 0;

err:
	if (client)
		free(client);
	if (remote)
		free(remote);

	return -1;
}

static void __trail_log_resp_err(char *buf, jsmntok_t *tokv, int tokc)
{
	char *error = NULL, *msg = NULL, *__code = NULL;
	int code = 0;
	/*
	 * Error response looks like
	 * {
	 *  "error": <String>
	 *  "msg": <String> <Maybe empty>
	 *  "code": <int> <Maybe empty>
	 * }
	 */
	error = pv_json_get_value(buf, "error", tokv, tokc);

	msg = pv_json_get_value(buf, "msg", tokv, tokc);

	__code = pv_json_get_value(buf, "code", tokv, tokc);
	if (__code) {
		sscanf(__code, "%d", &code);
		free(__code);
		__code = NULL;
	}

	if (error && msg) {
		pv_log(WARN, "Error %s: Message %s, code = %d", error, msg,
		       code);
	} else {
		pv_log(WARN,
		       "Malformed Error JSON from API,"
		       " error:%s,msg:%s, code=%d",
		       (error ? error : "nil"), (msg ? msg : "nil"), code);
	}
	if (error)
		free(error);
	if (msg)
		free(msg);
}

static void trail_log_thttp_err(thttp_response_t *thttp_res)
{
	int tokc;
	jsmntok_t *tokv = NULL;
	char *buf = NULL;

	if (!thttp_res || thttp_res->code == THTTP_STATUS_OK)
		return;
	buf = thttp_res->body;
	if (!buf)
		return;
	if (jsmnutil_parse_json(buf, &tokv, &tokc) >= 0) {
		__trail_log_resp_err(buf, tokv, tokc);
	}
	if (tokv)
		free(tokv);
}

static void trail_log_trest_err(trest_response_ptr tres)
{
	if (!tres || tres->code == THTTP_STATUS_OK)
		return;
	if (!tres->json_tokv)
		return;
	__trail_log_resp_err(tres->body, tres->json_tokv, tres->json_tokc);
}

#define SHA256_STR_SIZE ((256 / 4) + 1)

static int trail_put_object(struct pantavisor *pv, struct pv_object *o,
			    const char **crtfiles)
{
	int ret = -1;
	int fd, bytes;
	off_t size, pos, i, str_size;
	char *signed_puturl = NULL;
	char sha_str[SHA256_STR_SIZE];
	char objpath[PATH_MAX];
	char body[512];
	unsigned char buf[4096];
	unsigned char local_sha[32];
	struct stat st;
	trest_request_ptr treq = 0;
	trest_response_ptr tres = 0;
	thttp_request_t *req = 0;
	thttp_request_tls_t *tls_req = 0;
	thttp_response_t *res = 0;

	if (o->uploaded) {
		pv_log(INFO, "object '%s' already uploaded, skipping", o->id);
		return 0;
	}

	pv_paths_storage_object(objpath, PATH_MAX, o->id);
	fd = open(objpath, O_RDONLY);
	if (fd < 0)
		return -1;

	stat(objpath, &st);
	size = st.st_size;

	mbedtls_sha256_context sha256_ctx;

	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0);

	while ((bytes = read(fd, buf, 4096)) > 0) {
		mbedtls_sha256_update(&sha256_ctx, buf, bytes);
	}

	mbedtls_sha256_finish(&sha256_ctx, local_sha);
	mbedtls_sha256_free(&sha256_ctx);

	pos = 0;
	i = 0;
	while (i < 32) {
		pos += snprintf(sha_str + pos, 3, "%02x", local_sha[i]);
		i++;
	}

	SNPRINTF_WTRUNC(body, sizeof(body),
			"{ \"objectname\": \"%s\","
			" \"size\": \"%jd\","
			" \"sha256sum\": \"%s\""
			" }",
			o->name, (intmax_t)size, sha_str);

	pv_log(INFO, "syncing '%s'", o->id);

	if (strncmp(o->id, sha_str, SHA256_STR_SIZE)) {
		pv_log(INFO,
		       "sha256 mismatch, probably writable image, skipping");
		goto out;
	}

	treq = trest_make_request(THTTP_METHOD_POST, "/objects/", body);

	tres = trest_do_json_request(pv->remote->client, treq);
	if (!tres) {
		pv_log(WARN, "POST /objects/ could not be initialized");
		goto out;
	} else if (tres->code == THTTP_STATUS_CONFLICT) {
		pv_log(INFO, "object '%s' already owned by user, skipping",
		       o->id);
		o->uploaded = true;
		ret = 0;
		goto out;
	} else if (!tres->code && tres->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "POST /objects/ could not auth (status=%d)",
		       tres->status);
		goto out;
	} else if (tres->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "POST /objects/ returned error (code=%d; body='%s')",
		       tres->code, tres->body);
		goto out;
	}

	signed_puturl = pv_json_get_value(tres->body, "signed-puturl",
					  tres->json_tokv, tres->json_tokc);

	tls_req = (thttp_request_tls_t *)thttp_request_tls_new_0();

	if (signed_puturl && tls_req) {
		tls_req->crtfiles = (char **)crtfiles;
		req = (thttp_request_t *)tls_req;
		req->is_tls = 1;

		req->method = THTTP_METHOD_PUT;
		req->proto = THTTP_PROTO_HTTP;
		req->proto_version = THTTP_PROTO_VERSION_10;
		req->host = pv_config_get_str(PH_CREDS_HOST);
		req->port = pv_config_get_int(PH_CREDS_PORT);
		req->host_proxy = pv_config_get_str(PH_CREDS_PROXY_HOST);
		req->port_proxy = pv_config_get_int(PH_CREDS_PROXY_PORT);
		req->proxyconnect =
			!pv_config_get_int(PH_CREDS_PROXY_NOPROXYCONNECT);
		if (req->is_tls) {
			str_size = strlen("https://") + strlen(req->host) +
				   1 /* : */ + 5 /* port */ + 2 /* 0-delim */;
			req->baseurl = calloc(str_size, sizeof(char));
			SNPRINTF_WTRUNC(req->baseurl, str_size, "https://%s:%d",
					req->host, req->port);
		} else {
			((thttp_request_tls_t *)req)->crtfiles = NULL;
			str_size = strlen("https://") + strlen(req->host) +
				   1 /* : */ + 5 /* port */ + 2 /* 0-delim */;
			req->baseurl = calloc(str_size, sizeof(char));
			SNPRINTF_WTRUNC(req->baseurl, str_size, "http://%s:%d",
					req->host, req->port);
		}
		if (req->host_proxy)
			req->is_tls =
				false; /* XXX: global config if proxy is tls is TBD */
		req->user_agent = pv_user_agent;

		req->path = strstr(signed_puturl, "/local-s3");

		req->body_content_type = "application/json";
		lseek(fd, 0, SEEK_SET);
		req->fd = fd;
		req->len = size;

		pv_log(INFO, "'%s' does not exist, uploading", o->id);

		res = thttp_request_do(req);

		if (!res) {
			pv_log(WARN,
			       "'%s' could not be uploaded: could not be initialized",
			       o->id);
		} else if (!res->code) {
			pv_log(WARN,
			       "'%s' could not be uploaded: got no response",
			       o->id);
		} else if (res->code != THTTP_STATUS_OK) {
			pv_log(WARN,
			       "'%s' could not be uploaded: returned HTTP error (code=%d; body='%s')",
			       o->id, res->code, res->body);
		} else {
			pv_log(INFO,
			       "'%s' uploaded correctly, size=%jd, code=%d",
			       o->id, (intmax_t)size, res->code);
			o->uploaded = true;
			ret = 0;
		}
	} else {
		pv_log(ERROR,
		       "'%s' could not be registered, signed_puturl not retrieved",
		       o->id);
	}

out:
	close(fd);
	if (signed_puturl)
		free(signed_puturl);
	if (treq)
		trest_request_free(treq);
	if (tres) {
		/*
		 * For Conflict on an object we don't see it
		 * as an error so skip the trail_log in this
		 * case.
		 */
		if (tres->code != THTTP_STATUS_CONFLICT)
			trail_log_trest_err(tres);
		trest_response_free(tres);
	}
	if (req)
		thttp_request_free(req);
	if (res) {
		trail_log_thttp_err(res);
		thttp_response_free(res);
	}

	return ret;
}

static int trail_put_objects(struct pantavisor *pv)
{
	int ret = 0;
	struct pv_object *curr = NULL;
	const char **crtfiles = pv_ph_get_certs();

	pv_objects_iter_begin(pv->state, curr)
	{
		ret++;
	}
	pv_objects_iter_end;

	pv_log(DEBUG, "first boot: %d objects found, syncing", ret);

	// push all
	pv_objects_iter_begin(pv->state, curr)
	{
		if (trail_put_object(pv, curr, crtfiles) < 0)
			break;
		ret--;
	}
	pv_objects_iter_end;

	return ret;
}

static int trail_first_boot(struct pantavisor *pv)
{
	char *json = pv_storage_get_state_json(pv->state->rev);
	if (!json) {
		pv_log(ERROR, "Could not read state json");
		return -1;
	}

	trest_request_ptr req;
	trest_response_ptr res;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	status = trest_update_auth(pv->remote->client);
	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "cannot update auth token");
		free(json);
		return -1;
	}

	// first upload all objects
	if (trail_put_objects(pv) > 0) {
		pv_log(DEBUG, "error syncing objects on first boot");
		free(json);
		return -1;
	}

	req = trest_make_request(THTTP_METHOD_POST, "/trails/", json);

	res = trest_do_json_request(pv->remote->client, req);
	if (!res) {
		pv_log(WARN, "POST /trails/ could not be initialized");
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "POST /trails/ could not auth (status=%d)",
		       res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "POST /trails/ returned error (code=%d; body='%s')",
		       res->code, res->body);
	} else {
		pv_log(INFO,
		       "factory revision (base trail) pushed to remote correctly");
	}

	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);
	free(json);

	return 0;
}

int pv_updater_sync()
{
	int ret;
	char *addr;
	struct pantavisor *pv = pv_get_instance();

	if (!pv)
		return -1;

	if (trail_remote_init(pv)) {
		pv_log(WARN, "remote not initialized");
		return -1;
	}

	if (trest_update_auth(pv->remote->client) != TREST_AUTH_STATUS_OK) {
		pv_log(INFO, "cannot authenticate to cloud");
		return -1;
	}

	// sync factory revision with Hub
	return trail_first_boot(pv);
}
