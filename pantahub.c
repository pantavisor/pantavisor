/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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
#include <dirent.h>
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

#include "trestclient.h"
#include "pantahub.h"
#include "pantavisor.h"
#include "json.h"
#include "paths.h"
#include "metadata.h"
#include "utils/tsh.h"
#include "utils/str.h"
#include "utils/fs.h"

#define MODULE_NAME "pantahub-api"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define ENDPOINT_FMT "/devices/%s"

trest_ptr *client = 0;
char *endpoint = 0;

static int ph_client_init(struct pantavisor *pv)
{
	int size;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	if (client)
		goto auth;

	client = pv_get_trest_client(pv, NULL);

	if (!client)
		return 0;

auth:
	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		client = NULL; // XXX: free here
		return 0;
	}

	if (!endpoint && pv_config_get_creds_id()) {
		size = sizeof(ENDPOINT_FMT) + strlen(pv_config_get_creds_id()) +
		       1;
		endpoint = malloc(size * sizeof(char));
		SNPRINTF_WTRUNC(endpoint, size, ENDPOINT_FMT,
				pv_config_get_creds_id());
	}

	return 1;
}

static void pv_ph_set_online(struct pantavisor *pv, bool online)
{
	int fd, hint;
	struct stat st;
	char path[PATH_MAX];

	pv_paths_pv_file(path, PATH_MAX, ONLINE_FNAME);
	hint = stat(path, &st) ? 0 : 1;

	if (online) {
		if (!hint) {
			fd = open(path, O_CREAT | O_SYNC, 0400);
			if (fd >= 0)
				close(fd);
		}
		pv_metadata_add_devmeta(DEVMETA_KEY_PH_ONLINE, "1");
	} else {
		if (hint)
			pv_fs_path_remove(path, false);

		pv_metadata_add_devmeta(DEVMETA_KEY_PH_ONLINE, "0");
	}

	pv->online = online;
}

/* API */

bool pv_ph_is_auth(struct pantavisor *pv)
{
	// if client and endpoint exists, it means we have authenticate
	if (client && endpoint)
		goto success;

	ph_client_init(pv);

	if (client && endpoint)
		goto success;

	pv_ph_set_online(pv, false);
	return false;

success:
	pv_ph_set_online(pv, true);
	return true;
}

const char **pv_ph_get_certs(struct pantavisor *__unused)
{
	struct dirent **files;
	char **cafiles;
	char path[PATH_MAX];
	int n = 0, i = 0, size = 0;

	pv_paths_cert(path, PATH_MAX, "");
	n = scandir(path, &files, NULL, alphasort);
	if (n < 0)
		return NULL;

	// Always n-1 due to . and .., and need one extra
	cafiles = calloc(n - 1, sizeof(char *));

	while (n--) {
		if (!strncmp(files[n]->d_name, ".", 1))
			continue;

		pv_paths_cert(path, PATH_MAX, files[n]->d_name);
		size = strlen(path);
		cafiles[i] = malloc((size + 1) * sizeof(char));
		memcpy(cafiles[i], path, size);
		cafiles[i][size] = '\0';
		i++;
		free(files[n]);
	}

	free(files);

	return (const char **)cafiles;
}

struct pv_connection *pv_get_instance_connection()
{
	struct pv_connection *conn = NULL;
	int port = 0;
	char *host = NULL;

	conn = (struct pv_connection *)calloc(1, sizeof(struct pv_connection));
	if (!conn) {
		pv_log(DEBUG, "Unable to allocate memory for connection\n");
		return NULL;
	}
	// default to global PH instance
	if (strcmp(pv_config_get_creds_host(), "") == 0)
		host = "api.pantahub.com";
	else
		host = pv_config_get_creds_host();

	port = pv_config_get_creds_port();
	if (!port)
		port = 443;

	conn->hostorip = host;
	conn->port = port;

	return conn;
}

void pv_ph_release_client(struct pantavisor *pv)
{
	if (client) {
		trest_free(client);
		client = 0;
	}

	if (endpoint) {
		free(endpoint);
		endpoint = 0;
	}
}

int pv_ph_device_get_meta(struct pantavisor *pv)
{
	int ret = -1;

	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!ph_client_init(pv))
		return -1;

	req = trest_make_request(THTTP_METHOD_GET, endpoint, 0);

	res = trest_do_json_request(client, req);
	if (!res) {
		pv_log(WARN, "HTTP request GET %s could not be initialized",
		       endpoint);
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request GET %s could not auth (status=%d)",
		       endpoint, res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "request GET %s returned HTTP error (code=%d; body='%s')",
		       endpoint, res->code, res->body);
	} else {
		pv_metadata_parse_usermeta(res->body);
		ret = 0;
	}

	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

int pv_ph_device_exists(struct pantavisor *pv)
{
	int ret = 0;
	char *id = 0;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!ph_client_init(pv)) {
		pv_log(WARN, "failed to initialize PantaHub connection");
		goto out;
	}

	req = trest_make_request(THTTP_METHOD_GET, endpoint, 0);

	res = trest_do_json_request(client, req);
	if (!res) {
		pv_log(WARN, "HTTP request GET %s could not be initialized",
		       endpoint);
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request GET %s could not auth (status=%d)",
		       endpoint, res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request GET %s returned HTTP error (code=%d; body='%s')",
		       endpoint, res->code, res->body);
	} else {
		id = pv_json_get_value(res->body, "id", res->json_tokv,
				       res->json_tokc);

		if (id && (strcmp(id, "") != 0)) {
			pv_log(DEBUG, "device exists: '%s'", id);
			ret = 1;
		}
	}

out:
	if (id)
		free(id);
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

static int pv_ph_register_self_builtin(struct pantavisor *pv)
{
	int ret = 0;
	int tokc;
	int baseurl_size, header_size;
	thttp_request_tls_t *tls_req = 0;
	thttp_response_t *res = 0;
	jsmntok_t *tokv;
	char **headers = NULL;

	tls_req = thttp_request_tls_new_0();
	tls_req->crtfiles = (char **)pv_ph_get_certs(pv);

	thttp_request_t *req = (thttp_request_t *)tls_req;

	req->method = THTTP_METHOD_POST;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->user_agent = pv_user_agent;

	req->host = pv_config_get_creds_host();
	req->port = pv_config_get_creds_port();
	req->host_proxy = pv_config_get_creds_host_proxy();
	req->port_proxy = pv_config_get_creds_port_proxy();
	req->proxyconnect = !pv_config_get_creds_noproxyconnect();

	baseurl_size = strlen("https://") + strlen(req->host) + 1 /* : */ +
		       5 /* port */ + 2 /* 0-delim */;
	req->baseurl = calloc(baseurl_size, sizeof(char));
	SNPRINTF_WTRUNC(req->baseurl, baseurl_size, "https://%s:%d", req->host,
			req->port);

	if (req->host_proxy)
		req->is_tls =
			false; /* XXX: global config if proxy is tls is TBD */

	req->path = "/devices/";
	req->body = 0;

	if (pv_config_get_factory_autotok() &&
	    strcmp(pv_config_get_factory_autotok(), "")) {
		headers = calloc(2, sizeof(char *));
		header_size = sizeof(DEVICE_TOKEN_FMT) + 64;
		headers[0] = calloc(header_size, sizeof(char));
		SNPRINTF_WTRUNC(headers[0], header_size, DEVICE_TOKEN_FMT,
				pv_config_get_factory_autotok());
		thttp_add_headers(req, headers, 1);
	}

	req->body_content_type = "application/json";

	res = thttp_request_do(req);

	// If registered, override in-memory PantaHub credentials
	if (!res) {
		pv_log(WARN, "HTTP request GET %s could not be initialized",
		       req->path);
	} else if (res->code == THTTP_STATUS_OK && res->body) {
		jsmnutil_parse_json(res->body, &tokv, &tokc);
		pv_config_set_creds_id(
			pv_json_get_value(res->body, "id", tokv, tokc));
		pv_config_set_creds_prn(
			pv_json_get_value(res->body, "prn", tokv, tokc));
		pv_config_set_creds_secret(
			pv_json_get_value(res->body, "secret", tokv, tokc));
		ret = 1;
	} else if (!res->code) {
		pv_log(WARN, "HTTP request GET %s got no response", req->path);
	} else {
		pv_log(WARN,
		       "HTTP request GET %s returned HTTP error (code=%d; body='%s')",
		       req->path, res->code, res->body);
	}

	if (headers) {
		free(headers[0]);
		free(headers);
	}
	if (req)
		thttp_request_free(req);
	if (res)
		thttp_response_free(res);

	return ret;
}

static int pv_ph_register_self_ext(struct pantavisor *pv, char *cmd)
{
	int ret = 0;
	int status = -1;

	if (tsh_run(cmd, 1, &status) < 0) {
		pv_log(ERROR, "registration attempt with cmd: %s", cmd);
		goto exit;
	}

	// If registered, override in-memory PantaHub credentials
	if (pv_config_load_creds()) {
		pv_log(ERROR, "error loading updated config file");
		goto exit;
	}

	ret = 1;
exit:
	return ret;
}

#define PANTAVISOR_EXTERNAL_REGISTER_HANDLER_FMT "/btools/%s.register"

int pv_ph_register_self(struct pantavisor *pv)
{
	int ret = 1;
	char cmd[PATH_MAX];
	enum {
		HUB_CREDS_TYPE_BUILTIN = 0,
		HUB_CREDS_TYPE_EXTERNAL,
		HUB_CREDS_TYPE_ERROR
	} creds_type;

	if (!strcmp(pv_config_get_creds_type(), "builtin")) {
		creds_type = HUB_CREDS_TYPE_BUILTIN;
	} else if (strlen(pv_config_get_creds_type()) >= 4 &&
		   !strncmp(pv_config_get_creds_type(), "ext-", 4)) {
		struct stat sb;
		int rv;

		// if no executable handler is found; fall back to builtin
		SNPRINTF_WTRUNC(cmd, sizeof(cmd),
				PANTAVISOR_EXTERNAL_REGISTER_HANDLER_FMT,
				pv_config_get_creds_type());
		rv = stat(cmd, &sb);
		if (rv) {
			pv_log(ERROR,
			       "unable to stat trest client for cmd %s: %s",
			       cmd, strerror(errno));
			goto err;
		}
		if (!(sb.st_mode & S_IXUSR)) {
			pv_log(ERROR,
			       "unable to get trest client for cmd %s ... not executable.",
			       cmd);
			goto err;
		}

		creds_type = HUB_CREDS_TYPE_EXTERNAL;
	} else {
		pv_log(ERROR, "unable to get trest client for creds_type %s.",
		       pv_config_get_creds_type());
		goto err;
	}

	switch (creds_type) {
	case HUB_CREDS_TYPE_BUILTIN:
		ret = pv_ph_register_self_builtin(pv);
		break;
	case HUB_CREDS_TYPE_EXTERNAL:
		ret = pv_ph_register_self_ext(pv, cmd);
		break;
	default:
		pv_log(ERROR,
		       "unable to register for creds_type %s. "
		       "Currently supported: builtin and ext-* handlers",
		       pv_config_get_creds_type());
		ret = 0;
		goto err;
	}

err:
	return ret;
}

int pv_ph_device_is_owned(struct pantavisor *pv, char **c)
{
	int ret = 0;
	char *owner = 0, *challenge = 0;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!ph_client_init(pv)) {
		pv_log(ERROR, "failed to initialize PantaHub connection");
		goto out;
	}

	req = trest_make_request(THTTP_METHOD_GET, endpoint, 0);

	res = trest_do_json_request(client, req);
	if (!res) {
		pv_log(WARN, "HTTP request GET %s could not be initialized",
		       endpoint);
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request GET %s could not auth (status=%d)",
		       endpoint, res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request GET %s returned HTTP error (code=%d; body='%s')",
		       endpoint, res->code, res->body);
	} else {
		owner = pv_json_get_value(res->body, "owner", res->json_tokv,
					  res->json_tokc);

		if (owner && (strcmp(owner, "") != 0)) {
			pv_log(DEBUG, "device-owner: '%s'", owner);
			ret = 1;
			goto out;
		}

		challenge = pv_json_get_value(res->body, "challenge",
					      res->json_tokv, res->json_tokc);

		strcpy(*c, challenge);
	}

out:
	if (owner)
		free(owner);
	if (challenge)
		free(challenge);
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}

void pv_ph_update_hint_file(struct pantavisor *pv, char *c)
{
	char buf[256], path[PATH_MAX];

	pv_paths_pv_file(path, PATH_MAX, DEVICE_ID_FNAME);
	SNPRINTF_WTRUNC(buf, sizeof(buf), "%s\n", pv_config_get_creds_id());
	if (pv_fs_file_save(path, buf, 044))
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	if (!c)
		return;

	pv_paths_pv_file(path, PATH_MAX, CHALLENGE_FNAME);
	SNPRINTF_WTRUNC(buf, sizeof(buf), "%s\n", c);
	if (pv_fs_file_save(path, buf, 044))
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));
}

int pv_ph_upload_metadata(struct pantavisor *pv, char *metadata)
{
	uint8_t ret = -1;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;
	char buf[256];

	if (!ph_client_init(pv))
		goto out;

	SNPRINTF_WTRUNC(buf, sizeof(buf), "%s%s", endpoint, "/device-meta");

	req = trest_make_request(THTTP_METHOD_PATCH, buf, metadata);

	res = trest_do_json_request(client, req);
	if (!res) {
		pv_log(WARN, "PATCH %s could not be initialized", endpoint);
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request PATCH %s could not auth (status=%d)",
		       endpoint, res->status);
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request PATCH %s returned HTTP error (code=%d; body='%s')",
		       endpoint, res->code, res->body);
	} else {
		ret = 0;
	}

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}
