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

#include "trestclient.h"
#include "pantahub.h"
#include "pantavisor.h"
#include "utils.h"
#include "json.h"
#include "tsh.h"
#include "metadata.h"

#define MODULE_NAME             "pantahub-api"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
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

	if (!endpoint) {
		size = sizeof(ENDPOINT_FMT) + strlen(pv_config_get_creds_id()) + 1;
		endpoint = malloc(size * sizeof(char));
		sprintf(endpoint, ENDPOINT_FMT, pv_config_get_creds_id());
	}

	return 1;
}

static void pv_ph_set_online(struct pantavisor *pv, bool online)
{
	int fd, hint;
	char *path = "/pv/online";
	struct stat st;

	hint = stat(path, &st) ? 0 : 1;

	if (online) {
		if (!hint) {
			fd = open(path, O_CREAT | O_SYNC, 0400);
			close(fd);
		}
	} else {
		if (hint)
			remove(path);
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

const char** pv_ph_get_certs(struct pantavisor *__unused)
{
	struct dirent **files;
	char **cafiles;
	char *dir = "/certs/";
	char path[512];
	int n = 0, i = 0, size = 0;

	n = scandir(dir, &files, NULL, alphasort);
	if (n < 0)
		return NULL;

	// Always n-1 due to . and .., and need one extra
	cafiles = calloc(1, (sizeof(char*) * (n-1)));

	while (n--) {
		if (!strncmp(files[n]->d_name, ".", 1))
			continue;

		sprintf(path, "/certs/%s", files[n]->d_name);
		size = strlen(path);
		cafiles[i] = malloc((size+1) * sizeof(char));
		memcpy(cafiles[i], path, size);
		cafiles[i][size] = '\0';
		i++;
		free(files[n]);
	}

	free(files);

	return (const char **) cafiles;
}

struct pv_connection* pv_get_instance_connection()
{
	struct pv_connection *conn = NULL;
	int port = 0;
	char *host = NULL;

	conn = (struct pv_connection*)calloc(1, sizeof(struct pv_connection));
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

	req = trest_make_request(TREST_METHOD_GET,
				 endpoint,
				 0, 0, 0);

	res = trest_do_json_request(client, req);

	if (!res->body || res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "error getting device details (code=%d)", res->code);
		goto out;
	}

	ret = pv_metadata_update_usermeta(res->body);

out:
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

	req = trest_make_request(TREST_METHOD_GET,
				 endpoint,
				 0, 0, 0);

	res = trest_do_json_request(client, req);

	if (!res->body || res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "error verifying device exists (code=%d)", res->code);
		goto out;
	}

	id = pv_json_get_value(res->body, "id",
			res->json_tokv, res->json_tokc);

	if (id && (strcmp(id, "") != 0)) {
		pv_log(DEBUG, "device exists: '%s'", id);
		ret = 1;
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
	int ret = 1;
	int tokc;
	thttp_request_tls_t* tls_req = 0;
	thttp_response_t* res = 0;
	jsmntok_t *tokv;

	tls_req = thttp_request_tls_new_0();
	tls_req->crtfiles = (char **) pv_ph_get_certs(pv);

	thttp_request_t* req = (thttp_request_t*) tls_req;

	req->method = THTTP_METHOD_POST;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->user_agent = pv_user_agent;

	req->host = pv_config_get_creds_host();
	req->port = pv_config_get_creds_port();
	req->host_proxy = pv_config_get_creds_host_proxy();
	req->port_proxy = pv_config_get_creds_port_proxy();
	req->proxyconnect = !pv_config_get_creds_noproxyconnect();

	req->baseurl = calloc(1, sizeof(char)*(strlen("https://") + strlen(req->host) + 1 /* : */ + 5 /* port */ + 2 /* 0-delim */));
	sprintf(req->baseurl, "https://%s:%d", req->host, req->port);

	if (req->host_proxy)
                req->is_tls = false; /* XXX: global config if proxy is tls is TBD */

	req->path = "/devices/";
	req->body = 0;

	if (pv_config_get_factory_autotok() && strcmp(pv_config_get_factory_autotok(), "")) {
		req->headers = calloc(1, 2 * sizeof(char *));
		req->headers[0] = calloc(1, sizeof(DEVICE_TOKEN_FMT) + 64);
		sprintf(req->headers[0], DEVICE_TOKEN_FMT, pv_config_get_factory_autotok());
	} else {
		req->headers = 0;
	}

	req->body_content_type = "application/json";

	pv_log(WARN, "host/port/proxy/port=path pv_ph_register_self_builtin %s/%d/%s/%d=%s\n", req->host, req->port, req->host_proxy, req->port_proxy, req->path);

	res = thttp_request_do(req);

	// If registered, override in-memory PantaHub credentials
	if (res->code == THTTP_STATUS_OK && res->body) {
		jsmnutil_parse_json(res->body, &tokv, &tokc);
		pv_config_set_creds_id(pv_json_get_value(res->body, "id", tokv, tokc));
		pv_config_set_creds_prn(pv_json_get_value(res->body, "prn", tokv, tokc));
		pv_config_set_creds_secret(pv_json_get_value(res->body, "secret", tokv, tokc));
	} else {
		pv_log(ERROR, "registration attempt failed (http code %d)", res->code);
		ret = 0;
	}

	if (req->headers) {
		free(req->headers[0]);
		free(req->headers);
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
		HUB_CREDS_TYPE_BUILTIN=0,
		HUB_CREDS_TYPE_EXTERNAL,
		HUB_CREDS_TYPE_ERROR
	} creds_type;

	if (!strcmp(pv_config_get_creds_type(), "builtin")) {
		creds_type = HUB_CREDS_TYPE_BUILTIN;
	} else if(strlen(pv_config_get_creds_type()) >= 4 &&
			!strncmp(pv_config_get_creds_type(), "ext-", 4)) {
		struct stat sb;
		int rv;

		// if no executable handler is found; fall back to builtin
		sprintf(cmd, PANTAVISOR_EXTERNAL_REGISTER_HANDLER_FMT,
			pv_config_get_creds_type());
		rv = stat(cmd, &sb);
		if (rv) {
			pv_log(ERROR, "unable to stat trest client for cmd %s: %s", cmd, strerror(errno));
			goto err;
		}
		if (!(sb.st_mode & S_IXUSR)) {
			pv_log(ERROR, "unable to get trest client for cmd %s ... not executable.", cmd);
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
		pv_log(ERROR, "unable to register for creds_type %s. "
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
	int ret = 1;
	char *owner = 0, *challenge = 0;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!ph_client_init(pv)) {
		pv_log(ERROR, "failed to initialize PantaHub connection");
		ret = 0;
		goto out;
	}

	req = trest_make_request(TREST_METHOD_GET,
				 endpoint,
				 0, 0, 0);

	res = trest_do_json_request(client, req);
	if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN, "unable to query device information, code %d", res->code);
		ret = 0;
		goto out;
	}

	owner = pv_json_get_value(res->body, "owner",
			res->json_tokv, res->json_tokc);

	if (owner && (strcmp(owner, "") != 0)) {
		pv_log(DEBUG, "device-owner: '%s'", owner);
		goto out;
	}

	challenge = pv_json_get_value(res->body, "challenge",
			res->json_tokv, res->json_tokc);

	strcpy(*c, challenge);
	ret = 0;

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
	int fd;
	char buf[256];

	fd = open("/pv/device-id", O_TRUNC | O_SYNC | O_RDWR);
	if (!fd) {
		pv_log(INFO, "unable to open device-id hint file");
		return;
	}
	sprintf(buf, "%s\n", pv_config_get_creds_id());
	write(fd, buf, strlen(buf));
	close(fd);

	if (!c)
		return;

	fd = open("/pv/challenge", O_TRUNC | O_SYNC | O_RDWR);
	if (!fd) {
		pv_log(INFO, "unable to open challenge hint file");
		return;
	}
	sprintf(buf, "%s\n", c);
	write(fd, buf, strlen(buf));
	close(fd);
}

int pv_ph_upload_metadata(struct pantavisor *pv, char *metadata)
{
	uint8_t ret = 1;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;
	char buf[256];

	if (!ph_client_init(pv))
		goto out;

	sprintf(buf, "%s%s", endpoint, "/device-meta");

	req = trest_make_request(TREST_METHOD_PATCH,
				 buf,
				 0, 0,
				 metadata);

	res = trest_do_json_request(client, req);
	if (!res->body || res->code != THTTP_STATUS_OK) {
		pv_log(DEBUG, "metadata upload status = %d, body = '%s'", res->code, res->body);
		goto out;
	}

	ret = 0;

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
}
