/*
 * Copyright (c) 2017 Pantacor Ltd.
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

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <trest.h>
#include <thttp.h>

#define MODULE_NAME             "pantahub-api"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "pantavisor.h"
#include "utils.h"

#include "pantahub.h"

#define DEVICE_REGISTER_FMT "{ \"secret\" : \"%s\" }"
#define ENDPOINT_FMT "/devices/%s"

trest_ptr *client = 0;
char *endpoint = 0;
struct sockaddr_in *conn;

static int connect_try(struct sockaddr_in *serv)
{
	int ret, fd;
	socklen_t len;
	struct timeval tv;
	fd_set fdset;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	fcntl(fd, F_SETFL, O_NONBLOCK);

	ret = connect(fd, (struct sockaddr *) serv, sizeof (*serv));
	if (!ret)
		goto out;

	if (errno != EINPROGRESS)
		goto out;

	// 2 second timeout
	tv.tv_sec = 2;
	tv.tv_usec = 0;

	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);

	if (select(fd + 1, 0, &fdset, 0, &tv) <= 0)
		goto out;

	len = sizeof(ret);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len);

out:
	close(fd);

	return ret;
}

static int ph_client_init(struct pantavisor *pv)
{
	int size;
        trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	if (client)
		goto auth;

	client = trest_new_tls_from_userpass(
			pv->config->creds.host,
			pv->config->creds.port,
			pv->config->creds.prn,
			pv->config->creds.secret,
			pv_ph_get_certs(pv)
			);

auth:
	if (!pv->online)
		return 0;

	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK)
		return 0;

	if (!endpoint) {
		size = sizeof(ENDPOINT_FMT) + strlen(pv->config->creds.id) + 1;
		endpoint = malloc(size * sizeof(char));
		sprintf(endpoint, ENDPOINT_FMT, pv->config->creds.id);
	}

	return 1;
}

/* API */

const char** pv_ph_get_certs(struct pantavisor *pv)
{
	struct dirent **files;
	char **cafiles;
	char *dir = "/certs/";
	char path[128];
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
		strncpy(cafiles[i], path, size);
		cafiles[i][size] = '\0';
		i++;
	}

	return (const char **) cafiles;
}

static void pv_ph_set_online(struct pantavisor *pv, int online)
{
	int fd, hint;
	char *path = "/pv/online";
	struct stat st;

	hint = stat(path, &st) ? 0 : 1;

	switch (online) {
	case 0:
		if (hint)
			remove(path);
		break;
	default:
		if (!hint) {
			fd = open(path, O_CREAT | O_SYNC, 0400);
			close(fd);
		}
		break;
	}

	pv->online = online;
}

int pv_ph_is_available(struct pantavisor *pv)
{
	int ret = 1;
	int port = 0;
	struct addrinfo hints;
	struct addrinfo *result = 0, *rp = 0;
	char *host = 0;

	if (conn && !connect_try(conn))
		goto out;

	// default to global PH instance
	if (strcmp(pv->config->creds.host, "") == 0)
		host = "api.pantahub.com";
	else
		host = pv->config->creds.host;

	port = pv->config->creds.port;
	if (!port)
		port = 443;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family |= AF_INET;

	ret = getaddrinfo(host, NULL, &hints, &result);
	if (ret < 0) {
		pv_log(DEBUG, "ret=%d errno=%d", ret, errno);
		goto out;
	}

	rp = result;
	while (rp) {
		struct sockaddr_in *sock = (struct sockaddr_in *) rp->ai_addr;
		sock->sin_family = AF_INET;
		sock->sin_port = htons(port);
		if (connect_try(sock) == 0) {
			ret = 1;
			conn = sock;
			break;
		}
		rp = rp->ai_next;
	}

out:
	if (ret > 0) {
		pv_log(DEBUG, "PH available at '%s:%d'",
			inet_ntoa(conn->sin_addr), ntohs(conn->sin_port));
	} else {
		pv_log(DEBUG, "unable to reach Pantahub");
		if (result)
			freeaddrinfo(result);
		ret = 0;
	}

	pv_ph_set_online(pv, ret);

	return ret;
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

int pv_ph_upload_logs(struct pantavisor *pv, char *logs)
{
	int ret = 0;
	trest_request_ptr req = 0;
	trest_response_ptr res = 0;

	if (!ph_client_init(pv))
		goto out;

	req = trest_make_request(TREST_METHOD_POST,
				 "/logs/",
				 0, 0,
				 logs);

	res = trest_do_json_request(client, req);
	if (!res->body || res->code != THTTP_STATUS_OK) {
		pv_log(DEBUG, "logs upload status = %d, body = '%s'", res->code, res->body);
		if (res->code == THTTP_STATUS_BAD_REQUEST)
			ret = 1;
		goto out;
	}

	ret = 1;

out:
	if (req)
		trest_request_free(req);
	if (req)
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

	id = get_json_key_value(res->body, "id",
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

int pv_ph_register_self(struct pantavisor *pv)
{
	int ret = 1;
	int tokc;
	char json[512];
	char *secret;
	thttp_request_tls_t* tls_req = 0;
	thttp_response_t* res = 0;
	jsmntok_t *tokv;

	tls_req = thttp_request_tls_new_0();
	tls_req->crtfiles = (char **) pv_ph_get_certs(pv);

	thttp_request_t* req = (thttp_request_t*) tls_req;

	req->method = THTTP_METHOD_POST;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;

	req->host = pv->config->creds.host;
	req->port = pv->config->creds.port;

	req->path = "/devices/";

	secret = rand_string(10);
	sprintf(json, DEVICE_REGISTER_FMT, secret);
	req->body = json;

	req->headers = 0;
	req->body_content_type = "application/json";

	res = thttp_request_do(req);

	// If registered, override in-memory PantaHub credentials
	if (res->code == THTTP_STATUS_OK && res->body) {
		jsmnutil_parse_json(res->body, &tokv, &tokc);
		pv->config->creds.id = get_json_key_value(res->body, "id",
							tokv, tokc);
		pv->config->creds.prn = get_json_key_value(res->body, "prn",
							tokv, tokc);
		pv->config->creds.secret = get_json_key_value(res->body, "secret",
							tokv, tokc);
	} else {
		pv_log(ERROR, "registration attempt failed (http code %d)", res->code);
		ret = 0;
	}

	if (secret)
		free(secret);
	if (req)
		thttp_request_free(req);
	if (res)
		thttp_response_free(res);

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

	owner = get_json_key_value(res->body, "owner",
			res->json_tokv, res->json_tokc);

	if (owner && (strcmp(owner, "") != 0)) {
		pv_log(DEBUG, "device-owner: '%s'", owner);
		goto out;
	}

	challenge = get_json_key_value(res->body, "challenge",
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
	sprintf(buf, "device-id=%s\n", pv->config->creds.id);
	write(fd, buf, strlen(buf));
	close(fd);

	fd = open("/pv/challenge", O_TRUNC | O_SYNC | O_RDWR);
	if (!fd) {
		pv_log(INFO, "unable to open challenge hint file");
		return;
	}
	sprintf(buf, "challenge=%s\n", c);
	write(fd, buf, strlen(buf));
	close(fd);
}
