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
#include <limits.h>

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
#include "device.h"

#include "pantahub.h"
#include "trestclient.h"
#include "tsh.h"

#define ENDPOINT_FMT "/devices/%s"

trest_ptr *client = 0;
char *endpoint = 0;

int connect_try(struct sockaddr *serv)
{
	int ret, fd;
	socklen_t len;
	struct timeval tv;
	fd_set fdset;

	fd = socket(serv->sa_family, SOCK_STREAM, IPPROTO_IP);
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

	do {
		ret = select(fd + 1, 0, &fdset, 0, &tv);
	}while( (ret < 0) && (errno == EINTR));

	if (ret == 1) {
		len = sizeof(ret);
		getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len);
	} else {
		ret = -1;
	}

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

	client = pv_get_trest_client(pv, NULL);

	if (!client)
		return 0;

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

const char** pv_ph_get_certs(struct pantavisor *__unused)
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
		free(files[n]);
	}

	free(files);

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

/*
 * Returns 0 on success and out can be used,
 * a negative value otherwise and out can't be used.
 *
 * TODO: Add IPv6
 * */

static int pv_do_ph_resolve(const char *ph_host, int port, struct pv_connection *pv_conn)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *result = 0, *rp = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family |= AF_UNSPEC;

	ret = getaddrinfo(ph_host, NULL, &hints, &result);
	if (ret < 0) {
		pv_log(DEBUG, "ph_host = %s, ret=%d errno=%d", ph_host, ret, errno);
		goto out;
	}
	ret = -1;
	rp = result;
	while (rp) {

		struct sockaddr *sock = rp->ai_addr;

		if  (rp->ai_family == AF_INET) {
			
			struct sockaddr_in *_sock = (struct sockaddr_in *) rp->ai_addr;
			_sock->sin_family = AF_INET;
			_sock->sin_port = htons(port);

		} else if (rp->ai_family == AF_INET6) {

			struct sockaddr_in6 *_sock = (struct sockaddr_in6 *) rp->ai_addr;
			_sock->sin6_family = AF_INET6;
			_sock->sin6_port = htons(port);
		}

		if (connect_try(sock) == 0) {
			memcpy(&pv_conn->sock, sock, sizeof(*sock));
			pv_conn->since = time(NULL);
			ret = 0;
			break;
		}
		rp = rp->ai_next;
	}
	freeaddrinfo(result);
out:
	return ret;

}

struct pv_connection* pv_get_pv_connection(struct pantavisor_config *config)
{
	struct pv_connection *conn = NULL;
	int ret = 1;
	int port = 0;
	char *host = NULL;
	char dbg_addr[INET6_ADDRSTRLEN];

	conn = (struct pv_connection*)calloc(1, sizeof(struct pv_connection));
	if (!conn) {
		pv_log(DEBUG, "Unable to allocate memory for connection\n");
		goto out;
	}
	// default to global PH instance
	if (strcmp(config->creds.host, "") == 0)
		host = "api.pantahub.com";
	else
		host = config->creds.host;

	port = config->creds.port;
	if (!port)
		port = 443;
	ret = pv_do_ph_resolve(host, port, conn);
out:
	if (!ret) {
		void *ip = NULL;
		switch(conn->sock.sa_family) {
			case AF_INET6:
				ip = &((struct sockaddr_in6*)&conn->sock)->sin6_addr;
				break;
			case AF_INET:
			default:
				ip = &((struct sockaddr_in*)&conn->sock)->sin_addr;
				break;
		}
		pv_log(DEBUG, "PH available at '%s:%d'",
			inet_ntop(conn->sock.sa_family, ip, dbg_addr, sizeof(dbg_addr)),
			( conn->sock.sa_family == AF_INET ?
			ntohs(((struct sockaddr_in*)&conn->sock)->sin_port):
			ntohs(((struct sockaddr_in6*)&conn->sock)->sin6_port) 
			)
			);
	} else {
		pv_log(DEBUG, "unable to reach Pantahub");
		if (conn) {
			void *ip = NULL;
			switch(conn->sock.sa_family) {
			case AF_INET6:
				ip = &((struct sockaddr_in6*)&conn->sock)->sin6_addr;
				break;
			case AF_INET:
			default:
				ip = &((struct sockaddr_in*)&conn->sock)->sin_addr;
				break;
			}
			pv_log(DEBUG, "freeing connection socket for %s:%d",
					inet_ntop(conn->sock.sa_family, ip, dbg_addr, sizeof(dbg_addr)),
					( conn->sock.sa_family == AF_INET ?
					  ntohs(((struct sockaddr_in*)&conn->sock)->sin_port):
					  ntohs(((struct sockaddr_in6*)&conn->sock)->sin6_port) 
					)
			      );
			free(conn);
			conn = NULL;
		}
	}
	return conn;
}

int pv_ph_is_available(struct pantavisor *pv)
{
	struct pv_connection *conn = NULL;
	
	if (pv)
		conn = pv->conn;
	else
		return 0;

	if (conn && !connect_try(&conn->sock)) {
		void *ip = NULL;
		char dbg_addr[INET6_ADDRSTRLEN];

		switch(conn->sock.sa_family) {
		case AF_INET6:
			ip = &((struct sockaddr_in6*)&conn->sock)->sin6_addr;
			break;
		case AF_INET:
		default:
			ip = &((struct sockaddr_in*)&conn->sock)->sin_addr;
			break;
		}
		pv_log(DEBUG, "PH available at '%s:%d'",
			inet_ntop(conn->sock.sa_family, ip, dbg_addr, sizeof(dbg_addr)),
			( conn->sock.sa_family == AF_INET ?
			ntohs(((struct sockaddr_in*)&conn->sock)->sin_port):
			ntohs(((struct sockaddr_in6*)&conn->sock)->sin6_port) 
			)
			);
		goto out;
	}
	/*
	 * Free the old connection first.
	 * */
	if (conn)
		free(conn);
	pv->conn = pv_get_pv_connection(pv->config);
out:
	pv_ph_set_online(pv, pv->conn ? 1 : 0);

	return !!pv->conn;
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
	if (!req)
		goto out;
	res = trest_do_json_request(client, req);
	if (!res)
		goto out;
	if (!res->body || res->code != THTTP_STATUS_OK) {
		pv_log(DEBUG, "logs upload status = %d, body = '%s'", 
				res->code, (res->body ? res->body : ""));
		if (res->code == THTTP_STATUS_BAD_REQUEST)
			ret = 1;
		goto out;
	}

	ret = 1;

out:
	if (req)
		trest_request_free(req);
	if (res)
		trest_response_free(res);

	return ret;
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

	ret = pv_device_update_usermeta(pv, res->body);

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

	req->host = pv->config->creds.host;
	req->port = pv->config->creds.port;

	req->path = "/devices/";
	req->body = 0;
	if (pv->conn)
		req->conn = pv->conn->sock;

	if (pv->config->factory.autotok && strcmp(pv->config->factory.autotok, "")) {
		req->headers = calloc(1, 2 * sizeof(char *));
		req->headers[0] = calloc(1, sizeof(DEVICE_TOKEN_FMT) + 64);
		sprintf(req->headers[0], DEVICE_TOKEN_FMT, pv->config->factory.autotok);
	} else {
		req->headers = 0;
	}

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
	char config_path[PATH_MAX];

	if (tsh_run(cmd, 1, &status) < 0) {
		pv_log(ERROR, "registration attempt with cmd: %s", cmd);
		goto exit;
	}

	// If registered, override in-memory PantaHub credentials
	sprintf(config_path, "%s/config/pantahub.config", pv->config->storage.mntpoint);
	if (ph_config_from_file(config_path, pv->config) < 0) {
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

        if (!strcmp(pv->config->creds.type, "builtin")) {
		creds_type = HUB_CREDS_TYPE_BUILTIN;
	} else if(strlen(pv->config->creds.type) >= 4 &&
			!strncmp(pv->config->creds.type, "ext-", 4)) {
		struct stat sb;
		int rv;

		// if no executable handler is found; fall back to builtin
		sprintf(cmd, PANTAVISOR_EXTERNAL_REGISTER_HANDLER_FMT,
			pv->config->creds.type);
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
				pv->config->creds.type);
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
				pv->config->creds.type);
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
	sprintf(buf, "%s\n", pv->config->creds.id);
	write(fd, buf, strlen(buf));
	close(fd);

	fd = open("/pv/challenge", O_TRUNC | O_SYNC | O_RDWR);
	if (!fd) {
		pv_log(INFO, "unable to open challenge hint file");
		return;
	}
	sprintf(buf, "%s\n", c);
	write(fd, buf, strlen(buf));
	close(fd);
}

uint8_t pv_ph_upload_metadata(struct pantavisor *pv, char *metadata)
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
