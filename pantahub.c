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

#define MODULE_NAME "pantahub"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define ENDPOINT_FMT "/devices/%s"

trest_ptr *client = 0;
char *endpoint = 0;

static void ph_client_free()
{
	if (!client)
		return;

	trest_free(client);
	client = NULL;
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
	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		ph_client_free();
		return 0;
	}

	const char *id = pv_config_get_str(PH_CREDS_ID);
	if (!id) {
		ph_client_free();
		return 0;
	}

	if (!endpoint) {
		size = sizeof(ENDPOINT_FMT) + strlen(id) + 1;
		endpoint = malloc(size * sizeof(char));
		SNPRINTF_WTRUNC(endpoint, size, ENDPOINT_FMT, id);
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
			if (fd >= 0) {
				close(fd);
				pv_fs_path_sync(path);
			}
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

	if (!ph_client_init(pv)) {
		return false;
	}

	if (client && endpoint)
		goto success;

	pv_ph_set_online(pv, false);
	return false;

success:
	pv_ph_set_online(pv, true);
	return true;
}

const char **pv_ph_get_certs()
{
	struct dirent **files;
	char **cafiles;
	char path[PATH_MAX];
	int n = 0, i = 0, size = 0;

	pv_paths_cert(path, PATH_MAX, "");
	n = scandir(path, &files, NULL, alphasort);
	if (n < 0) {
		pv_log(WARN, "%s could not be scanned", path);
		return NULL;
	} else if (n == 0) {
		pv_log(WARN, "%s is empty", path);
		free(files);
		return NULL;
	}

	// Always n-1 due to . and .., and need one extra
	cafiles = calloc(n - 1, sizeof(char *));

	while (n--) {
		if (!strncmp(files[n]->d_name, ".", 1)) {
			free(files[n]);
			continue;
		}

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
		pv_log(DEBUG, "Unable to allocate memory for connection");
		return NULL;
	}
	// default to global PH instance
	host = pv_config_get_str(PH_CREDS_HOST);
	if (!host || (strcmp(host, "") == 0))
		host = "api.pantahub.com";

	port = pv_config_get_int(PH_CREDS_PORT);
	if (!port)
		port = 443;

	conn->hostorip = host;
	conn->port = port;

	return conn;
}

void pv_ph_release_client(struct pantavisor *pv)
{
	ph_client_free();

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
		goto out;

	char buf[256];
	SNPRINTF_WTRUNC(buf, sizeof(buf), "%s%s", endpoint, "/user-meta");

	req = trest_make_request(THTTP_METHOD_GET, buf, 0);

	res = trest_do_json_request(client, req);
	if (!res) {
		pv_log(WARN, "HTTP request GET %s could not be initialized",
		       buf);
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request GET %s could not auth (status=%d)",
		       buf, res->status);
		ph_client_free();
	} else if (res->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "request GET %s returned HTTP error (code=%d; body='%s')",
		       buf, res->code, res->body);
	} else {
		pv_metadata_parse_usermeta(res->body);
		ret = 0;
	}

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

	req = trest_make_request(THTTP_METHOD_GET, endpoint, 0);

	res = trest_do_json_request(client, req);
	if (!res) {
		pv_log(WARN, "HTTP request GET %s could not be initialized",
		       endpoint);
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN, "HTTP request GET %s could not auth (status=%d)",
		       endpoint, res->status);
		ph_client_free();
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
	tls_req->crtfiles = (char **)pv_ph_get_certs();

	thttp_request_t *req = (thttp_request_t *)tls_req;

	req->method = THTTP_METHOD_POST;
	req->proto = THTTP_PROTO_HTTP;
	req->proto_version = THTTP_PROTO_VERSION_10;
	req->user_agent = pv_user_agent;

	req->host = pv_config_get_str(PH_CREDS_HOST);
	req->port = pv_config_get_int(PH_CREDS_PORT);
	req->host_proxy = pv_config_get_str(PH_CREDS_PROXY_HOST);
	req->port_proxy = pv_config_get_int(PH_CREDS_PROXY_PORT);
	req->proxyconnect = !pv_config_get_int(PH_CREDS_PROXY_NOPROXYCONNECT);

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

	const char *autotok = pv_config_get_str(PH_FACTORY_AUTOTOK);
	if (autotok && strcmp(autotok, "")) {
		headers = calloc(2, sizeof(char *));
		header_size = sizeof(DEVICE_TOKEN_FMT) + 64;
		headers[0] = calloc(header_size, sizeof(char));
		SNPRINTF_WTRUNC(headers[0], header_size, DEVICE_TOKEN_FMT,
				autotok);
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
	int status = -1;

	if (tsh_run(cmd, 1, &status) < 0) {
		pv_log(ERROR, "registration attempt with cmd: %s", cmd);
		return 0;
	}

	return 1;
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

	const char *type = pv_config_get_str(PH_CREDS_TYPE);
	if (!strcmp(type, "builtin")) {
		creds_type = HUB_CREDS_TYPE_BUILTIN;
	} else if (strlen(type) >= 4 && !strncmp(type, "ext-", 4)) {
		struct stat sb;
		int rv;

		// if no executable handler is found; fall back to builtin
		SNPRINTF_WTRUNC(cmd, sizeof(cmd),
				PANTAVISOR_EXTERNAL_REGISTER_HANDLER_FMT, type);
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
		       type);
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
		       type);
		ret = 0;
		goto err;
	}

err:
	return ret;
}

int pv_ph_device_is_owned(struct pantavisor *pv, char **c)
{
	int ret = 0;
	char *owner = 0;
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
		ph_client_free();
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

		*c = pv_json_get_value(res->body, "challenge", res->json_tokv,
				       res->json_tokc);
	}

out:
	if (owner)
		free(owner);
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
	SNPRINTF_WTRUNC(buf, sizeof(buf), "%s\n",
			pv_config_get_str(PH_CREDS_ID));
	if (pv_fs_file_save(path, buf, 0444))
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	if (!c)
		return;

	pv_paths_pv_file(path, PATH_MAX, CHALLENGE_FNAME);
	SNPRINTF_WTRUNC(buf, sizeof(buf), "%s\n", c);
	if (pv_fs_file_save(path, buf, 0444))
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
		ph_client_free();
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

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

typedef enum {
	PH_STATE_INIT,
	PH_STATE_REGISTER,
	PH_STATE_CLAIM,
	PH_STATE_SYNC,
	PH_STATE_IDLE,
	PH_STATE_UPDATE,
	PH_STATE_MAX
} ph_state_t;

static const char *_state_string(ph_state_t state)
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
	case PH_STATE_IDLE:
		return "idle";
	case PH_STATE_UPDATE:
		return "update";
	default:
		return "unknown";
	}

	return "unknown";
}

typedef struct {
	mbedtls_dyncontext *ssl;
	mbedtls_ssl_config config;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_x509_crt cacert;
} mbedtls_t;

typedef struct {
	ph_state_t state;
	mbedtls_t mbedtls;
	char *token;
} pantahub_t;

static pantahub_t ph;

int pv_pantahub_init()
{
	// OLD STUFF. TO BE REMOVED

	struct pantavisor *pv = pv_get_instance();
	char tmp[256], path[PATH_MAX];

	pv_log(DEBUG, "initializing PantacorHub client...");

	const char *prn = pv_config_get_str(PH_CREDS_PRN);
	if (!prn || !strcmp(prn, "")) {
		pv_log(DEBUG, "device is not claimed yet");
		pv->unclaimed = true;
	} else {
		pv_log(DEBUG, "device is already claimed");
		pv->unclaimed = false;
		pv_paths_pv_file(path, PATH_MAX, DEVICE_ID_FNAME);
		SNPRINTF_WTRUNC(tmp, sizeof(tmp), "%s\n",
				pv_config_get_str(PH_CREDS_ID));
		if (pv_fs_file_save(path, tmp, 0444) < 0)
			pv_log(WARN, "could not save file %s: %s", path,
			       strerror(errno));
	}

	pv_paths_pv_file(path, PATH_MAX, PHHOST_FNAME);
	SNPRINTF_WTRUNC(tmp, sizeof(tmp), "https://%s:%d\n",
			pv_config_get_str(PH_CREDS_HOST),
			pv_config_get_int(PH_CREDS_PORT));
	if (pv_fs_file_save(path, tmp, 0444) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	// NEW IMPLEMENTATION

	ph.state = PH_STATE_INIT;
	ph.token = NULL;

	return 0;
}

int pv_pantahub_close()
{
	if (ph.token)
		free(ph.token);
	return pv_config_unload_creds();
}

void _next_state(ph_state_t state)
{
	if (ph.state == state)
		return;

	ph.state = state;
	pv_metadata_add_devmeta(DEVMETA_KEY_PH_STATE, _state_string(state));
}

static void _state_init()
{
	_next_state(PH_STATE_IDLE);
}

static void _err_mbedtls(const char *func, int err)
{
	pv_log(ERROR, "%s failed with code %d\n", func, err);
}

static void _recv_response(struct evhttp_request *req, void *ctx, char *out,
			   int max_len)
{
	if (!req || !evhttp_request_get_response_code(req)) {
		struct bufferevent *bev = (struct bufferevent *)ctx;
		unsigned long oslerr;
		int printed_err = 0;
		int errcode = EVUTIL_SOCKET_ERROR();
		pv_log(WARN, "request failed");
		while ((oslerr = bufferevent_get_mbedtls_error(bev))) {
			_err_mbedtls("bufferevent_get_mbedtls_error", oslerr);
			printed_err = 1;
		}
		if (!printed_err)
			pv_log(WARN, "socket error = %s (%d)\n",
			       evutil_socket_error_to_string(errcode), errcode);
		return;
	}

	pv_log(DEBUG, "response: %d %s\n",
	       evhttp_request_get_response_code(req),
	       evhttp_request_get_response_code_line(req));

	int nread = 0, i = 0;
	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
					out, max_len - i)) > 0) {
		out += nread;
		i += nread;
	}
}

static void _parse_post_auth_body(const char *json)
{
	int tokc;
	jsmntok_t *tokv = NULL;

	if (jsmnutil_parse_json(json, &tokv, &tokc) < 0) {
		goto out;
	}

	ph.token = pv_json_get_value(json, "token", tokv, tokc);

out:
	if (tokv)
		free(tokv);
}

static void _recv_post_auth(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "POST auth response received");
	char buffer[1024];
	memset(&buffer, 0, sizeof(buffer));
	_recv_response(req, ctx, &buffer[0], 1024);
	pv_log(DEBUG, "body: '%s'", buffer);
	_parse_post_auth_body(buffer);
	if (ph.token)
		pv_log(DEBUG, "token: '%s'", ph.token);
}

static void _recv_get_usermeta(struct evhttp_request *req, void *ctx)
{
	pv_log(DEBUG, "GET usermeta response received");
	char buffer[1024];
	memset(&buffer, 0, sizeof(buffer));
	_recv_response(req, ctx, &buffer[0], 1024);
	pv_log(DEBUG, "body: '%s'", buffer);
}

static void _send_request(struct event_base *base, enum evhttp_cmd_type op,
			  const char *uri, const char *body,
			  void (*cb)(struct evhttp_request *, void *))
{
	ph.mbedtls.ssl = NULL;
	mbedtls_x509_crt_init(&ph.mbedtls.cacert);
	mbedtls_ctr_drbg_init(&ph.mbedtls.ctr_drbg);
	mbedtls_entropy_init(&ph.mbedtls.entropy);
	mbedtls_ssl_config_init(&ph.mbedtls.config);

	mbedtls_ctr_drbg_seed(&ph.mbedtls.ctr_drbg, mbedtls_entropy_func,
			      &ph.mbedtls.entropy,
			      (const unsigned char *)"pantavisor",
			      sizeof("pantavisor"));
	mbedtls_ssl_config_defaults(&ph.mbedtls.config, MBEDTLS_SSL_IS_CLIENT,
				    MBEDTLS_SSL_TRANSPORT_STREAM,
				    MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(&ph.mbedtls.config, mbedtls_ctr_drbg_random,
			     &ph.mbedtls.ctr_drbg);

	const char **crts = pv_ph_get_certs();
	int res;
	res = mbedtls_x509_crt_parse_file(&ph.mbedtls.cacert, *crts);
	if (res != 0) {
		_err_mbedtls("mbedtls_x509_crt_parse_file", res);
		goto error;
	}
	mbedtls_ssl_conf_ca_chain(&ph.mbedtls.config, &ph.mbedtls.cacert, NULL);

	ph.mbedtls.ssl = bufferevent_mbedtls_dyncontext_new(&ph.mbedtls.config);

	char *host = pv_config_get_str(PH_CREDS_HOST);
	mbedtls_ssl_set_hostname(ph.mbedtls.ssl, host);

	struct bufferevent *bev;
	bev = bufferevent_mbedtls_socket_new(
		base, -1, ph.mbedtls.ssl, BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		pv_log(ERROR, "bufferevent_mbedtls_socket_new failed");
		goto error;
	}

	bufferevent_mbedtls_set_allow_dirty_shutdown(bev, 1);

	struct evhttp_connection *evcon = NULL;
	int port = pv_config_get_int(PH_CREDS_PORT);
	evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev, host,
						       port);
	if (!evcon) {
		pv_log(ERROR, "evhttp_connection_base_bufferevent_new failed");
		goto error;
	}
	evhttp_connection_set_family(evcon, AF_INET);

	int retries = 2;
	evhttp_connection_set_retries(evcon, retries);

	int timeout = 2;
	evhttp_connection_set_timeout(evcon, timeout);

	struct evhttp_request *req;
	req = evhttp_request_new(cb, bev);
	if (!req) {
		pv_log(ERROR, "evhttp_request_new failed");
		goto error;
	}

	struct evkeyvalq *output_headers;
	output_headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Host", host);
	evhttp_add_header(output_headers, "Connection", "close");
	evhttp_add_header(output_headers, "User-Agent", pv_user_agent);

	if (ph.token) {
		char bearer[1024];
		memset(bearer, 0, sizeof(bearer));
		snprintf(bearer, sizeof(bearer), "Bearer %s", ph.token);

		pv_log(DEBUG, "%s", bearer);
		evhttp_add_header(output_headers, "Authorization", bearer);
	}

	if (body) {
		size_t len = strlen(body);
		pv_log(DEBUG, "body: '%s'; len: %zu", body, len);

		struct evbuffer *output_buffer;
		output_buffer = evhttp_request_get_output_buffer(req);
		evbuffer_add(output_buffer, body, len);

		char buf[64];
		evutil_snprintf(buf, sizeof(buf) - 1, "%zu", len);
		evhttp_add_header(output_headers, "Content-Length", buf);
		evhttp_add_header(output_headers, "Content-Type",
				  "application/json");
	}

	res = evhttp_make_request(evcon, req, op, uri);
	if (res != 0) {
		_err_mbedtls("evhttp_make_request", res);
		goto error;
	}

	//if (evcon)
	//	evhttp_connection_free(evcon);
	//mbedtls_ssl_config_free(&ph.mbedtls.config);
	//mbedtls_ctr_drbg_free(&ph.mbedtls.ctr_drbg);
	//mbedtls_x509_crt_free(&ph.mbedtls.cacert);
	return;
error:
	if (evcon)
		evhttp_connection_free(evcon);
	mbedtls_ssl_config_free(&ph.mbedtls.config);
	mbedtls_ctr_drbg_free(&ph.mbedtls.ctr_drbg);
	mbedtls_x509_crt_free(&ph.mbedtls.cacert);
}

static void _state_idle(struct event_base *base)
{
	char uri[256];
	char body[1024];

	if (!ph.token) {
		snprintf(uri, sizeof(uri), "/auth/login");
		snprintf(body, sizeof(body),
			 "{\"username\":\"%s\",\"password\":\"%s\"}",
			 pv_config_get_str(PH_CREDS_PRN),
			 pv_config_get_str(PH_CREDS_SECRET));
		pv_log(DEBUG, "POST %s", uri);
		_send_request(base, EVHTTP_REQ_POST, uri, body,
			      _recv_post_auth);
	}

	if (ph.token) {
		snprintf(uri, sizeof(uri), "/devices/%s/user-meta",
			 pv_config_get_str(PH_CREDS_ID));

		pv_log(DEBUG, "GET %s", uri);
		_send_request(base, EVHTTP_REQ_GET, uri, NULL,
			      _recv_get_usermeta);
	}
}

int pv_pantahub_step(struct event_base *base)
{
	pv_log(DEBUG, "next state: %s", _state_string(ph.state));

	switch (ph.state) {
	case PH_STATE_INIT:
		_state_init();
		break;
	case PH_STATE_IDLE:
		_state_idle(base);
		break;
	default:
		pv_log(WARN, "state not implemented");
	}
}
