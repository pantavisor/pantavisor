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

#include <stdlib.h>
#include <dirent.h>
#include <string.h>

#include "phclient/remote.h"
#include "phclient/log.h"

trest_ptr *client = 0;

static void _free_client()
{
	if (!client)
		return;

	trest_free(client);
	client = NULL;
}

static const char **_load_ca()
{
	struct dirent **files;
	char **cafiles;
	int n = 0, i = 0, size = 0;

	n = scandir("/opt/pantavisor/certs", &files, NULL, alphasort);
	if (n < 0) {
		ph_log(WARN, "/opt/pantavisor/certs could not be scanned");
		return NULL;
	} else if (n == 0) {
		ph_log(WARN, "/opt/pantavisor/certs is empty");
		free(files);
		return NULL;
	}

	// Always n-1 due to . and .., and need one extra
	cafiles = calloc(n - 1, sizeof(char *));

	char path[PATH_MAX];
	while (n--) {
		if (!strncmp(files[n]->d_name, ".", 1)) {
			free(files[n]);
			continue;
		}

		snprintf(path, PATH_MAX, "/opt/pantavisor/certs/%s",
			 files[n]->d_name);
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

static trest_ptr _new_trest_client(struct ph_creds *creds)
{
	const char **cafiles;
	trest_ptr client = NULL;

	ph_log(DEBUG, "initializing client...");

	cafiles = _load_ca();
	if (!cafiles) {
		ph_log(ERROR, "unable to assemble cert list");
		return client;
	}

	client = trest_new_tls_from_userpass(
		creds->host, creds->port, creds->prn, creds->secret,
		(const char **)cafiles,
		"Pantavisor/2 (Linux; x86_64) PV/019-352-ga35f4ae-250408 Date/250408",
		NULL);
	if (!client) {
		ph_log(INFO, "unable to create device client");
	}

	return client;
}

static int _init_client(struct ph_creds *creds)
{
	int size;
	trest_auth_status_enum status = TREST_AUTH_STATUS_NOTAUTH;

	if (client)
		goto auth;

	client = _new_trest_client(creds);

	if (!client) {
		ph_log(WARN, "client could not be initialized");
		return 0;
	}

auth:
	status = trest_update_auth(client);
	if (status != TREST_AUTH_STATUS_OK) {
		ph_log(WARN, "token could not be retreived");
		_free_client();
		return 0;
	}

	return 1;
}

struct ctx_trest *ph_remote_get_usrmeta(struct ph_creds *creds)
{
	ph_log(DEBUG, "sending GET usrmeta request...");

	struct ctx_trest *ctx = NULL;

	trest_request_ptr req = 0;

	if (!_init_client(creds)) {
		ph_log(WARN, "could not init client");
		goto out;
	}

	char buf[256];
	snprintf(buf, sizeof(buf), "/devices/%s/user-meta", creds->id);

	req = trest_make_request(THTTP_METHOD_GET, buf, 0);

	ctx = calloc(1, sizeof(struct ctx_trest));
	if (trest_send_json_request(client, req, ctx) < 0) {
		ph_log(WARN, "could not send request");
		if (ctx)
			free(ctx);
		ctx = NULL;
		goto out;
	}

out:
	if (req)
		trest_request_free(req);
	return ctx;
}

struct ctx_trest *ph_remote_put_devmeta(struct ph_creds *creds,
					const char *json)
{
	ph_log(DEBUG, "sending PUT devmeta request...");

	struct ctx_trest *ctx = NULL;

	trest_request_ptr req = 0;

	if (!_init_client(creds)) {
		ph_log(WARN, "could not init client");
		goto out;
	}

	char buf[256];
	snprintf(buf, sizeof(buf), "/devices/%s/device-meta", creds->id);

	req = trest_make_request(THTTP_METHOD_PATCH, buf, (char *)json);

	ctx = calloc(1, sizeof(struct ctx_trest));
	if (trest_send_json_request(client, req, ctx) < 0) {
		ph_log(WARN, "could not send request");
		if (ctx)
			free(ctx);
		ctx = NULL;
		goto out;
	}

out:
	if (req)
		trest_request_free(req);
	return ctx;
}

char *ph_remote_read_response(struct ctx_trest *ctx)
{
	ph_log(DEBUG, "reading response...");

	char *body = NULL;
	trest_response_ptr res = 0;

	res = trest_recv_json_response(client, ctx);
	if (!res) {
		ph_log(WARN, "could not be initialized");
	} else if (!res->code && res->status != TREST_AUTH_STATUS_OK) {
		ph_log(WARN, "could not auth (status=%d)", res->status);
		_free_client();
	} else if (res->code != THTTP_STATUS_OK) {
		ph_log(WARN, "returned HTTP error (code=%d; body='%s')",
		       res->code, res->body);
	} else {
		body = strdup(res->body);
	}

	if (res)
		trest_response_free(res);

	return body;
}
