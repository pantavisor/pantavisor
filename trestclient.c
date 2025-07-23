/*
 * Copyright (c) 2020-2024 Pantacor Ltd.
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

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>

#include <jsmn/jsmnutil.h>

#include "trestclient.h"

#include "pantahub/pantahub.h"

#include "utils/tsh.h"
#include "utils/str.h"

#define MODULE_NAME "client"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PANTAVISOR_EXTERNAL_LOGIN_HANDLER_FMT "/btools/%s.login"
#define PV_TRESTCLIENT_MAX_READ 4096

static struct trest_response *external_login_handler(trest_ptr self, void *data)
{
	char loginhandler_cmd[PATH_MAX];
	int fd_outerr[2];
	struct trest_response *response;
	struct pantavisor *pv;
	char buf[PV_TRESTCLIENT_MAX_READ];
	int read_c, body_s, s;

	const char *type = pv_config_get_str(PH_CREDS_TYPE);

	pv = NULL;
	response = NULL;

	response = calloc(sizeof(struct trest_response), 1);
	if (!response) {
		perror(NULL);
		pv_log(ERROR, "unable to allocate response struct");
		goto err;
	}

	pv = data;
	if (!pv) {
		pv_log(ERROR,
		       "login handler without pantavisor in 'data' called. Misconfiguration.");
		goto err;
	}

	pv_log(INFO, "external login handler called for creds type '%s'", type);

	SNPRINTF_WTRUNC(loginhandler_cmd, sizeof(loginhandler_cmd),
			PANTAVISOR_EXTERNAL_LOGIN_HANDLER_FMT, type);

	if (pipe(fd_outerr) < 0) {
		pv_log(ERROR,
		       "unable to setup pipe for reading login handler output: %s",
		       strerror(errno));
		goto err;
	}

	tsh_run_io(loginhandler_cmd, 0, NULL, NULL, fd_outerr, fd_outerr);
	close(fd_outerr[1]); // close writing end of this pipe

	// reset read counter and setup read body
	read_c = 0;
	response->body = malloc((size_t)PV_TRESTCLIENT_MAX_READ);
	body_s = PV_TRESTCLIENT_MAX_READ;
	response->body[0] = '\0';
	while ((s = read(fd_outerr[0], buf, sizeof(buf))) != 0) {
		if (s == -1) {
			if (errno == EINTR)
				continue;
			pv_log(ERROR,
			       "error reading from login handler pipe: %s",
			       strerror(errno));
			goto errfd;
		}
		if (!s)
			break;

		while (read_c + s > body_s) {
			void *newb = realloc(response->body,
					     body_s + PV_TRESTCLIENT_MAX_READ);
			if (!newb) {
				pv_log(ERROR,
				       "error allocating buf for login handler response: %s",
				       strerror(errno));
				goto errfd;
			}
			response->body = newb;
			body_s += PV_TRESTCLIENT_MAX_READ;
		}
		memcpy(response->body + read_c, buf, s);
		read_c += s;
	}
	response->body[read_c] = '\0';
	close(fd_outerr[0]);

	pv_log(INFO, "login handler response body: %s", response->body);

	response->json_tokc = jsmnutil_parse_json(
		response->body, &response->json_tokv, &response->json_toks);

	if (!response->json_tokc) {
		// XXX: update auth status of response?
		pv_log(ERROR, "error parsing login handler response %s",
		       response->body);
		goto err;
	}

	// XXX: this for now is just here for completeness.
	response->code = THTTP_STATUS_OK;

	return response;

errfd:
	close(fd_outerr[0]);
err:
	if (response)
		response->code = THTTP_STATUS_INTERNAL_SERVER_ERROR;

	return response;
}

trest_ptr pv_get_trest_client(struct pantavisor *pv, struct pv_connection *conn)
{
	const char **cafiles;
	trest_ptr client;

	if (!conn)
		conn = pv->conn;

	enum {
		HUB_CREDS_TYPE_BUILTIN = 0,
		HUB_CREDS_TYPE_EXTERNAL,
		HUB_CREDS_TYPE_ERROR
	} creds_type;

	// Make sure values are reasonable
	const char *host = pv_config_get_str(PH_CREDS_HOST);
	int port = pv_config_get_int(PH_CREDS_PORT);
	if (!host || (strcmp(host, "") == 0))
		return NULL;

	const char *type = pv_config_get_str(PH_CREDS_TYPE);
	const char *prn = pv_config_get_str(PH_CREDS_PRN);
	const char *secret = pv_config_get_str(PH_CREDS_SECRET);
	char *proxy_host = pv_config_get_str(PH_CREDS_PROXY_HOST);
	int proxy_port = pv_config_get_int(PH_CREDS_PROXY_PORT);
	int noproxyconnect = pv_config_get_int(PH_CREDS_PROXY_NOPROXYCONNECT);

	if (!strcmp(type, "builtin")) {
		creds_type = HUB_CREDS_TYPE_BUILTIN;
	} else if (strlen(type) >= 4 && !strncmp(type, "ext-", 4)) {
		char cmd[PATH_MAX];
		struct stat sb;
		int rv;

		// if no executable handler is found; fall back to builtin
		SNPRINTF_WTRUNC(cmd, sizeof(cmd),
				PANTAVISOR_EXTERNAL_LOGIN_HANDLER_FMT, type);

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

	cafiles = pv_ph_get_certs();
	if (!cafiles) {
		pv_log(ERROR, "unable to assemble cert list");
		goto err;
	}

	switch (creds_type) {
	case HUB_CREDS_TYPE_BUILTIN:
		// Create client

		if (!prn || (strcmp(prn, "") == 0) || !secret ||
		    (strcmp(secret, "") == 0)) {
			goto err;
		}

		client = trest_new_tls_from_userpass(host, port, prn, secret,
						     (const char **)cafiles,
						     pv_user_agent,
						     (conn ? NULL : NULL));

		if (!client) {
			pv_log(INFO, "unable to create device client");
			goto err;
		}
		break;
	case HUB_CREDS_TYPE_EXTERNAL:
		client = trest_new_tls_with_login_handler(
			host, port, external_login_handler, pv,
			(const char **)cafiles, pv_user_agent,
			(conn ? NULL : NULL));

		if (!client) {
			pv_log(INFO, "unable to create device client");
			goto err;
		}
		break;
	default:
		pv_log(ERROR,
		       "unable to get trest client for creds_type %s. "
		       "Currently supported: builtin and ext-* handlers",
		       type);
		goto err;
	}

	// a proxy -> dont use tls unless proxyconnect configured
	if (proxy_host) {
		trest_set_proxy_connect(client, proxy_host, proxy_port, false,
					!noproxyconnect);
	}

	return client;
err:
	return NULL;
}
