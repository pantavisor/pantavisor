/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#include "phlogger_client.h"
#include "trestclient.h"
#include "pantahub.h"

#include <trest.h>
#include <stdlib.h>

#define MODULE_NAME "phlogger_client"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct phlogger_client {
	trest_ptr *cli;
	struct pv_connection *endpoint;
};

static struct pantavisor *pv_global;

struct phlogger_client *pv_phlogger_client_new()
{
	struct phlogger_client *ph = calloc(1, sizeof(struct phlogger_client));
	if (!ph)
		return NULL;

	ph->endpoint = pv_get_instance_connection();
	if (!ph->endpoint) {
		pv_log(ERROR, "couldn't allocate endpoint");
		goto err;
	}

	ph->cli = pv_get_trest_client(pv_global, ph->endpoint);
	if (!ph->cli) {
		pv_log(ERROR, "couldn't allocate client");
		goto err;
	}

	pv_log(DEBUG, "connection OK host: %s:%d", ph->endpoint->hostorip,
	       ph->endpoint->port);

	return ph;
err:
	pv_phlogger_client_free(ph);
	return NULL;
}

void pv_phlogger_client_free(struct phlogger_client *ph)
{
	if (ph->cli)
		trest_free(ph->cli);
	if (ph->endpoint)
		free(ph->endpoint);
	free(ph);
}

int pv_phlogger_client_send_logs(struct phlogger_client *ph, char *logs)
{
	if (!ph)
		return -1;

	trest_request_ptr req = NULL;
	trest_response_ptr rsp = NULL;
	trest_auth_status_enum status = trest_update_auth(ph->cli);

	int ret = -1;

	if (status != TREST_AUTH_STATUS_OK) {
		pv_log(DEBUG, "couldn't authenticate with the hub");
		goto out;
	}

	req = trest_make_request(THTTP_METHOD_POST, "/logs/", logs);
	if (!req) {
		pv_log(DEBUG, "couldn't create the request");
		goto out;
	}

	rsp = trest_do_json_request(ph->cli, req);
	if (!rsp) {
		pv_log(WARN,
		       "HTTP request POST /logs/ could not be initialized");
	} else if (!rsp->code && rsp->status != TREST_AUTH_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request POST /logs/ could not auth (status = %d)",
		       rsp->status);
	} else if (rsp->code != THTTP_STATUS_OK) {
		pv_log(WARN,
		       "HTTP request POST /logs/ returned HTTP error (code = %d; body = '%s')",
		       rsp->code, rsp->body);
	} else {
		ret = 0;
	}

out:
	if (req)
		trest_request_free(req);
	if (rsp)
		trest_response_free(rsp);

	return ret;
}