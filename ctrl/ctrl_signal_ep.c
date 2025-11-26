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

#include "ctrl_endpoints.h"
#include "ctrl.h"
#include "ctrl_caller.h"
#include "ctrl_util.h"
#include "state.h"
#include "pantavisor.h"
#include "json.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>

#define MODULE_NAME "signal-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define CTRL_SIGNAL_MAX_SIZE (4096)

struct pv_ctrl_signal {
	char *type;
	char *payload;
};

static struct pv_ctrl_signal signal_parse(const char *buf)
{
	int tokc;
	jsmntok_t *tokv;
	jsmnutil_parse_json(buf, &tokv, &tokc);

	struct pv_ctrl_signal sig = { 0 };

	sig.type = pv_json_get_value(buf, "type", tokv, tokc);
	if (!sig.type)
		pv_log(WARN, "unable to get type value from signal");

	sig.payload = pv_json_get_value(buf, "payload", tokv, tokc);
	if (!sig.payload)
		pv_log(WARN, "unable to get payload value from signal");

	if (tokv)
		free(tokv);

	return sig;
}

static void signal_process(struct evhttp_request *req, void *ctx)
{
	if (pv_ctrl_utils_is_req_ok(req, ctx, NULL) != 0)
		return;

	struct pv_ctrl_signal sig = { 0 };
	struct pantavisor *pv = pv_get_instance();

	char *data = pv_ctrl_utils_get_data(req, CTRL_SIGNAL_MAX_SIZE, NULL);
	if (!data) {
		pv_log(WARN, "nothing to read from signal request");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Signal has bad format");
		return;
	}

	sig = signal_parse(data);

	if (!sig.type) {
		pv_log(WARN, "unable to parse signal");
		pv_ctrl_utils_send_error(req, HTTP_BADREQUEST,
					 "Signal has bad format");
		goto out;
	}

	struct pv_ctrl_caller caller = { 0 };
	if (pv_ctrl_caller_init(&caller, req) != 0) {
		pv_log(WARN, "couldn't get caller info");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL, "Internal error");
		goto out;
	}

	pv_log(DEBUG, "received signal %s: %s", sig.type, sig.payload);

	int ret = pv_state_interpret_signal(pv->state, caller.plat->name,
					    sig.type, sig.payload);
	if (ret != 0) {
		pv_ctrl_utils_send_error(
			req, HTTP_INTERNAL,
			"Signal not expected from this platform");
		goto out;
	}

	pv_ctrl_utils_send_ok(req);

out:
	if (data)
		free(data);

	if (sig.type)
		free(sig.type);

	if (sig.payload)
		free(sig.payload);
}

int pv_ctrl_endpoints_signal_init()
{
	pv_ctrl_add_endpoint("/signal", EVHTTP_REQ_POST, false, signal_process);
	return 0;
}