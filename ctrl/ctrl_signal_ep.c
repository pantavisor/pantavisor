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

#include "ctrl/utils.h"
#include "ctrl/handler.h"
#include "ctrl/sender.h"
#include "ctrl/incdata.h"
#include "state.h"
#include "pantavisor.h"
#include "json.h"

#include <event2/http.h>
#include <event2/buffer.h>

#include <string.h>

#define MODULE_NAME "singal-ep"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define PV_CTRL_MAX_REQ_SIZE (4096)

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

static void signal_process(struct evhttp_request *req)
{
	int methods[] = { EVHTTP_REQ_GET, -1 };

	struct pv_ctrl_sender *snd =
		pv_ctrl_utils_checks(MODULE_NAME, req, methods, true);

	if (!snd)
		return;

	struct pv_ctrl_signal sig = { 0 };
	struct pantavisor *pv = pv_get_instance();

	char *data = pv_ctrl_incdata_get_data(req, PV_CTRL_MAX_REQ_SIZE, NULL);
	if (!data) {
		pv_log(WARN, "nothing to read from signal request");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Signal has bad format");
		goto out;
	}

	sig = signal_parse(data);

	if (!sig.type) {
		pv_log(WARN, "unable to parse signal");
		pv_ctrl_utils_send_error(req, HTTP_INTERNAL,
					 "Signal has bad format");
		goto out;
	}

	int ret = pv_state_interpret_signal(pv->state, snd->plat->name,
					    sig.type, sig.payload);
	if (ret != 0) {
		pv_ctrl_utils_send_error(
			req, HTTP_INTERNAL,
			"Signal not expected from this platform");
		goto out;
	}

out:
	if (data)
		free(data);

	if (sig.type)
		free(sig.type);

	if (sig.payload)
		free(sig.payload);

	pv_ctrl_sender_free(snd);
}

static int signal_handler(struct evhttp_request *req)
{
	const char *uri = evhttp_request_get_uri(req);
	char parts[PV_CTRL_UTILS_MAX_PARTS][NAME_MAX] = { 0 };
	int size = pv_ctrl_utils_split_path(uri, parts);

	if (size < 1 || size > 1 || strcmp(parts[0], "singal") != 0)
		return -1;

	signal_process(req);
	return 0;
}

struct pv_ctrl_handler signal_hnd = {
	.path = "/singal",
	.fn = signal_handler,
};