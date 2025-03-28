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
#include <stdio.h>
#include <uev/uev.h>

#include "phclient/log.h"
#include "phclient/creds.h"
#include "phclient/local.h"
#include "phclient/remote.h"

#define BUFFER_SIZE 8192

typedef enum {
	PH_CLIENT_STATE_INIT,
	PH_CLIENT_STATE_IDLE,
	PH_CLIENT_STATE_MAX
} ph_client_state_t;

static const char *_state_string(ph_client_state_t state)
{
	switch (state) {
	case PH_CLIENT_STATE_INIT:
		return "PH_CLIENT_STATE_INIT";
	case PH_CLIENT_STATE_IDLE:
		return "PH_CLIENT_STATE_IDLE";
	default:
		return "PH_CLIENT_STATE_UNKNOWN";
	}

	return "PH_CLIENT_STATE_UNKNOWN";
}

static ph_client_state_t state;
static struct ph_creds creds;

static void _state_init()
{
	char buffer[BUFFER_SIZE];
	if (ph_local_get_creds(buffer, BUFFER_SIZE) < 0) {
		ph_log(WARN, "could not get config");
		return;
	}

	ph_creds_init(&creds);
	if (ph_creds_parse(buffer, &creds) < 0) {
		ph_log(WARN, "could not parse config");
		return;
	}

	ph_creds_print(&creds);

	state = PH_CLIENT_STATE_IDLE;
}

static void _read_usrmeta_response(uev_t *w, void *arg, int events)
{
	ph_log(DEBUG, "processing usrmeta response event...");

	struct ctx_trest *trest_ctx = (struct ctx_trest *)arg;

	if (UEV_ERROR == events) {
		ph_log(ERROR,
		       "problem with usermeta response, attempting to restart");
		uev_io_start(w);
		return;
	}

	char *response = ph_remote_read_response(trest_ctx);
	if (!response) {
		ph_log(WARN, "no response from event");
		return;
	}

	if (UEV_HUP == events) {
		ph_log(WARN, "hangup event");
		free(response);
		return;
	}

	ph_log(DEBUG, "parsing response '%s'...", response);

	free(trest_ctx);
	free(response);
	free(w);
}

static void _read_devmeta_response(uev_t *w, void *arg, int events)
{
	ph_log(DEBUG, "processing devmeta response event...");

	struct ctx_trest *trest_ctx = (struct ctx_trest *)arg;

	if (UEV_ERROR == events) {
		ph_log(ERROR,
		       "problem with usermeta response, attempting to restart");
		uev_io_start(w);
		return;
	}

	char *response = ph_remote_read_response(trest_ctx);
	if (!response) {
		ph_log(WARN, "no response from event");
		return;
	}

	if (UEV_HUP == events) {
		ph_log(WARN, "hangup event");
		free(response);
		return;
	}

	ph_log(DEBUG, "parsing response '%s'...", response);

	free(trest_ctx);
	free(response);
	free(w);
}

static void _state_idle(uev_ctx_t *uev_ctx)
{
	struct ctx_trest *trest_ctx = ph_remote_get_usrmeta(&creds);
	uev_t *response = calloc(1, sizeof(uev_t));
	uev_io_init(uev_ctx, response, _read_usrmeta_response,
		    (void *)trest_ctx, trest_ctx->plain.server_fd, UEV_READ);

	char *devmeta = NULL;
	char buffer[BUFFER_SIZE];
	if (ph_local_get_devmeta(buffer, BUFFER_SIZE) < 0) {
		ph_log(WARN, "could not get devmeta");
		return;
	}
	trest_ctx = ph_remote_put_devmeta(&creds, buffer);
	response = calloc(1, sizeof(uev_t));
	uev_io_init(uev_ctx, response, _read_devmeta_response,
		    (void *)trest_ctx, trest_ctx->plain.server_fd, UEV_READ);
}

static void _state_machine(uev_t *w, void *arg, int events)
{
	if (UEV_ERROR == events) {
		ph_log(ERROR, "problem with timer, attempting to restart");
		uev_timer_start(w);
		return;
	}

	uev_ctx_t *ctx = (uev_ctx_t *)arg;

	ph_log(DEBUG, "next state: '%s'", _state_string(state));

	switch (state) {
	case PH_CLIENT_STATE_INIT:
		_state_init();
		break;
	case PH_CLIENT_STATE_IDLE:
		_state_idle(ctx);
		break;
	default:
		ph_log(WARN, "unknown state");
	}
}

int main(void)
{
	state = PH_CLIENT_STATE_INIT;

	uev_ctx_t ctx;
	uev_t timer;
	uev_init(&ctx);
	uev_timer_init(&ctx, &timer, _state_machine, (void *)&ctx, 2 * 1000,
		       2 * 1000);

	return uev_run(&ctx, 0);
}
