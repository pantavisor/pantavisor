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

#include "ctrl/sender.h"
#include "utils/socket.h"
#include "platforms.h"
#include "state.h"

#include <event2/bufferevent.h>
#include <event2/http.h>

#include <stdlib.h>
#include <string.h>

#define MODULE_NAME "sender"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static int get_fd_from_request(struct evhttp_request *req)
{
	return bufferevent_getfd(evhttp_connection_get_bufferevent(
		evhttp_request_get_connection(req)));
}

void pv_ctrl_sender_free(struct pv_ctrl_sender *snd)
{
	if (!snd)
		return;
	if (snd->name)
		free(snd->name);

	free(snd);
}

struct pv_ctrl_sender *pv_ctrl_sender_new(struct evhttp_request *req)
{
	int fd = get_fd_from_request(req);

	const char *base_err = "couldn't create pv_ctrl_sender";
	if (fd < 0) {
		pv_log(WARN, "%s, bad fd = %d", base_err, fd);
		return NULL;
	}

	struct pv_ctrl_sender *snd = calloc(1, sizeof(struct pv_ctrl_sender));
	if (!snd) {
		pv_log(WARN, "%s, allocation failed", base_err);
		return NULL;
	}

	snd->method = evhttp_request_get_command(req);

	errno = 0;
	pid_t snd_pid = pv_socket_get_sender_pid(fd);
	if (snd_pid < 0) {
		pv_log(WARN, "%s, error requesting pid: %s (%d)", base_err,
		       strerror(errno), errno);
		goto err;
	}

	snd->name = pv_cgroup_get_process_name(snd_pid);

	struct pantavisor *pv = pv_get_instance();
	snd->plat = pv_state_fetch_platform(pv->state, snd->name);
	if (!snd->plat) {
		pv_log(WARN, "%s, platform %s not found in current state",
		       base_err, snd->name);
		goto err;
	}

	if (!strncmp(snd->name, "_pv_", strlen(snd->name)))
		snd->is_privileged = true;
	else
		snd->is_privileged =
			pv_platform_has_role(snd->plat, PLAT_ROLE_MGMT);

	return snd;

err:
	pv_ctrl_sender_free(snd);
	return NULL;
}
