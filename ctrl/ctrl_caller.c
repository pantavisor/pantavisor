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

#include "ctrl_caller.h"
#include "pantavisor.h"
#include "platforms.h"
#include "socket.h"
#include "state.h"

#include <event2/http.h>
#include <event2/bufferevent.h>

#include <string.h>

#define MODULE_NAME "ctrl-caller"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static int ctrl_caller_get_fd(struct evhttp_request *req)
{
	return bufferevent_getfd(evhttp_connection_get_bufferevent(
		evhttp_request_get_connection(req)));
}

int pv_ctrl_caller_init(struct pv_ctrl_caller *caller,
			struct evhttp_request *req)
{
	pid_t pid = pv_socket_get_sender_pid(ctrl_caller_get_fd(req));
	if (pid < 0) {
		pv_log(WARN, "error requesting pid: %s (%d)", strerror(errno));
		return -1;
	}

	char *name = pv_cgroup_get_process_name(pid);
	if (!name) {
		pv_log(WARN, "couldn't get process name for pid = %d", pid);
		return -1;
	}

	int ret = -1;
	caller->method = evhttp_request_get_command(req);

	struct pantavisor *pv = pv_get_instance();
	caller->plat = pv_state_fetch_platform(pv->state, name);
	if (!caller->plat) {
		pv_log(WARN, "platform %s not found in current state", name);
		goto out;
	}

	if (!strncmp(name, "_pv_", strlen(name)))
		caller->is_privileged = true;
	else
		caller->is_privileged =
			pv_platform_has_role(caller->plat, PLAT_ROLE_MGMT);
	ret = 0;
out:
	if (name)
		free(name);

	return ret;
}