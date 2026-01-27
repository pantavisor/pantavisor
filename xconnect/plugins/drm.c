/*
 * Copyright (c) 2026 Pantacor Ltd.
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
#include <string.h>
#include "../include/xconnect.h"

#define MODULE_NAME "pvx-drm"

static int drm_on_link_added(struct pvx_link *link)
{
	if (!link->consumer || !link->consumer_socket || !link->provider_socket)
		return -1;

	printf("%s: Adding DRM link for %s (role: %s)\n", MODULE_NAME,
	       link->consumer, link->role ? link->role : "none");
	printf("%s: Target: %s, Provider Node: %s\n", MODULE_NAME,
	       link->consumer_socket, link->provider_socket);
	if (link->consumer_pid <= 0) {
		fprintf(stderr,
			"%s: Consumer PID required for device injection\n",
			MODULE_NAME);
		return -1;
	}

	printf("%s: Calling helper to inject devnode...\n", MODULE_NAME);
	int ret = pvx_helper_inject_devnode(link->consumer_socket,
					    link->consumer_pid,
					    link->provider_socket,
					    link->provider_pid);
	printf("%s: Helper returned %d\n", MODULE_NAME, ret);
	if (ret < 0) {
		fprintf(stderr, "%s: Failed to inject device node\n",
			MODULE_NAME);
		return -1;
	}

	return 0;
}

struct pvx_plugin pvx_plugin_drm = { .type = "drm",
				     .on_link_added = drm_on_link_added,
				     .on_accept = NULL };
