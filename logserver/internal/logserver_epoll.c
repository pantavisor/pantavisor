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

#include "logserver_epoll.h"
#include "logserver_pvlog.h"
#include "log.h"

#include <errno.h>
#include <string.h>

#define MODULE_NAME "logserver_epoll"
#define pv_log(level, msg, ...)                                                \
	pv_ls_pv_log(MODULE_NAME, level, msg, ##__VA_ARGS__)

static int pv_ls_epoll_command(int epfd, int fd, int cmd)
{
	struct epoll_event ev = { 0 };
	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.fd = fd;
	return epoll_ctl(epfd, cmd, fd, &ev);
}

int pv_ls_epoll_add(int epfd, int fd)
{
	return pv_ls_epoll_command(epfd, fd, EPOLL_CTL_ADD);
}

int pv_ls_epoll_create(void)
{
	int fd = epoll_create1(EPOLL_CLOEXEC);
	if (fd < 0)
		pv_log(ERROR, "could not create logserver epoll fd: %s",
		       strerror(errno));

	return fd;
}

int pv_ls_epoll_del(int epfd, int fd)
{
	return pv_ls_epoll_command(epfd, fd, EPOLL_CTL_DEL);
}

int pv_ls_epoll_wait(int epfd, struct epoll_event *ev, int max)
{
	int ready;

	do {
		ready = epoll_wait(epfd, ev, max, -1);
	} while (ready < 0 && errno == EINTR);

	if (ready < 0) {
		pv_log(ERROR, "error calling epoll_wait: %s", strerror(errno));
		return -1;
	}

	return ready;
}
