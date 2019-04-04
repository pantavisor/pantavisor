/*
 * Copyright (c) 2019 Pantacor Ltd.
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
#include <unistd.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <linux/watchdog.h>

#define MODULE_NAME             "wdt"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "wdt.h"

int fd;

int pv_wdt_start(struct pantavisor *pv)
{
	int timeout = pv->config->wdt.timeout;

	if (!pv->config->wdt.enabled)
		return 0;

	if (fd > 0)
		return 0;

	fd = open("/dev/watchdog", O_RDWR | O_NOCTTY);
	if (fd < 0) {
		pv_log(DEBUG, "No watchdog timer device found");
		return -1;
	}

	ioctl(fd, WDIOC_SETTIMEOUT, &timeout);
	ioctl(fd, WDIOC_GETTIMEOUT, &timeout);

	if (!timeout)
		pv_log(DEBUG, "error setting up watchdog device");

	pv_log(DEBUG, "watchdog opened with %ds timeout", timeout);
	pv->config->updater.interval = timeout / 2;
	pv_log(INFO, "clamping PH update interval to wdt/2 (%ds)", pv->config->updater.interval);

	return 0;
}

void pv_wdt_kick(struct pantavisor *pv)
{
	if (!fd)
		return;

	ioctl(fd, WDIOC_KEEPALIVE, 0);
}

int pv_wdt_stop(struct pantavisor *pv)
{
	if (!fd) {
		pv_log(DEBUG, "No watchdog timer available to stop");
		return -1;
	}

	pv_wdt_kick(pv);
	write(fd, "V", 1);
	close(fd);

	fd = 0;

	return 0;
}
