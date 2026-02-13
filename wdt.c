/*
 * Copyright (c) 2019-2024 Pantacor Ltd.
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
#include <errno.h>
#include <string.h>

#include <sys/ioctl.h>
#include <linux/watchdog.h>

#include "wdt.h"

#define MODULE_NAME "wdt"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

static int pv_wdt_fd = -1;

int pv_wdt_start()
{
	if (pv_config_get_wdt_mode() == WDT_DISABLED)
		return 0;

	if (pv_wdt_fd >= 0)
		return 0;

	pv_wdt_fd = open("/dev/watchdog", O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (pv_wdt_fd < 0) {
		pv_log(DEBUG, "No watchdog timer device found");
		return -1;
	}

	int timeout = pv_config_get_int(PV_WDT_TIMEOUT);
	ioctl(pv_wdt_fd, WDIOC_SETTIMEOUT, &timeout);
	ioctl(pv_wdt_fd, WDIOC_GETTIMEOUT, &timeout);

	if (!timeout)
		pv_log(DEBUG, "error setting up watchdog device");

	pv_wdt_kick();

	pv_log(DEBUG, "watchdog started with %ds timeout", timeout);

	return 0;
}

void pv_wdt_stop()
{
	if (pv_wdt_fd < 0)
		return;

	struct watchdog_info info;

	if (ioctl(pv_wdt_fd, WDIOC_GETSUPPORT, &info)) {
		pv_log(WARN, "could not ioctl");
	}

	if (WDIOF_MAGICCLOSE & info.options) {
		pv_log(INFO,
		       "magic char supported. WDT will not stop ... you must reset timeout yourself now or reboot.");
	}

	if (close(pv_wdt_fd) < 0) {
		pv_log(WARN, "wdt with could not be closed: %s",
		       strerror(errno));
	}

	pv_wdt_fd = -1;

	pv_log(DEBUG, "watchdog stopped");
}

void pv_wdt_kick()
{
	if (pv_wdt_fd < 0)
		return;

	ioctl(pv_wdt_fd, WDIOC_KEEPALIVE, 0);

	pv_log(DEBUG, "watchdog kicked");
}

