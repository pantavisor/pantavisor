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
#include "pvctl_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <pthread.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/prctl.h>
#include "cmd.h"
#include <errno.h>

#ifndef MODULE_NAME
#define MODULE_NAME             "pvctl-utils"
#endif

#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"


static int open_socket(const char *path)
{
	int fd, ret;
	struct sockaddr_un addr;
	int retries = 5;
	const int wait_secs = 2;
	char str_err[128];

try_again:
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		pv_log(WARN, "Socket creation failed\n");
		return fd;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	strcpy(addr.sun_path, path);

	ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0) {
		close(fd);
		if (retries > 0) {
			sleep(wait_secs);
			retries--;
			goto try_again;
		} else {
			strerror_r(errno, str_err, sizeof(str_err));
			printf("Connect error on path %s, errno = %d (%s)\n",
					path, errno, str_err);
			return -errno;
		}
	}
	return fd;
}

int pvctl_write(const char *buf, ssize_t count)
{
	return pvctl_write_to_path("/pantavisor/pv-ctrl", buf, count);
}

int pvctl_write_to_path(const char *path, const char *buf, ssize_t count)
{
	int fd = open_socket(path);
	ssize_t written = 0;
	if (fd < 0) {
		return -1;
	}
	while (count) {
		written = write(fd, buf, count);
		if (written < 0 ) {
			if (errno == EINTR)
				continue;
			break;
		}
		count -=written;
		buf += written;
	}
	close(fd);
	return count;

}
