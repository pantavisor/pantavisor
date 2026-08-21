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

#ifndef LOGSERVER_SOCKET_H
#define LOGSERVER_SOCKET_H

#include <sys/uio.h>
#include <stdbool.h>

struct logserver_sck_data {
	struct iovec *vec;
	size_t len;
	struct {
		int type;
		int level;
		void *data;
		size_t len;
	} aux;
};

ssize_t logserver_sck_get(int sock, struct logserver_sck_data *data);
ssize_t logserver_sck_send_fd(int type, int fd, char *plat, char *src,
			      size_t bufsz, int loglevel);
ssize_t logserver_sck_send_to(void *data, size_t len);
int logserver_sck_create(const char *path, bool passcred);
void logserver_sck_close(int sock, const char *name);

#endif
