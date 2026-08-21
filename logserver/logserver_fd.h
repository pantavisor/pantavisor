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

#ifndef LOGSERVER_FD_H
#define LOGSERVER_FD_H

#include "utils/list.h"
#include "buffer.h"

#include <stdbool.h>
#include <sys/types.h>

struct logserver_fd {
	char *plat;
	char *src;
	int lvl;
	int fd;
	struct dl_list lst;
};

int logserver_fd_add(struct dl_list *list, struct logserver_fd *lfd);
bool logserver_fd_exist(struct dl_list *list, int fd);
void logserver_fd_remove_by_fd(struct dl_list *list, int fd);
struct buffer *logserver_fd_get_data(struct logserver_fd *lfd, ssize_t *len);
struct logserver_fd *logserver_fd_fetch_by_fd(struct dl_list *list, int fd);
struct logserver_fd *logserver_fd_fetch_by_data(struct dl_list *list,
						const char *plat,
						const char *src);
void logserver_fd_list_free(struct dl_list *list);

#endif
