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

#include "logserver_fd.h"
#include "utils/fs.h"
#include "errno.h"

#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void logserver_fd_free(struct logserver_fd *lfd)
{
	if (!lfd)
		return;

	dl_list_del(&lfd->lst);

	if (lfd->plat)
		free(lfd->plat);
	if (lfd->src)
		free(lfd->src);

	if (lfd->fd >= 0)
		close(lfd->fd);

	free(lfd);
}

static struct logserver_fd *logserver_fd_new(struct logserver_fd *lfd)
{
	if (!lfd || !lfd->plat || !lfd->src || lfd->fd < 0)
		return NULL;

	struct logserver_fd *new_fd = calloc(1, sizeof(*new_fd));
	if (!new_fd)
		return NULL;

	// set to -1 because calloc set it to 0 (stdout)
	new_fd->fd = -1;

	if (lfd->plat) {
		new_fd->plat = strdup(lfd->plat);
		if (!new_fd->plat)
			goto err;
	}

	if (lfd->src) {
		new_fd->src = strdup(lfd->src);
		if (!new_fd->src)
			goto err;
	}

	new_fd->fd = lfd->fd;
	new_fd->lvl = lfd->lvl;

	int flags = fcntl(new_fd->fd, F_GETFL, 0);
	fcntl(new_fd->fd, F_SETFL, flags | O_NONBLOCK);

	dl_list_init(&new_fd->lst);

	return new_fd;
err:
	logserver_fd_free(new_fd);
	return NULL;
}

struct logserver_fd *logserver_fd_fetch_by_fd(struct dl_list *list, int fd)
{
	if (fd < 0)
		return NULL;

	struct logserver_fd *it = NULL;
	struct logserver_fd *tmp = NULL;

	dl_list_for_each_safe(it, tmp, list, struct logserver_fd, lst)
	{
		if (fd == it->fd)
			return it;
	}

	return NULL;
}

struct logserver_fd *logserver_fd_fetch_by_data(struct dl_list *list,
						const char *plat,
						const char *src)
{
	struct logserver_fd *it = NULL;
	struct logserver_fd *tmp = NULL;

	dl_list_for_each_safe(it, tmp, list, struct logserver_fd, lst)
	{
		if (!strcmp(it->plat, plat) && !strcmp(it->src, src))
			return it;
	}

	return NULL;
}

bool logserver_fd_exist(struct dl_list *list, int fd)
{
	return logserver_fd_fetch_by_fd(list, fd) != NULL;
}

int logserver_fd_add(struct dl_list *list, struct logserver_fd *lfd)
{
	if (!list || !lfd)
		return -1;

	struct logserver_fd *new_fd = logserver_fd_new(lfd);
	if (!new_fd)
		return -1;

	dl_list_add(list, &new_fd->lst);
	return 0;
}

void logserver_fd_remove_by_fd(struct dl_list *list, int fd)
{
	struct logserver_fd *lfd = logserver_fd_fetch_by_fd(list, fd);
	if (!lfd)
		return;
	logserver_fd_free(lfd);
}

struct buffer *logserver_fd_get_data(struct logserver_fd *lfd, ssize_t *len)
{
	struct buffer *buffer;
	int attemps = 3;

	while (attemps > 0) {
		buffer = pv_buffer_get(true);
		if (!buffer)
			return NULL;

		errno = 0;
		*len = pv_fs_file_read_nointr(lfd->fd, buffer->buf,
					      buffer->size);
		if (*len > 0) {
			ssize_t end =
				*len < buffer->size ? *len : buffer->size - 1;

			buffer->buf[end] = '\0';
			return buffer;
		}

		pv_buffer_drop(buffer);
		*len = 0;

		if (errno != EAGAIN)
			return NULL;
		attemps--;
	}

	return NULL;
}

void logserver_fd_list_free(struct dl_list *list)
{
	struct logserver_fd *it = NULL;
	struct logserver_fd *tmp = NULL;

	dl_list_for_each_safe(it, tmp, list, struct logserver_fd, lst)
	{
		logserver_fd_free(it);
	}
}
