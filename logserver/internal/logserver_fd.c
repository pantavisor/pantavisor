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

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

struct pv_ls_fd *pv_ls_fd_new(const char *plat, const char *src, int fd,
			      int level)
{
	struct pv_ls_fd *lfd = calloc(1, sizeof(struct pv_ls_fd));
	if (!lfd)
		return NULL;

	// avoid closing fd
	lfd->fd = -1;

	if (plat) {
		lfd->plat = strdup(plat);
		if (!lfd->plat)
			goto err;
	}

	if (src) {
		lfd->src = strdup(src);
		if (!lfd->src)
			goto err;
	}

	if (fd >= 0) {
		int flags = fcntl(fd, F_GETFL);
		if (flags < 0)
			flags = 0;

		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}

	lfd->fd = fd;
	lfd->lvl = level;

	dl_list_init(&lfd->lst);

	return lfd;
err:
	pv_ls_fd_free(lfd);
	return NULL;
}

void pv_ls_fd_free(struct pv_ls_fd *lfd)
{
	if (!lfd)
		return;

	if (lfd->fd >= 0)
		close(lfd->fd);
	if (lfd->plat)
		free(lfd->plat);
	if (lfd->path)
		free(lfd->path);
	if (lfd->src)
		free(lfd->src);
	free(lfd);
}

int pv_ls_fd_list_add(struct dl_list *list, struct pv_ls_fd *lfd)
{
	if (!lfd || !list)
		return -1;

	dl_list_add(list, &lfd->lst);
	return 0;
}

bool pv_ls_fd_list_exists(struct dl_list *list, int fd)
{
	return pv_ls_fd_list_fetch_by_fd(list, fd) != NULL;
}

struct pv_ls_fd *pv_ls_fd_list_fetch_by_fd(struct dl_list *list, int fd)
{
	if (!list || fd < 0)
		return NULL;

	struct pv_ls_fd *it;
	dl_list_for_each(it, list, struct pv_ls_fd, lst)
	{
		if (it->fd == fd)
			return it;
	}
	return NULL;
}

struct pv_ls_fd *pv_ls_fd_list_fetch_by_data(struct dl_list *list,
					     const char *plat, const char *src)
{
	if (!list || !plat || !src || !*plat || !*src)
		return NULL;

	struct pv_ls_fd *it;
	dl_list_for_each(it, list, struct pv_ls_fd, lst)
	{
		if (it->plat && it->src && !strcmp(it->plat, plat) &&
		    !strcmp(it->src, src))
			return it;
	}
	return NULL;
}

struct pv_ls_fd *pv_ls_fd_list_remove(struct dl_list *list, int fd)
{
	struct pv_ls_fd *lfd = pv_ls_fd_list_fetch_by_fd(list, fd);
	if (!lfd)
		return NULL;

	dl_list_del(&lfd->lst);

	return lfd;
}
