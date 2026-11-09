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

#include "logserver_conninfo.h"
#include "cgroup.h"
#include "utils/socket.h"

#include <stdlib.h>

struct pv_ls_conninfo *pv_ls_cinfo_new(int fd)
{
	if (fd < 0)
		return NULL;

	struct pv_ls_conninfo *ci = calloc(1, sizeof(*ci));
	if (!ci)
		return NULL;

	ci->pid = pv_socket_get_sender_pid(fd);
	if (ci->pid < 0)
		goto err;

	ci->cgroup = pv_cgroup_get_process_name(ci->pid);
	if (!ci->cgroup)
		goto err;

	ci->fd = fd;

	return ci;
err:
	pv_ls_cinfo_free(ci);
	return NULL;
}

void pv_ls_cinfo_free(struct pv_ls_conninfo *ci)
{
	if (!ci)
		return;
	free(ci->cgroup);
	free(ci);
}

struct pv_ls_conninfo *pv_ls_cinfo_search(struct dl_list *list, int fd)
{
	if (!list || fd < 0)
		return NULL;

	struct pv_ls_conninfo *it;
	dl_list_for_each(it, list, struct pv_ls_conninfo, lst)
	{
		if (it->fd == fd)
			return it;
	}
	return NULL;
}

struct pv_ls_conninfo *pv_ls_cinfo_list_remove(struct dl_list *list, int fd)
{
	if (!list || fd < 0)
		return NULL;

	struct pv_ls_conninfo *ci = pv_ls_cinfo_search(list, fd);
	if (!ci)
		return NULL;

	dl_list_del(&ci->lst);

	return ci;
}

void pv_ls_cinfo_list_free(struct dl_list *list)
{
	if (!list)
		return;

	struct pv_ls_conninfo *it, *tmp;
	dl_list_for_each_safe(it, tmp, list, struct pv_ls_conninfo, lst)
	{
		dl_list_del(&it->lst);
		pv_ls_cinfo_free(it);
	}
}
