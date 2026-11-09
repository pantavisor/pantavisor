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

#include <stdbool.h>

struct pv_ls_fd {
	char *plat;
	char *src;
	char *path;
	int lvl;
	int fd;
	struct dl_list lst;
};


// pv_ls_fd_new() takes ownership of fd only on success: the returned
// object closes it in pv_ls_fd_free(). On failure (NULL), fd is left
// open and the caller must close it.

struct pv_ls_fd *pv_ls_fd_new(const char *plat, const char *src, int fd,
			      int level);
void pv_ls_fd_free(struct pv_ls_fd *lfd);
int pv_ls_fd_list_add(struct dl_list *list, struct pv_ls_fd *lfd);
bool pv_ls_fd_list_exists(struct dl_list *list, int fd);
struct pv_ls_fd *pv_ls_fd_list_fetch_by_fd(struct dl_list *list, int fd);
struct pv_ls_fd *pv_ls_fd_list_fetch_by_data(struct dl_list *list,
					     const char *plat, const char *src);
struct pv_ls_fd *pv_ls_fd_list_remove(struct dl_list *list, int fd);

#endif
