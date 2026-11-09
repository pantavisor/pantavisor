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

#ifndef LOGSERVER_CONNINFO_H
#define LOGSERVER_CONNINFO_H

#include "utils/list.h"

#include <sys/types.h>

struct pv_ls_conninfo {
	int fd;
	pid_t pid;
	char *cgroup;
	struct dl_list lst;
};

struct pv_ls_conninfo *pv_ls_cinfo_new(int fd);
void pv_ls_cinfo_free(struct pv_ls_conninfo *ci);
struct pv_ls_conninfo *pv_ls_cinfo_search(struct dl_list *list, int fd);
struct pv_ls_conninfo *pv_ls_cinfo_list_remove(struct dl_list *list, int fd);
void pv_ls_cinfo_list_free(struct dl_list *list);

#endif
