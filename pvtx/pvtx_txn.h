/*
 * Copyright (c) 2025 Pantacor Ltd.
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

#ifndef PVTX_TXN_LIB_H
#define PVTX_TXN_LIB_H

#include "pvtx_error.h"

int pv_pvtx_txn_begin(const char *from, const char *obj_path,
		   struct pv_pvtx_error *err);
int pv_pvtx_txn_add_from_disk(const char *path, struct pv_pvtx_error *err);
int pv_pvtx_txn_add_tar_from_fd(int fd, struct pv_pvtx_error *err);

int pv_pvtx_txn_abort(struct pv_pvtx_error *err);
char *pv_pvtx_txn_commit(struct pv_pvtx_error *err);
char *pv_pvtx_txn_get_json(struct pv_pvtx_error *err);
int pv_pvtx_txn_deploy(const char *path, struct pv_pvtx_error *err);
int pv_pvtx_txn_remove(const char *part, struct pv_pvtx_error *err);

// queue API
int pv_pvtx_queue_new(const char *queue_path, const char *obj_path,
		   struct pv_pvtx_error *err);
int pv_pvtx_queue_remove(const char *part, struct pv_pvtx_error *err);
int pv_pvtx_queue_unpack_from_disk(const char *part, struct pv_pvtx_error *err);
int pv_pvtx_queue_unpack_tar_from_fd(int fd, struct pv_pvtx_error *err);
int pv_pvtx_queue_process(const char *from, const char *queue_path,
		       const char *obj_path, struct pv_pvtx_error *err);

#endif
