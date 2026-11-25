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

#ifndef PV_CTRL_DEVMODE_TAR_H
#define PV_CTRL_DEVMODE_TAR_H

struct evhttp_request;

/*
 * Answer req with a pax tar stream of leaf in dirfd, a folder with everything
 * below it or a single file. An empty leaf means the folder dirfd itself.
 * path is the name of leaf relative to the container root, empty for the root.
 * Returns 0 and takes dirfd, the answer is then sent by the stream; returns -1
 * with errno set and sends nothing, dirfd stays with the caller.
 */
int pv_ctrl_devmode_tar_start(struct evhttp_request *req, int dirfd,
			      const char *leaf, const char *path);

#endif
