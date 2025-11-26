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

#include "ctrl_file.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

struct pv_ctrl_file *pv_ctrl_file_new(struct evhttp_request *req,
				      const char *path,
				      enum pv_ctrl_file_type type)
{
	struct pv_ctrl_file *file = calloc(1, sizeof(struct pv_ctrl_file));
	if (!file)
		return NULL;

	if (type == PV_CTRL_FILE_READ)
		file->fd = open(path, O_CLOEXEC | O_RDONLY, 0644);
	else if (type == PV_CTRL_FILE_WRITE)
		file->fd = open(path, O_CREAT | O_TRUNC | O_CLOEXEC | O_WRONLY,
				0644);
	else
		goto err;

	memccpy(file->path, path, '\0', PATH_MAX);

	// not owned!
	file->req = req;
	file->ok = true;

	return file;

err:
	pv_ctrl_file_free(file);
	return NULL;
}

void pv_ctrl_file_free(struct pv_ctrl_file *file)
{
	if (!file)
		return;

	if (file->fd >= 0)
		close(file->fd);

	free(file);

	return;
}