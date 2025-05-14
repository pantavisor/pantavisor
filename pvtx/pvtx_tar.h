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

#ifndef PVTX_TAR_H
#define PVTX_TAR_H

#include "pvtx_error.h"

#include <sys/types.h>
#include <linux/limits.h>

enum pv_pvtx_tar_type {
	PVTX_TAR_UNKNOWN,
	PVTX_TAR_RAW,
	PVTX_TAR_GZIP,
	PVTX_TAR_BZIP2
};

struct pv_pvtx_tar_content {
	char name[NAME_MAX];
	unsigned char *data;
	off_t size;
};

struct pv_pvtx_tar {
	enum pv_pvtx_tar_type type;
	struct pv_pvtx_error err;
	struct pv_pvtx_tar_priv *priv;
};

static inline const char *pv_pvtx_tar_type_to_str(enum pv_pvtx_tar_type type)
{
	switch (type) {
	case PVTX_TAR_UNKNOWN:
		return "unknown";
	case PVTX_TAR_RAW:
		return "tar";
	case PVTX_TAR_GZIP:
		return "gzip";
	case PVTX_TAR_BZIP2:
		return "bzip2";
	}

	return "unknown";
}

enum pv_pvtx_tar_type pv_pvtx_tar_type_get(const char *path,
					   struct pv_pvtx_error *err);
struct pv_pvtx_tar *pv_pvtx_tar_from_fd(int fd, enum pv_pvtx_tar_type type,
					struct pv_pvtx_error *err);
struct pv_pvtx_tar *pv_pvtx_tar_from_path(const char *path,
					  enum pv_pvtx_tar_type type,
					  struct pv_pvtx_error *err);
struct pv_pvtx_tar_content *pv_pvtx_tar_next(struct pv_pvtx_tar *tar);

void pv_pvtx_tar_free(struct pv_pvtx_tar *tar);
void pv_pvtx_tar_content_free(struct pv_pvtx_tar_content *con);

#endif
