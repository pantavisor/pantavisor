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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "pvtx_tar_impl.h"
#include "pvtx_tar.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/limits.h>

struct pv_pvtx_tar_priv {
	struct pv_pvtx_tar_imp *imp;
	void *imp_data;
};

struct pv_pvtx_tar_metadata {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
};

extern struct pv_pvtx_tar_imp pv_pvtx_tar_raw;
extern struct pv_pvtx_tar_imp pv_pvtx_tar_gzip;

#ifdef PANTAVISOR_PVTX_BZ2
extern struct pv_pvtx_tar_imp pv_pvtx_tar_bz2;
#endif

static ssize_t read_nointr(struct pv_pvtx_tar_priv *priv, void *buf,
			   size_t size)
{
	ssize_t total_read = 0;
	errno = 0;

	while (total_read != size) {
		int cur_read = priv->imp->read(priv->imp_data, buf + total_read,
					       size - total_read);
		if (cur_read < 0) {
			if (errno == EINTR)
				continue;
			return total_read == 0 ? cur_read : total_read;
		}
		if (cur_read == 0)
			break;
		total_read += cur_read;
	}
	return total_read;
}

static void get_name(struct pv_pvtx_tar *tar, struct pv_pvtx_tar_metadata *meta,
		     char *name)
{
	const char *long_link = "/./@LongLink";
	if (strncmp(meta->name, long_link, strlen(long_link))) {
		memccpy(name, meta->name, '\0', 100);
		return;
	}

	// NOTE: here we could check the typeflag which
	// for large name should be 'L' but seems redundant
	char *buf[PVTX_TAR_BLOCK_SIZE] = { 0 };
	read_nointr(tar->priv, buf, PVTX_TAR_BLOCK_SIZE);
	memccpy(name, buf, '\0', NAME_MAX);
}

int pv_pvtx_tar_next(struct pv_pvtx_tar *tar, struct pv_pvtx_tar_content *con)
{
	pv_pvtx_error_clear(&tar->err);

	char buf[PVTX_TAR_BLOCK_SIZE] = { 0 };
	ssize_t size = read_nointr(tar->priv, buf, PVTX_TAR_BLOCK_SIZE);

	if (size < PVTX_TAR_BLOCK_SIZE) {
		pv_pvtx_error_set(&tar->err, -1, "couldn't read header");
		return -1;
	}

	struct pv_pvtx_tar_metadata meta = { 0 };
	memcpy(&meta, buf, sizeof(struct pv_pvtx_tar_metadata));
	if (strncmp(meta.magic, "ustar", strlen("ustar"))) {
		pv_pvtx_error_set(&tar->err, -1, "ustar not found");
		return -1;
	}

	memset(con->name, 0, NAME_MAX);
	get_name(tar, &meta, con->name);

	con->size = strtoll(meta.size, NULL, 8);
	con->cap = (con->size | (PVTX_TAR_BLOCK_SIZE - 1)) + 1;
	if (!con->priv)
		con->priv = tar->priv;
	con->read = 0;

	return 0;
}

ssize_t pv_pvtx_tar_content_read_block(struct pv_pvtx_tar_content *con,
				       void *buf, ssize_t size)
{
	if (con->read >= con->size || size < 1)
		return 0;

	ssize_t to_read = size;
	if ((to_read + con->read) > con->size) {
		to_read = con->size - con->read;
		if (to_read % PVTX_TAR_BLOCK_SIZE)
			to_read = (to_read | (PVTX_TAR_BLOCK_SIZE - 1)) + 1;
	}

	ssize_t read = read_nointr(con->priv, buf, to_read);
	if (read > 0)
		con->read += read;

	return to_read;
}

ssize_t pv_pvtx_tar_content_read_object(struct pv_pvtx_tar_content *con,
					void *buf)
{
	memset(buf, 0, con->size);
	while (con->read < con->cap) {
		void *p = buf + con->read;
		ssize_t size = read_nointr(con->priv, p, PVTX_TAR_BLOCK_SIZE);
		if (size > 0)
			con->read += size;
		else
			break;
	}

	return con->read;
}

void pv_pvtx_tar_free(struct pv_pvtx_tar *tar)
{
	if (!tar)
		return;

	if (!tar->priv || !tar->priv->imp_data)
		goto out;

	struct pv_pvtx_tar_priv *priv = tar->priv;

	if (priv->imp)
		priv->imp->close(priv->imp_data);
	else
		free(priv->imp_data);

	free(priv);

out:
	free(tar);
}

static enum pv_pvtx_tar_type imp_from_file(int fd, struct pv_pvtx_error *err)
{
	enum pv_pvtx_tar_type type = PVTX_TAR_UNKNOWN;
	errno = 0;
	if (lseek(fd, 0, SEEK_SET) == -1) {
		char *e = NULL;
		if (errno == ESPIPE) {
			e = "type cannot be obtained from a no seekable fd: %s";
			pv_pvtx_error_set(err, errno, e, strerror(errno));
		} else {
			pv_pvtx_error_set(err, errno, "%s", strerror(errno));
		}
		return type;
	}

	if (pv_pvtx_tar_gzip.is_fmt(fd)) {
		type = PVTX_TAR_GZIP;
	} else if (pv_pvtx_tar_raw.is_fmt(fd)) {
		type = PVTX_TAR_RAW;

#ifdef PANTAVISOR_PVTX_BZ2
	} else if (pv_pvtx_tar_bz2.is_fmt(fd)) {
		type = PVTX_TAR_BZIP2;
#endif
	}

	lseek(fd, 0, SEEK_SET);
	return type;
}

enum pv_pvtx_tar_type pv_pvtx_tar_type_get(const char *path,
					   struct pv_pvtx_error *err)
{
	pv_pvtx_error_clear(err);
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		pv_pvtx_error_set(err, -1, "couldn't open file");
		return PVTX_TAR_UNKNOWN;
	}

	enum pv_pvtx_tar_type type = imp_from_file(fd, err);
	close(fd);
	return type;
}

struct pv_pvtx_tar *pv_pvtx_tar_from_fd(int fd, enum pv_pvtx_tar_type type,
					struct pv_pvtx_error *err)
{
	if (fd < 0)
		return NULL;

	pv_pvtx_error_clear(err);

	struct pv_pvtx_tar *tar = calloc(1, sizeof(struct pv_pvtx_tar));
	if (!tar) {
		pv_pvtx_error_set(err, errno, "couldn't allocate tar object");
		return NULL;
	}

	tar->priv = calloc(1, sizeof(struct pv_pvtx_tar_priv));
	if (!tar->priv) {
		pv_pvtx_error_set(&tar->err, -1,
				  "couldn't alloc implementation");
		goto err;
	}

	struct pv_pvtx_tar_priv *priv = tar->priv;

	if (type == PVTX_TAR_UNKNOWN) {
		type = imp_from_file(fd, err);
		if (err->code != 0 || type == PVTX_TAR_UNKNOWN)
			goto err;
	}

	if (type == PVTX_TAR_RAW) {
		priv->imp = &pv_pvtx_tar_raw;
		tar->type = PVTX_TAR_RAW;
	} else if (type == PVTX_TAR_GZIP) {
		priv->imp = &pv_pvtx_tar_gzip;
		tar->type = PVTX_TAR_GZIP;
#ifdef PANTAVISOR_PVTX_BZ2
	} else if (type == PVTX_TAR_BZIP2) {
		priv->imp = &pv_pvtx_tar_bz2;
		tar->type = PVTX_TAR_BZIP2;
#endif
	} else {
		goto err;
	}

	priv->imp_data = priv->imp->from_fd(fd);

	return tar;

err:
	if (tar)
		pv_pvtx_tar_free(tar);

	return NULL;
}

struct pv_pvtx_tar *pv_pvtx_tar_from_path(const char *path,
					  enum pv_pvtx_tar_type type,
					  struct pv_pvtx_error *err)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pv_pvtx_error_set(err, -1, "couldn't open file %s", path);
		return NULL;
	}

	struct pv_pvtx_tar *tar = pv_pvtx_tar_from_fd(fd, type, err);

	return tar;
}