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

#include "pvtx_tar_impl.h"

#include <zlib.h>

#ifdef PV_PVXT_BZIP_ENABLE
#include <bzlib.h>
#endif

#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

// raw file implementation
static bool pv_pvtx_raw_is_fmt(int fd)
{
	lseek(fd, 257, SEEK_SET);

	char buf[5] = { 0 };
	if (read(fd, buf, 5) < 0)
		return false;

	return !strncmp(buf, "ustar", 5);
}

static void *pv_pvtx_raw_from_fd(int fd)
{
	lseek(fd, 0, SEEK_SET);
	int *tar_fd = malloc(sizeof(int));
	if (!tar_fd)
		return NULL;
	*tar_fd = fd;
	return tar_fd;
}

static ssize_t pv_pvtx_raw_read(void *impl_data, void *buf, size_t count)
{
	return read((*(int *)impl_data), buf, count);
}

static int pv_pvtx_raw_close(void *impl_data)
{
	int *fd = (int *)impl_data;
	int ret = close(*fd);
	free(fd);
	return ret;
}

static off_t pv_pvtx_raw_seek(void *impl_data, off_t offset, int whence)
{
	return lseek((*(int *)impl_data), offset, whence);
}

// gzip file implementation

static bool pv_pvtx_gzip_is_fmt(int fd)
{
	lseek(fd, 0, SEEK_SET);
	unsigned char buf[2] = { 0 };

	if (read(fd, buf, 2) < 0)
		return false;

	return buf[0] == 0x1f && buf[1] == 0x8b;
}

static void *pv_pvtx_gzip_from_fd(int fd)
{
	lseek(fd, 0, SEEK_SET);
	return gzdopen(fd, "r");
}

static ssize_t pv_pvtx_gzip_read(void *impl_data, void *buf, size_t count)
{
	return gzread((gzFile)impl_data, buf, count);
}

static int pv_pvtx_gzip_close(void *impl_data)
{
	return gzclose((gzFile)impl_data);
}

static off_t pv_pvtx_gzip_seek(void *impl_data, off_t offset, int whence)
{
	return gzseek((gzFile)impl_data, offset, whence);
}

#ifdef PV_PVXT_BZIP_ENABLE
// bzip2 file implementation
// pos and path fields are needed to simulate the seek operations
struct pvtx_bz2 {
	off_t pos;
	BZFILE *bzfd;
	int fd;
};

static bool pv_pvtx_bzip2_is_fmt(int fd)
{
	lseek(fd, 0, SEEK_SET);
	char buf[3] = { 0 };

	if (read(fd, buf, 3) < 0)
		return false;

	return !strncmp(buf, "BZh", 3);
}

static int pv_pvtx_bzip2_close(void *impl_data)
{
	if (!impl_data)
		return 0;

	struct pvtx_bz2 *bz2 = (struct pvtx_bz2 *)impl_data;

	if (!bz2)
		return 0;

	if (bz2->bzfd)
		BZ2_bzclose(bz2->bzfd);

	if (bz2->fd > 0)
		close(bz2->fd);

	free(bz2);

	return 0;
}

static void *pv_pvtx_bzip2_from_fd(int fd)
{
	if (fd < 0)
		return NULL;

	struct pvtx_bz2 *bz2 = calloc(1, sizeof(struct pvtx_bz2));
	if (!bz2)
		return NULL;

	lseek(fd, 0, SEEK_SET);
	bz2->bzfd = BZ2_bzdopen(fd, "rb");
	if (!bz2->bzfd)
		goto err;

	bz2->fd = fd;

	return bz2;

err:
	pv_pvtx_bzip2_close(bz2);
	return NULL;
}

static ssize_t pv_pvtx_bzip2_read(void *impl_data, void *buf, size_t count)
{
	struct pvtx_bz2 *bz2 = (struct pvtx_bz2 *)impl_data;
	off_t n = BZ2_bzread(bz2->bzfd, buf, count);

	// update the position to simulate seek
	if (n > 0)
		bz2->pos += n;

	return n;
}

// simulated seek
// bzip2 do not support seek operations so this is a simulation
// to use the same API.
// The idea is to track the bytes read (see the read function) and to move it
// we use a read operation.
static off_t pv_pvtx_bzip2_seek(void *impl_data, off_t offset, int whence)
{
	struct pvtx_bz2 *bz2 = (struct pvtx_bz2 *)impl_data;

	off_t to_move = offset;
	if (whence == SEEK_SET) {
		if (offset < bz2->pos) {
			printf("1===\n");
			if (bz2->fd < 0) {
				printf("****** dead fd\n");
				return -2;
			}
			lseek(bz2->fd, 0, SEEK_SET);
			BZFILE *f = BZ2_bzdopen(bz2->fd, "rb");
			if (!f)
				return -1;

			BZ2_bzclose(bz2->bzfd);
			bz2->bzfd = f;
			bz2->pos = 0;
		} else if (offset == bz2->pos) {
			printf("2===\n");
			return 0;
		} else {
			printf("3===\n");
			to_move = offset - bz2->pos;
		}
	} else if (whence == SEEK_END)
		return -1;

	char buf[1024] = { 0 };
	ssize_t total = 0;
	while (total < to_move) {
		ssize_t remaining = to_move - total;
		ssize_t to_read = remaining < 1024 ? remaining : 1024;
		// int bytes = BZ2_bzread(bz2->fd, buf, to_read);
		int bytes = pv_pvtx_bzip2_read(impl_data, buf, to_read);
		if (bytes == 0)
			break;
		if (bytes < 0)
			return -1;
		total += bytes;
	}

	return total;
}
#endif

struct pv_pvtx_tar_imp pv_pvtx_tar_raw = {
	.is_fmt = pv_pvtx_raw_is_fmt,
	.from_fd = pv_pvtx_raw_from_fd,
	.read = pv_pvtx_raw_read,
	.close = pv_pvtx_raw_close,
	.seek = pv_pvtx_raw_seek,
};

struct pv_pvtx_tar_imp pv_pvtx_tar_gzip = {
	.is_fmt = pv_pvtx_gzip_is_fmt,
	.from_fd = pv_pvtx_gzip_from_fd,
	.read = pv_pvtx_gzip_read,
	.close = pv_pvtx_gzip_close,
	.seek = pv_pvtx_gzip_seek,
};

#ifdef PV_PVXT_BZIP_ENABLE
struct pv_pvtx_tar_imp pv_pvtx_tar_bz2 = {
	.is_fmt = pv_pvtx_bzip2_is_fmt,
	.from_fd = pv_pvtx_bzip2_from_fd,
	.read = pv_pvtx_bzip2_read,
	.close = pv_pvtx_bzip2_close,
	.seek = pv_pvtx_bzip2_seek,
};
#endif