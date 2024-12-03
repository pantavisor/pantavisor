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

#include "mtd.h"

#include "fs.h"

#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <mtd/mtd-user.h>

#define MODULE_NAME "pv_mtd"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "../log.h"

#define PV_MTD_DEV_PATH "/dev/mtd%d"
#define PV_MTD_SYS_PATH "/sys/block/mtdblock%d/device/%s"
#define PV_MTD_MAX_DEVS (100)
#define PV_MTD_MAX_SIZE_STR 64

static int get_attribute(int mtd_idx, const char *attr, char *buf, int size)
{
	char path[PATH_MAX] = { 0 };
	snprintf(path, PATH_MAX, PV_MTD_SYS_PATH, mtd_idx, attr);

	errno = 0;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		pv_log(DEBUG, "couldn't open %s: %s (%d)", path,
		       strerror(errno), errno);
		return -1;
	}

	int read = pv_fs_file_read_nointr(fd, buf, size);
	close(fd);

	if (read < 0)
		pv_log(DEBUG, "couldn't read device attribute");

	return read < 0 ? -1 : 0;
}

static int get_attribute_num(int mtd_idx, const char *attr, off_t *result)
{
	char buf[PV_MTD_MAX_SIZE_STR] = { 0 };
	if (get_attribute(mtd_idx, attr, buf, PV_MTD_MAX_SIZE_STR) != 0)
		return -1;

	errno = 0;
	long n = strtol(buf, NULL, 10);

	if (errno != 0) {
		pv_log(DEBUG, "couldn't convert str '%s': %s(%d)", attr,
		       strerror(errno), errno);
		return -1;
	}

	*result = n;

	return 0;
}

static int search_device_by_name(const char *name)
{
	for (int i = 0; i < PV_MTD_MAX_DEVS; ++i) {
		char buf[NAME_MAX] = { 0 };
		if (get_attribute(i, "name", buf, NAME_MAX) != 0)
			continue;

		if (!strncmp(name, buf, strlen(name)))
			return i;
	}
	return -1;
}

struct pv_mtd *pv_mtd_from_name(const char *name)
{
	int idx = search_device_by_name(name);
	if (idx < 0)
		return NULL;

	struct pv_mtd *mtd = calloc(1, sizeof(struct pv_mtd));
	if (!mtd)
		return NULL;

	if (get_attribute_num(idx, "erasesize", &mtd->erasesize) != 0)
		goto err;

	if (get_attribute_num(idx, "writesize", &mtd->writesize) != 0)
		goto err;

	if (get_attribute_num(idx, "size", &mtd->size) != 0)
		goto err;

	snprintf(mtd->dev, PATH_MAX, PV_MTD_DEV_PATH, idx);
	memcpy(mtd->name, name, strlen(name));

	mtd->fd = open(mtd->dev, O_RDWR | O_CLOEXEC);
	if (mtd->fd < 0)
		goto err;

	return mtd;

err:
	if (mtd)
		pv_mtd_free(mtd);
	return NULL;
}

void pv_mtd_free(struct pv_mtd *mtd)
{
	if (!mtd)
		return;

	close(mtd->fd);
	free(mtd);
}

int pv_mtd_erase(struct pv_mtd *mtd, off_t from, off_t len)
{
	erase_info_t ei = { 0 };
	errno = 0;
	ei.length = mtd->erasesize;
	for (ei.start = from; ei.start < len; ei.start += ei.length) {
		if (ioctl(mtd->fd, MEMUNLOCK, &ei) == -1) {
			// errno 524 is ENOTSUPP in the linux driver
			// implementation, sadly seems no to be visible from
			// here using that name.
			if (errno != 524) {
				pv_log(DEBUG, "couldn't unlock %s (%d)",
				       strerror(errno), errno);
				return -1;
			}
		}

		if (ioctl(mtd->fd, MEMERASE, &ei) == -1) {
			pv_log(DEBUG, "couldn't erase %s (%d)", strerror(errno),
			       errno);
			return -1;
		}
	}

	return 0;
}

ssize_t pv_mtd_read(struct pv_mtd *mtd, void *buf, size_t size)
{
	ssize_t read_bytes = 0;
	while (read_bytes < size) {
		char *ptr = ((char *)buf) + read_bytes;
		ssize_t cur_rd = read(mtd->fd, ptr, mtd->writesize);
		if (cur_rd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		read_bytes += cur_rd;
	}

	return read_bytes;
}

ssize_t pv_mtd_write(struct pv_mtd *mtd, const void *buf, size_t buf_sz)
{
	size_t wbytes = 0;
	while (wbytes < buf_sz) {
		ssize_t cur_wr = 0;
		do {
			const char *ptr = ((char *)buf) + wbytes + cur_wr;
			cur_wr += write(mtd->fd, ptr, mtd->writesize);
			if (cur_wr < 0) {
				if (errno == EINTR)
					continue;

				break;
			}
		} while (cur_wr < (mtd->writesize - buf_sz - wbytes));
		wbytes += cur_wr;
	}
	fsync(mtd->fd);
	return wbytes;
}

static ssize_t copy_fd(int src, int dst, off_t src_size, off_t writesize)
{
	if (src < 0 || dst < 0) {
		pv_log(DEBUG, "invalid file descriptor src = %d; dst = %d", src,
		       dst);
		return 0;
	}

	char *buf = calloc(writesize, sizeof(char));
	if (!buf) {
		pv_log(DEBUG, "couldn't allocate buffer");
		return 0;
	}

	ssize_t read_bytes = 0;
	ssize_t write_bytes = 0;

	while (write_bytes < src_size) {
		ssize_t cur_rd = read(src, buf, writesize);
		if (cur_rd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		ssize_t cur_wr = 0;
		do {
			cur_wr += write(dst, buf + cur_wr, writesize);
			if (cur_wr < 0) {
				if (errno == EINTR)
					continue;

				break;
			}
		} while (cur_wr < cur_rd);

		write_bytes += cur_wr;
	}

	fsync(src);
	fsync(dst);
	free(buf);

	return write_bytes;
}

ssize_t pv_mtd_copy_to_fd(struct pv_mtd *mtd, int fd, off_t size)
{
	if (!mtd)
		return 0;

	return copy_fd(mtd->fd, fd, size, mtd->writesize);
}

ssize_t pv_mtd_copy_from_fd(struct pv_mtd *mtd, int fd, off_t size)
{
	if (!mtd)
		return 0;

	return copy_fd(fd, mtd->fd, size, mtd->writesize);
}

off_t pv_mtd_seek(struct pv_mtd *mtd, off_t offset, int whence)
{
	return lseek(mtd->fd, offset, whence);
}