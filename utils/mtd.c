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

#include "../uboot_mtd_env.h"

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
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "../log.h"

// the kernel's ENOTSUPP, which userspace headers do not name
#define ENOTSUPP_LINUX 524

struct pv_mtd *pv_mtd_from_name(const char *name)
{
	struct mtd_info_user mi;
	struct pv_mtd *mtd = calloc(1, sizeof(*mtd));

	if (!mtd)
		return NULL;
	mtd->fd = -1;

	if (!name || pv_uboot_mtd_find(name, mtd->dev, sizeof(mtd->dev)))
		goto err;

	mtd->fd = open(mtd->dev, O_RDWR | O_CLOEXEC);
	if (mtd->fd < 0)
		goto err;

	if (ioctl(mtd->fd, MEMGETINFO, &mi) || !mi.erasesize || !mi.writesize) {
		pv_log(DEBUG, "%s is not usable MTD flash", mtd->dev);
		goto err;
	}

	snprintf(mtd->name, sizeof(mtd->name), "%s", name);
	mtd->erasesize = mi.erasesize;
	mtd->writesize = mi.writesize;
	mtd->size = mi.size;

	return mtd;
err:
	pv_mtd_free(mtd);
	return NULL;
}

void pv_mtd_free(struct pv_mtd *mtd)
{
	if (!mtd)
		return;

	if (mtd->fd >= 0)
		close(mtd->fd);
	free(mtd);
}

// not every MTD type knows bad blocks (NOR): then the block is good
static bool is_bad_block(struct pv_mtd *mtd, off_t off)
{
	loff_t loff = off;

	return ioctl(mtd->fd, MEMGETBADBLOCK, &loff) > 0;
}

// start of the first good block at or after off, or -1 at the end
static off_t next_good_block(struct pv_mtd *mtd, off_t off)
{
	for (; off < mtd->size; off += mtd->erasesize)
		if (!is_bad_block(mtd, off))
			return off;

	return -1;
}

off_t pv_mtd_capacity(struct pv_mtd *mtd)
{
	off_t bytes = 0;

	for (off_t off = 0; off < mtd->size; off += mtd->erasesize)
		if (!is_bad_block(mtd, off))
			bytes += mtd->erasesize;

	return bytes;
}

// start of the good block that holds logical offset off, or -1
static off_t block_for(struct pv_mtd *mtd, off_t off)
{
	off_t blk = next_good_block(mtd, 0);

	for (off_t n = off / mtd->erasesize; n > 0 && blk >= 0; n--)
		blk = next_good_block(mtd, blk + mtd->erasesize);

	return blk;
}

ssize_t pv_mtd_read(struct pv_mtd *mtd, off_t off, void *buf, size_t len)
{
	off_t blk = block_for(mtd, off);
	size_t done = 0;

	off %= mtd->erasesize;
	while (blk >= 0 && done < len) {
		size_t n = mtd->erasesize - off;

		if (n > len - done)
			n = len - done;
		if (pread(mtd->fd, (char *)buf + done, n, blk + off) !=
		    (ssize_t)n)
			return -1;
		done += n;
		off = 0;
		blk = next_good_block(mtd, blk + mtd->erasesize);
	}

	return done == len ? (ssize_t)done : -1;
}

static int erase_block(struct pv_mtd *mtd, off_t off)
{
	erase_info_t ei = { .start = off, .length = mtd->erasesize };

	// flash without lock support answers ENOTSUPP, which is fine
	if (ioctl(mtd->fd, MEMUNLOCK, &ei) && errno != ENOTSUPP_LINUX)
		pv_log(DEBUG, "cannot unlock %s at 0x%llx: %s", mtd->dev,
		       (long long)off, strerror(errno));

	if (ioctl(mtd->fd, MEMERASE, &ei)) {
		pv_log(WARN, "cannot erase %s at 0x%llx: %s", mtd->dev,
		       (long long)off, strerror(errno));
		return -1;
	}

	return 0;
}

struct image_src {
	const char *head;
	size_t head_left;
	int fd;
	off_t left;
};

// fill blk from the head, then the fd; unused bytes stay erased (0xff)
static ssize_t fill_block(unsigned char *blk, size_t size,
			  struct image_src *src)
{
	size_t used = src->head_left < size ? src->head_left : size;

	memset(blk, 0xff, size);
	memcpy(blk, src->head, used);
	src->head += used;
	src->head_left -= used;

	while (used < size && src->left > 0) {
		size_t want = size - used;
		ssize_t rd;

		if ((off_t)want > src->left)
			want = src->left;
		rd = read(src->fd, blk + used, want);
		if (rd < 0 && errno == EINTR)
			continue;
		if (rd <= 0) {
			pv_log(WARN, "image ended before its size");
			return -1;
		}
		used += rd;
		src->left -= rd;
	}

	return used;
}

static int write_block(struct pv_mtd *mtd, off_t off, const unsigned char *blk,
		       size_t used)
{
	// only whole pages are written, the rest of the block stays erased
	size_t len =
		(used + mtd->writesize - 1) / mtd->writesize * mtd->writesize;

	if (pwrite(mtd->fd, blk, len, off) != (ssize_t)len) {
		pv_log(WARN, "cannot write %s at 0x%llx: %s", mtd->dev,
		       (long long)off, strerror(errno));
		return -1;
	}

	return 0;
}

int pv_mtd_write_image(struct pv_mtd *mtd, const void *head, size_t head_len,
		       int fd, off_t size)
{
	struct image_src src = { head, head_len, fd, size };
	off_t cap = pv_mtd_capacity(mtd), off = 0;
	unsigned char *blk;
	int ret = -1;

	if ((off_t)head_len + size > cap) {
		pv_log(ERROR, "image of %lld bytes does not fit in %s (%lld)",
		       (long long)head_len + size, mtd->name, (long long)cap);
		return -1;
	}

	blk = malloc(mtd->erasesize);
	if (!blk)
		return -1;

	while (src.head_left || src.left > 0) {
		ssize_t used;

		off = next_good_block(mtd, off);
		if (off < 0)
			goto out;
		used = fill_block(blk, mtd->erasesize, &src);
		if (used < 0 || erase_block(mtd, off) ||
		    write_block(mtd, off, blk, used))
			goto out;
		off += mtd->erasesize;
	}
	ret = fsync(mtd->fd) ? -1 : 0;
out:
	free(blk);
	return ret;
}
