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

#ifndef PV_MTD_H
#define PV_MTD_H

#include <linux/limits.h>
#include <sys/types.h>
#include <stdint.h>

/*
 * A raw MTD partition seen as the list of its good erase blocks, the way
 * U-Boot's nand read sees it: logical offset 0 is the start of the first
 * good block and bad blocks are skipped.
 */
struct pv_mtd {
	char name[NAME_MAX];
	char dev[PATH_MAX];
	int fd;
	off_t erasesize;
	off_t writesize;
	off_t size;
};

/* Partition with exactly this name in /proc/mtd, or NULL. Free it. */
struct pv_mtd *pv_mtd_from_name(const char *name);
void pv_mtd_free(struct pv_mtd *mtd);

/* Bytes the good erase blocks of the partition can hold. */
off_t pv_mtd_capacity(struct pv_mtd *mtd);

/* Read len bytes from logical offset off; returns bytes read or -1. */
ssize_t pv_mtd_read(struct pv_mtd *mtd, off_t off, void *buf, size_t len);

/*
 * Write head (head_len bytes) followed by size bytes read from fd into the
 * good blocks from the start of the partition, erasing each block first.
 * Fails without touching the flash when it does not fit. Returns 0 or -1.
 */
int pv_mtd_write_image(struct pv_mtd *mtd, const void *head, size_t head_len,
		       int fd, off_t size);

#endif
