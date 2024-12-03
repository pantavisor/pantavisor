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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE SE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef PV_MTD_H
#define PV_MTD_H

#include <linux/limits.h>
#include <sys/types.h>
#include <stdint.h>

struct pv_mtd {
	char name[NAME_MAX];
	char dev[PATH_MAX];
	int fd;
	off_t erasesize;
	off_t writesize;
	off_t size;
};

struct pv_mtd *pv_mtd_from_name(const char *name);
void pv_mtd_free(struct pv_mtd *mtd);
int pv_mtd_erase(struct pv_mtd *mtd, off_t from, off_t len);
ssize_t pv_mtd_read(struct pv_mtd *mtd, void *buf, size_t size);
ssize_t pv_mtd_write(struct pv_mtd *mtd, const void *buf, size_t buf_sz);
ssize_t pv_mtd_copy_from_fd(struct pv_mtd *mtd, int fd, off_t size);
ssize_t pv_mtd_copy_to_fd(struct pv_mtd *mtd, int fd, off_t size);
off_t pv_mtd_seek(struct pv_mtd *mtd, off_t offset, int whence);

#endif
