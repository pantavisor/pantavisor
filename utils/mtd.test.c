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

/*
 * pv_mtd on a file standing in for the flash: the ioctls are replaced here
 * so bad blocks can be placed anywhere.
 */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>

#include "mtd.h"

#define BLOCK 8192
#define PAGE 2048
#define BLOCKS 8

static unsigned char bad[BLOCKS];

// replaces libc's ioctl for this test binary
int ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);

	if (req == MEMGETBADBLOCK)
		return bad[*(loff_t *)arg / BLOCK];
	if (req == MEMUNLOCK) {
		errno = 524;
		return -1;
	}
	if (req == MEMERASE) {
		erase_info_t *ei = arg;
		unsigned char *ff = malloc(ei->length);

		assert(!bad[ei->start / BLOCK]);
		memset(ff, 0xff, ei->length);
		assert(pwrite(fd, ff, ei->length, ei->start) ==
		       (ssize_t)ei->length);
		free(ff);
		return 0;
	}
	return -1;
}

void __log(char *module, int level, const char *fmt, ...)
{
	(void)module;
	(void)level;
	(void)fmt;
}

int pv_uboot_mtd_find(const char *name, char *dev, size_t size)
{
	(void)name;
	(void)dev;
	(void)size;
	return -1;
}

static struct pv_mtd *fake_flash(void)
{
	struct pv_mtd *mtd = calloc(1, sizeof(*mtd));
	unsigned char blk[BLOCK];
	char path[] = "/tmp/mtdtestXXXXXX";

	mtd->fd = mkstemp(path);
	unlink(path);
	memset(blk, 0xff, sizeof(blk));
	for (int i = 0; i < BLOCKS; i++)
		assert(write(mtd->fd, blk, BLOCK) == BLOCK);
	mtd->erasesize = BLOCK;
	mtd->writesize = PAGE;
	mtd->size = BLOCK * BLOCKS;
	snprintf(mtd->name, sizeof(mtd->name), "fake");
	memset(bad, 0, sizeof(bad));
	return mtd;
}

static int data_fd(size_t size, unsigned char seed)
{
	char path[] = "/tmp/mtddataXXXXXX";
	int fd = mkstemp(path);
	unsigned char *d = malloc(size);

	unlink(path);
	for (size_t i = 0; i < size; i++)
		d[i] = (unsigned char)(seed + i * 7);
	assert(write(fd, d, size) == (ssize_t)size);
	free(d);
	lseek(fd, 0, SEEK_SET);
	return fd;
}

static unsigned char want(size_t i, unsigned char seed)
{
	return (unsigned char)(seed + i * 7);
}

static void test_capacity(void)
{
	struct pv_mtd *mtd = fake_flash();

	assert(pv_mtd_capacity(mtd) == BLOCK * BLOCKS);
	bad[0] = bad[3] = 1;
	assert(pv_mtd_capacity(mtd) == BLOCK * (BLOCKS - 2));
	pv_mtd_free(mtd);
}

// header and data land in sequential good blocks, bad ones are skipped
static void test_write_skips_bad_blocks(void)
{
	struct pv_mtd *mtd = fake_flash();
	size_t size = BLOCK * 2 + 100;
	unsigned char head[64], *got = malloc(64 + size);
	int fd = data_fd(size, 3);

	bad[0] = bad[2] = 1;
	memset(head, 'H', sizeof(head));
	assert(!pv_mtd_write_image(mtd, head, sizeof(head), fd, size));

	assert(pv_mtd_read(mtd, 0, got, 64 + size) == (ssize_t)(64 + size));
	assert(!memcmp(got, head, 64));
	for (size_t i = 0; i < size; i++)
		assert(got[64 + i] == want(i, 3));

	// physical layout: header in block 1 (first good), data in 3 and 4
	unsigned char phys[8];
	assert(pread(mtd->fd, phys, 8, BLOCK * 1) == 8 && phys[0] == 'H');
	assert(pread(mtd->fd, phys, 8, BLOCK * 2) == 8 && phys[0] == 0xff);
	assert(pread(mtd->fd, phys, 8, BLOCK * 3) == 8 &&
	       phys[0] == want(BLOCK - 64, 3));
	// blocks after the image are untouched
	assert(pread(mtd->fd, phys, 8, BLOCK * 6) == 8 && phys[0] == 0xff);

	close(fd);
	free(got);
	pv_mtd_free(mtd);
}

static void test_read_at_offset(void)
{
	struct pv_mtd *mtd = fake_flash();
	size_t size = BLOCK * 3;
	unsigned char head[16] = { 1 }, got[300];
	int fd = data_fd(size, 9);

	bad[1] = 1;
	assert(!pv_mtd_write_image(mtd, head, sizeof(head), fd, size));
	// across the block 0 / block 2 boundary, like U-Boot nand read
	assert(pv_mtd_read(mtd, BLOCK - 100, got, sizeof(got)) ==
	       (ssize_t)sizeof(got));
	for (size_t i = 0; i < sizeof(got); i++)
		assert(got[i] == want(BLOCK - 100 + i - 16, 9));

	close(fd);
	pv_mtd_free(mtd);
}

static void test_too_big_leaves_flash_alone(void)
{
	struct pv_mtd *mtd = fake_flash();
	size_t size = BLOCK * (BLOCKS - 1);
	unsigned char head[4096] = { 1 }, byte;
	int fd = data_fd(size, 1);

	bad[5] = 1;
	// 7 blocks of data plus the header need 8, only 7 are good
	assert(pv_mtd_write_image(mtd, head, sizeof(head), fd, size));
	assert(pread(mtd->fd, &byte, 1, 0) == 1 && byte == 0xff);

	// without the bad block the same image fits exactly
	bad[5] = 0;
	lseek(fd, 0, SEEK_SET);
	assert(!pv_mtd_write_image(mtd, head, sizeof(head), fd, size));
	close(fd);
	pv_mtd_free(mtd);
}

static void test_short_source_fails(void)
{
	struct pv_mtd *mtd = fake_flash();
	unsigned char head[16] = { 1 };
	int fd = data_fd(100, 1);

	// the file is shorter than the size announced for it
	assert(pv_mtd_write_image(mtd, head, sizeof(head), fd, 5000));
	close(fd);
	pv_mtd_free(mtd);
}

int main(void)
{
	test_capacity();
	test_write_skips_bad_blocks();
	test_read_at_offset();
	test_too_big_leaves_flash_alone();
	test_short_source_fails();
	puts("mtd: ok");
	return 0;
}
