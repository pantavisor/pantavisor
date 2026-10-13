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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <mtd/mtd-user.h>

#include "uboot_mtd_env.h"
#include "uboot_env_buf.h"
#include "utils/str.h"

#define MODULE_NAME "uboot-mtd-env"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define ENV_CRC_LEN 4
#define RAW_ENV_SIZE 65536
#define MAX_ERASE_SIZE (4 * 1024 * 1024)

struct mtd_env {
	int fd;
	off_t offset; // start of the erase block holding the env
	size_t erasesize;
	unsigned char *blk; // the erase block as read
	size_t size; // bytes of the block that make up the env
	unsigned char *data; // key=value list inside blk
	size_t data_size;
	enum uboot_env_kind kind;
};

int pv_uboot_mtd_find(const char *name, char *dev, size_t size)
{
	char line[256];
	FILE *f = fopen("/proc/mtd", "r");
	int ret = -1;

	if (!f)
		return -1;

	while (ret && fgets(line, sizeof(line), f)) {
		char *start = strchr(line, '"');
		char *end = start ? strchr(start + 1, '"') : NULL;
		int idx = -1;

		if (!end || sscanf(line, "mtd%d:", &idx) != 1)
			continue;
		*end = '\0';
		if (!strcmp(start + 1, name)) {
			SNPRINTF_WTRUNC(dev, size, "/dev/mtd%d", idx);
			ret = 0;
		}
	}
	fclose(f);

	return ret;
}

static void env_close(struct mtd_env *e)
{
	if (e->fd >= 0)
		close(e->fd);
	free(e->blk);
	memset(e, 0, sizeof(*e));
	e->fd = -1;
}

static int is_bad_block(int fd, off_t offset)
{
	loff_t off = offset;

	// not every MTD type knows bad blocks (NOR): then the block is good
	return ioctl(fd, MEMGETBADBLOCK, &off) > 0;
}

// read the first good erase block, like U-Boot's ENV_RANGE bad block skip
static int env_load(struct mtd_env *e, const char *dev, int flags,
		    enum uboot_mtd_format fmt)
{
	struct mtd_info_user mi;
	off_t off;

	memset(e, 0, sizeof(*e));
	e->fd = open(dev, flags);
	if (e->fd < 0) {
		pv_log(INFO, "cannot open %s: %s", dev, strerror(errno));
		return -1;
	}

	if (ioctl(e->fd, MEMGETINFO, &mi) || !mi.erasesize ||
	    mi.erasesize > MAX_ERASE_SIZE) {
		pv_log(INFO, "%s is not usable MTD flash", dev);
		goto err;
	}

	for (off = 0; off < (off_t)mi.size; off += mi.erasesize)
		if (!is_bad_block(e->fd, off))
			break;
	if (off >= (off_t)mi.size) {
		pv_log(INFO, "no good erase block in %s", dev);
		goto err;
	}

	e->erasesize = mi.erasesize;
	e->offset = off;
	e->blk = malloc(e->erasesize);
	if (!e->blk ||
	    pread(e->fd, e->blk, e->erasesize, off) != (ssize_t)e->erasesize) {
		pv_log(INFO, "cannot read %s: %s", dev, strerror(errno));
		goto err;
	}

	e->kind = uboot_env_detect(e->blk, e->erasesize, &e->size);
	if (fmt == UBOOT_MTD_STD) {
		e->data = e->blk + ENV_CRC_LEN;
		e->data_size = e->size - ENV_CRC_LEN;
	} else {
		e->size = e->erasesize < RAW_ENV_SIZE ? e->erasesize :
							RAW_ENV_SIZE;
		e->data = e->blk;
		e->data_size = e->size;
	}

	return 0;
err:
	env_close(e);
	return -1;
}

// 1 when this env can be read and edited as fmt, logging why not
static int env_usable(const struct mtd_env *e, const char *dev,
		      enum uboot_mtd_format fmt)
{
	if (fmt == UBOOT_MTD_RAW) {
		if (e->kind == UBOOT_ENV_NONE)
			return 1;
		pv_log(WARN, "%s holds a U-Boot environment, not touching it",
		       dev);
		return 0;
	}

	if (e->kind == UBOOT_ENV_STD)
		return 1;
	if (e->kind == UBOOT_ENV_REDUNDANT) {
		pv_log(WARN,
		       "%s holds a redundant U-Boot environment, which is not supported yet",
		       dev);
		return 0;
	}

	pv_log(INFO, "no U-Boot environment in %s, U-Boot never saved one",
	       dev);
	return 0;
}

char *pv_uboot_mtd_env_get(const char *dev, enum uboot_mtd_format fmt,
			   const char *key)
{
	struct mtd_env e;
	char *value = NULL;

	if (env_load(&e, dev, O_RDONLY, fmt))
		return NULL;
	if (env_usable(&e, dev, fmt))
		value = uboot_env_get(e.data, e.data_size, key);
	env_close(&e);

	return value;
}

static int env_write(struct mtd_env *e, const char *dev,
		     enum uboot_mtd_format fmt)
{
	erase_info_t ei = { .start = e->offset, .length = e->erasesize };
	unsigned char *check = malloc(e->size);
	size_t size;
	int ret = -1;

	if (fmt == UBOOT_MTD_STD)
		uboot_env_seal(e->blk, e->size);

	if (!check)
		return -1;

	if (ioctl(e->fd, MEMUNLOCK, &ei))
		pv_log(DEBUG, "MEMUNLOCK on %s: %s", dev, strerror(errno));
	if (ioctl(e->fd, MEMERASE, &ei)) {
		pv_log(WARN, "cannot erase %s: %s", dev, strerror(errno));
		goto out;
	}
	if (pwrite(e->fd, e->blk, e->size, e->offset) != (ssize_t)e->size ||
	    fsync(e->fd)) {
		pv_log(WARN, "cannot write %s: %s", dev, strerror(errno));
		goto out;
	}

	if (pread(e->fd, check, e->size, e->offset) != (ssize_t)e->size ||
	    memcmp(check, e->blk, e->size) ||
	    (fmt == UBOOT_MTD_STD &&
	     uboot_env_detect(check, e->size, &size) != UBOOT_ENV_STD)) {
		pv_log(WARN, "%s does not read back what was written", dev);
		goto out;
	}
	ret = 0;
out:
	free(check);
	return ret;
}

int pv_uboot_mtd_env_set(const char *dev, enum uboot_mtd_format fmt,
			 const char *key, const char *value)
{
	struct mtd_env e;
	char *old;
	int ret = 1;

	if (env_load(&e, dev, O_RDWR, fmt))
		return 1;
	if (!env_usable(&e, dev, fmt))
		goto out;

	// do not wear the flash for a change that is already there
	old = uboot_env_get(e.data, e.data_size, key);
	if ((!old && !value) || (old && value && !strcmp(old, value))) {
		free(old);
		ret = 0;
		goto out;
	}
	free(old);

	if (uboot_env_edit(e.data, e.data_size, key, value)) {
		pv_log(WARN, "no room for %s in %s", key, dev);
		ret = -1;
		goto out;
	}

	ret = env_write(&e, dev, fmt);
out:
	env_close(&e);
	return ret;
}
