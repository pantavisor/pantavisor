/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <mtd/mtd-user.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <errno.h>

#include "utils/fs.h"
#include "utils/tsh.h"
#include "utils/str.h"
#include "config.h"
#include "bootloader.h"
#include "paths.h"

#define MODULE_NAME "uboot-ab"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define UBOOTAB_SYS_PATH "/sys/block/mtdblock%d/device/%s"
#define UBOOTAB_SYS_MAX_DEV (10)
#define UBOOTAB_PART_HEADER_SIZE (4096)

struct mtdpart {
	char *name;
	char *dev;
	off_t wr_size;
};

struct ubootab {
	struct mtdpart a;
	struct mtdpart b;
	struct mtdpart *free;
	char *pv_rev;
	char *pv_try;
	bool init;
};

static struct ubootab ubootab = { 0 };

static int run_command(const char *fmt, char *output, int size, ...)
{
	char *cmd = NULL;
	char err[1024] = { 0 };
	int ret = -1;

	va_list args;
	va_start(args, size);

	int len = vasprintf(&cmd, fmt, args);
	if (len < 0) {
		pv_log(DEBUG, "couldn't build command. fmt: %s", fmt);
		goto out;
	}

	if (tsh_run_output(cmd, 2, output, size, err, sizeof(err)) == -1) {
		pv_log(DEBUG, "command failed %s", err);
		goto out;
	}

	ret = 0;

out:
	if (cmd)
		free(cmd);

	va_end(args);

	return ret;
}

static int get_device_attr(int index, char *buf, int size, const char *attr)
{
	char path[PATH_MAX] = { 0 };

	SNPRINTF_WTRUNC(path, PATH_MAX, UBOOTAB_SYS_PATH, index, attr);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		pv_log(DEBUG, "couldn't open file %s", path);
		return -1;
	}

	memset(buf, 0, size);
	int len = pv_fs_file_read_nointr(fd, buf, size);
	close(fd);

	if (len < 1) {
		pv_log(DEBUG, "couldn't read from %s with fd = %d", path, fd);
		return -1;
	}
	return 0;
}

static struct mtdpart mtdpart_from_name(const char *name)
{
	// always use NAME_MAX
	char curname[NAME_MAX] = { 0 };
	int index = 0;
	for (; index < UBOOTAB_SYS_MAX_DEV; ++index) {
		if (get_device_attr(index, curname, NAME_MAX, "name") != 0)
			continue;

		if (!strncmp(curname, name, strlen(name)))
			break;
	}

	if (index >= UBOOTAB_SYS_MAX_DEV) {
		pv_log(ERROR, "couldn't find any device named %s", name);
		return (struct mtdpart){ 0 };
	}

	char dev[PATH_MAX] = { 0 };
	snprintf(dev, PATH_MAX, "/dev/mtd%d", index);

	char wr_size_str[32] = { 0 };
	if (get_device_attr(index, wr_size_str, 32, "writesize") != 0) {
		pv_log(DEBUG, "couldn't get writesize");
		return (struct mtdpart){ 0 };
	}

	errno = 0;
	int wr_size = strtol(wr_size_str, NULL, 10);
	if (errno == ERANGE) {
		pv_log(DEBUG, "couldn't get writesize, bas format. src = %s",
		       wr_size_str);
		return (struct mtdpart){ 0 };
	}

	struct mtdpart mtdpart = {
		.name = strdup(curname),
		.dev = strdup(dev),
		.wr_size = wr_size,
	};

	return mtdpart;
}

static char *ubootab_get_env_key(char *key)
{
	char buf[4096] = { 0 };
	int ret = run_command("fw_printenv -n %s", buf, 4096, key);

	size_t n = strlen(buf) - 1;
	while ((buf[n] == '\n' || buf[n] == '\r') && n >= 0) {
		buf[n] = '\0';
		--n;
	}

	if (ret != 0 || strlen(buf) == 0)
		return NULL;

	return strdup(buf);
}

static int ubootab_set_env_key(char *key, char *value)
{
	return run_command("fw_setenv %s %s", NULL, 0, key, value);
}

static int ubootab_unset_env_key(char *key)
{
	return run_command("fw_setenv %s", NULL, 0, key);
}

static int header_read(const char *dev, char *buf)
{
	int fd = open(dev, O_RDONLY);
	if (fd < 0) {
		pv_log(DEBUG,
		       "couldn't open device, cannot get the part header");
		return -1;
	}

	memset(buf, 0, UBOOTAB_PART_HEADER_SIZE);
	read(fd, buf, UBOOTAB_PART_HEADER_SIZE);
	close(fd);

	return 0;
}

static bool header_has_rev(const char *dev, const char *rev)
{
	char buf[UBOOTAB_PART_HEADER_SIZE] = { 0 };
	if (header_read(dev, buf) != 0)
		return false;

	char *header = buf + strlen("fit_rev=");

	return !strncmp(header, rev, strlen(rev));
}

static int set_free_part()
{
	char *rev = ubootab.pv_try ? ubootab.pv_try : ubootab.pv_rev;

	if (header_has_rev(ubootab.a.dev, rev))
		ubootab.free = &ubootab.b;
	else if (header_has_rev(ubootab.b.dev, rev))
		ubootab.free = &ubootab.a;
	else {
		pv_log(DEBUG, "couldn't find the current active part");
		return -1;
	}
	return 0;
}

static int ubootab_init()
{
	pv_log(DEBUG, "initializing uboot-ab");
	if (ubootab.init)
		return 0;

	ubootab.a = mtdpart_from_name(
		pv_config_get_str(PV_BOOTLOADER_UBOOTAB_A_NAME));
	ubootab.b = mtdpart_from_name(
		pv_config_get_str(PV_BOOTLOADER_UBOOTAB_B_NAME));

	if (ubootab.a.name == NULL || ubootab.b.name == NULL) {
		pv_log(WARN, "couldn't initialize bootloader");
		return -1;
	}

	ubootab.pv_rev = ubootab_get_env_key("pv_rev");
	ubootab.pv_try = ubootab_get_env_key("pv_try");

	if (set_free_part() != 0)
		return -1;

	ubootab.init = true;

	return 0;
}

static int erase_part(int fd)
{
	mtd_info_t info;
	if (ioctl(fd, MEMGETINFO, &info) == -1) {
		pv_log(DEBUG, "couldn't get device info from %s",
		       ubootab.free->dev);
		return -1;
	}

	erase_info_t ei = { 0 };
	errno = 0;
	ei.length = info.erasesize;
	for (ei.start = 0; ei.start < info.size; ei.start += ei.length) {
		if (ioctl(fd, MEMUNLOCK, &ei) == -1) {
			// errno 524 is ENOTSUPP in the linux driver
			// implementation, sadly seems no to be visible from
			// here using that name.
			if (errno != 524) {
				pv_log(DEBUG, "couldn't unlock %s (%d)",
				       strerror(errno), errno);
				return -1;
			}
		}

		if (ioctl(fd, MEMERASE, &ei) == -1) {
			pv_log(DEBUG, "couldn't erase %s (%d)", strerror(errno),
			       errno);
			return -1;
		}
	}

	return 0;
}

static int get_kernel_fd(const char *rev)
{
	char path[PATH_MAX] = { 0 };
	pv_paths_storage_trail_pv_file(path, PATH_MAX, rev, "pantavisor.fit");

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		pv_log(DEBUG, "couldn't open kernel file at %s", path);
		return -1;
	}

	return fd;
}

static int write_kernel_header(int fd, const char *rev)
{
	char buf[UBOOTAB_PART_HEADER_SIZE] = { 0 };
	if (snprintf(buf, UBOOTAB_PART_HEADER_SIZE, "fit_rev=%s", rev) < 0)
		return -1;

	lseek(fd, 0, SEEK_SET);
	return write(fd, buf, UBOOTAB_PART_HEADER_SIZE) == -1 ? -1 : 0;
}

static int copy_kernel_image(int kernel_fd, int part_fd)
{
	lseek(kernel_fd, 0, SEEK_SET);
	lseek(part_fd, UBOOTAB_PART_HEADER_SIZE, SEEK_SET);

	struct stat st = { 0 };
	if (fstat(kernel_fd, &st) != 0) {
		pv_log(DEBUG, "couldn't get kernel size");
		return -1;
	}

	char *buf = calloc(ubootab.free->wr_size, sizeof(char));
	if (!buf) {
		pv_log(WARN,
		       "couldn't allocate buffer, kernel image will not be written");
		return -1;
	}

	ssize_t read_bytes = 0;
	ssize_t write_bytes = 0;

	while (write_bytes < st.st_size) {
		ssize_t cur_rd = read(kernel_fd, buf, ubootab.free->wr_size);
		if (cur_rd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		ssize_t cur_wr = 0;
		do {
			cur_wr += write(part_fd, buf + cur_wr,
					ubootab.free->wr_size);
			if (cur_wr < 0) {
				if (errno == EINTR)
					continue;

				break;
			}
		} while (cur_wr < cur_rd);

		write_bytes += cur_wr;
	}

	fsync(part_fd);
	pv_log(DEBUG, "file size: %zd, written bytes: %zd", (size_t)st.st_size,
	       write_bytes);

	free(buf);

	return 0;
}

static int write_kernel(const char *rev)
{
	pv_log(DEBUG, "writting kernel for rev = %s at part %s", rev,
	       ubootab.free->name);

	int ret = -1;
	int part_fd = open(ubootab.free->dev, O_RDWR);
	if (part_fd < 0) {
		pv_log(DEBUG, "couldn't open device %s to write the kernel",
		       ubootab.free->dev);
		return -1;
	}

	int kernel_fd = get_kernel_fd(rev);

	if (part_fd < 0 || kernel_fd < 0)
		goto out;

	if (erase_part(part_fd) != 0)
		goto out;

	if (write_kernel_header(part_fd, rev) != 0) {
		pv_log(WARN,
		       "couldn't write kernel header, new image will not be written");
		goto out;
	}

	if (copy_kernel_image(kernel_fd, part_fd) != 0) {
		pv_log(DEBUG, "couldn't write kernel");
		goto out;
	}

	ret = 0;
out:
	if (part_fd >= 0)
		close(part_fd);
	if (kernel_fd >= 0)
		close(kernel_fd);

	if (ret != 0)
		pv_log(WARN,
		       "couldn't write the kernel in the proper part (%s)",
		       ubootab.free->name);

	return ret;
}

static int ubootab_install_update(char *rev)
{
	return write_kernel(rev);
}

static int ubootab_flush_env()
{
	return 0;
}

const struct bl_ops ubootab_ops = {
	.init = ubootab_init,
	.set_env_key = ubootab_set_env_key,
	.unset_env_key = ubootab_unset_env_key,
	.get_env_key = ubootab_get_env_key,
	.flush_env = ubootab_flush_env,
	.install_update = ubootab_install_update,
	.commit_update = NULL,
	.fail_update = NULL,
};