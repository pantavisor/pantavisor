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
#include <linux/limits.h>

#include "utils/fs.h"
#include "utils/tsh.h"
#include "config.h"
#include "bootloader.h"

#define MODULE_NAME "uboot-ab"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define UBOOTAB_DEV_TMPL "/sys/block/mtdblock%d/device/%s"
#define UBOOTAB_KERNEL_PATH_TMPL "/storage/trails/%s/bsp/pantavisor.fit"
#define UBOOTAB_SYS_MAX_DEV (10)
// 2048 to rev
// 2048 to hash
#define UBOOTAB_PART_HEADER_SIZE (4096)

struct mtdpart {
	char *name;
	char *dev;
	uint32_t offset;
};

struct ubootab {
	struct mtdpart a;
	struct mtdpart b;
	struct mtdpart *available;
	char *pv_rev;
	char *pv_try;
	bool init;
};

static struct ubootab ubootab = { 0 };

static int run_command(const char *fmt, char *output, int size, ...)
{
	char *cmd = NULL;
	int out[2] = { -1, -1 };
	int wstatus = 0;

	va_list args;
	va_start(args, size);

	int len = vasprintf(&cmd, fmt, args);
	if (len < 0) {
		pv_log(DEBUG, "couldn't build command. fmt: %s", fmt);
		wstatus = -1;
		goto out;
	}

	if (pipe2(out, O_CLOEXEC) != 0) {
		pv_log(DEBUG, "couldn't not open pipe");
		wstatus = -1;
		goto out;
	}

	if (tsh_run_io(cmd, 1, &wstatus, NULL, out, NULL) != 0) {
		pv_log(DEBUG, "tsh call fail");
		goto out;
	}

	if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus)) {
		pv_log(DEBUG, "command failed %s status: %d", cmd,
		       WEXITSTATUS(wstatus));
		goto out;
	} else if (WIFEXITED(wstatus)) {
		pv_log(DEBUG, "command succeeded: %s", cmd);
	} else if (WIFSIGNALED(wstatus)) {
		pv_log(DEBUG, "command signalled %s: %d", cmd,
		       WTERMSIG(wstatus));
		goto out;
	} else {
		pv_log(DEBUG, "command failed with wstatus: %d", wstatus);
		goto out;
	}

	if (output)
		pv_fs_file_read_nointr(out[1], output, size);
out:
	if (cmd)
		free(cmd);

	close(out[0]);
	close(out[1]);
	va_end(args);

	return wstatus;
}

static int get_device_attr(int index, const char *attr, char *buf, int size)
{
	char path[PATH_MAX] = { 0 };
	ssize_t len = snprintf(path, PATH_MAX, UBOOTAB_DEV_TMPL, index, attr);
	if (len <= 0) {
		pv_log(DEBUG,
		       "snprintf fails, couldn't create path with index = %d",
		       index);
		return -1;
	}

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		pv_log(DEBUG, "couldn't open file %s", path);
		return -1;
	}

	memset(buf, 0, size);
	len = pv_fs_file_read_nointr(fd, buf, size);
	close(fd);

	if (len < 1) {
		pv_log(DEBUG, "couldn't read from %s with fd = %d", path, fd);
		return -1;
	}
	return 0;
}

static struct mtdpart mtdpart_from_name(const char *name)
{
	char curname[NAME_MAX] = { 0 };
	int index = 0;
	for (; index < UBOOTAB_SYS_MAX_DEV; ++index) {
		if (get_device_attr(index, "name", curname, NAME_MAX) != 0)
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

	char offset_str[512] = { 0 };
	if (get_device_attr(index, "offset", offset_str, 512) != 0) {
		pv_log(DEBUG, "couldn't get the device offset from %s", name);
		return (struct mtdpart){ 0 };
	}

	struct mtdpart mtdpart = {
		.name = strdup(curname),
		.dev = strdup(dev),
		.offset = strtoul(offset_str, NULL, 10),
	};

	return mtdpart;
}

static char *ubootab_get_env_key(char *key)
{
	char buf[4096] = { 0 };
	int ret = run_command("fw_printenv -n %s", buf, 4096, key);

	if (ret != 0)
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

	return !strncpy(buf, rev, strlen(rev));
}


static void set_available_part()
{
	char *rev = ubootab.pv_try ? ubootab.pv_try : ubootab.pv_rev;

	if (header_has_rev(ubootab.a.dev, rev))
		ubootab.available = &ubootab.a;
	else if (header_has_rev(ubootab.b.dev, rev))
		ubootab.available = &ubootab.b;
	else
		pv_log(DEBUG, "couldn't find the current active part");
}

static int ubootab_init()
{
	if (ubootab.init)
		return 0;

	ubootab.a = mtdpart_from_name(pv_config_get_str(PV_UBOOTAB_A_NAME));
	ubootab.b = mtdpart_from_name(pv_config_get_str(PV_UBOOTAB_B_NAME));

	ubootab.pv_rev = ubootab_get_env_key("pv_rev");
	ubootab.pv_try = ubootab_get_env_key("pv_try");

	set_available_part();

	ubootab.init = true;

	return 0;
}

static int ubootab_flush_env()
{
	return 0;
}

static int erase_part(int fd)
{
	mtd_info_t info;
	if (ioctl(fd, MEMGETINFO, &info) == -1) {
		pv_log(DEBUG, "couldn't get device info from %s",
		       ubootab.available->dev);
		return -1;
	}

	erase_info_t ei = { 0 };
	ei.length = info.erasesize;
	for (ei.start = 0; ei.start < info.size; ei.start += ei.length) {
		if (ioctl(fd, MEMUNLOCK, &ei) == -1) {
			pv_log(DEBUG, "couldn't unlock");
			return -1;
		}

		if (ioctl(fd, MEMERASE, &ei) == -1) {
			pv_log(DEBUG, "couldn't erase");
			return -1;
		}
	}

	return 0;
}

static int get_kernel_fd(const char *rev)
{
	char path[PATH_MAX] = { 0 };
	snprintf(path, PATH_MAX, UBOOTAB_KERNEL_PATH_TMPL, rev);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		pv_log(DEBUG, "couldn't open kernel file at %s", path);
		return -1;
	}

	return fd;
}

static int write_kernel(const char *rev)
{
	int ret = -1;
	int mtd_fd = open(ubootab.available->dev, O_RDWR);
	if (mtd_fd < 0) {
		pv_log(DEBUG, "couldn't open device %s to write the kernel",
		       ubootab.available->dev);
		return -1;
	}

	int kernel_fd = get_kernel_fd(rev);

	if (mtd_fd < 0 || kernel_fd < 0)
		goto out;

	if (erase_part(mtd_fd) != 0)
		goto out;

	lseek(mtd_fd, 0, SEEK_SET);
	lseek(kernel_fd, 0, SEEK_SET);
	write(mtd_fd, rev, UBOOTAB_PART_HEADER_SIZE);

	char buf[4096] = { 0 };
	ssize_t read_bytes = 0;
	ssize_t write_bytes = 0;

	while (read_bytes = read(kernel_fd, buf, 4096), read_bytes > 0)
		write_bytes += write(mtd_fd, buf, read_bytes);

	ret = 0;
out:
	if (mtd_fd >= 0)
		close(mtd_fd);
	if (kernel_fd >= 0)
		close(kernel_fd);

	if (ret != 0)
		pv_log(WARN, "couldn't write the kernel in the proper part");

	return ret;
}

static int ubootab_install_update(char *rev)
{
	return write_kernel(rev);
}

static int ubootab_delete_part(struct mtdpart *part)
{
	int fd = open(part->dev, O_RDWR);
	if (fd < 0) {
		pv_log(DEBUG, "couldn't get inactive fd to delete");
		return -1;
	}

	if (erase_part(fd) != 0) {
		pv_log(DEBUG, "couldn't erase inactive part");
		return -1;
	}

	return 0;
}

static int ubootab_fail_update()
{
	return 0;
}

static int ubootab_commit_update()
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
	.commit_update = ubootab_commit_update,
	.fail_update = ubootab_fail_update,
};