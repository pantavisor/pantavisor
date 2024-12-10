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

#include "utils/tsh.h"
#include "utils/mtd.h"
#include "config.h"
#include "bootloader.h"
#include "paths.h"

#define MODULE_NAME "uboot-ab"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define UBOOTAB_HEADER_SIZE (4096)
#define UBOOTAB_FW_CONFIG "/etc/fw_env.config"

struct ubootab {
	struct pv_mtd *a;
	struct pv_mtd *b;
	struct pv_mtd *free;
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

static bool header_has_rev(struct pv_mtd *mtd, const char *rev)
{
	char buf[UBOOTAB_HEADER_SIZE] = { 0 };
	if (pv_mtd_read(mtd, buf, UBOOTAB_HEADER_SIZE, 0) < 0)
		return false;

	char *header = buf + strlen("fit_rev=");

	return !strncmp(header, rev, strlen(rev));
}

static int set_free_part()
{
	char *rev = ubootab.pv_try ? ubootab.pv_try : ubootab.pv_rev;

	if (header_has_rev(ubootab.a, rev))
		ubootab.free = ubootab.b;
	else if (header_has_rev(ubootab.b, rev))
		ubootab.free = ubootab.a;
	else {
		pv_log(DEBUG, "couldn't find the current active part");
		return -1;
	}
	return 0;
}

static int write_fw_env_file_entry(int fd, const char *name)
{
	struct pv_mtd *mtd = pv_mtd_from_name(name);

	int offset = pv_config_get_int(PV_BOOTLOADER_UBOOTAB_ENV_OFFSET);
	int size = pv_config_get_int(PV_BOOTLOADER_UBOOTAB_ENV_SIZE);

	int n = dprintf(fd, "%s\t%d\t%d\t%lld\t%lld\n", mtd->dev, offset, size,
			(long long)mtd->erasesize,
			(long long)mtd->size / mtd->erasesize);

	free(mtd);

	return n < 0 ? -1 : 0;
}

static int setup_fw_utils()
{
	unlink(UBOOTAB_FW_CONFIG);

	int ret = -1;
	int fd = open(UBOOTAB_FW_CONFIG, O_WRONLY, O_CREAT | O_CLOEXEC, 0664);

	if (fd < 0) {
		pv_log(DEBUG,
		       "couldn't write config file, cannot be opened: %s (%d)",
		       strerror(errno), errno);
		return -1;
	}

	// header
	dprintf(fd,
		"# Device name\tDevice offset\tEnv. size\tFlash sector size\tNumber of sectors\n");

	char *env = pv_config_get_str(PV_BOOTLOADER_UBOOTAB_ENV_NAME);
	if (!env) {
		pv_log(DEBUG, "env partition name is NULL!");
		goto out;
	}

	write_fw_env_file_entry(fd, env);

	char *bak = pv_config_get_str(PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME);
	if (!bak)
		goto out;

	write_fw_env_file_entry(fd, bak);

out:
	close(fd);

	return ret;
}

static int ubootab_init()
{
	pv_log(DEBUG, "initializing uboot-ab");
	if (ubootab.init)
		return 0;

	setup_fw_utils();

	ubootab.a = pv_mtd_from_name(
		pv_config_get_str(PV_BOOTLOADER_UBOOTAB_A_NAME));
	ubootab.b = pv_mtd_from_name(
		pv_config_get_str(PV_BOOTLOADER_UBOOTAB_B_NAME));

	if (!ubootab.a || !ubootab.b) {
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

static int write_kernel_header(const char *rev)
{
	char buf[UBOOTAB_HEADER_SIZE] = { 0 };
	if (snprintf(buf, UBOOTAB_HEADER_SIZE, "fit_rev=%s", rev) < 0)
		return -1;

	if (pv_mtd_write(ubootab.free, buf, UBOOTAB_HEADER_SIZE, 0) < 0)
		return -1;

	return 0;
}

static int copy_kernel_image(int kernel_fd)
{
	if (pv_mtd_copy_fd(ubootab.free, kernel_fd, UBOOTAB_HEADER_SIZE) < 0)
		return -1;
	return 0;
}

static int write_kernel(const char *rev)
{
	pv_log(DEBUG, "writting kernel for rev = %s at part %s", rev,
	       ubootab.free->name);

	pv_mtd_erase(ubootab.free);
	if (write_kernel_header(rev) != 0) {
		pv_log(WARN,
		       "couldn't write kernel header, new image will not be written");
		return -1;
	}

	int kfd = get_kernel_fd(rev);
	if (kfd < 0) {
		pv_log(DEBUG, "couldn't open kernel image");
		return -1;
	}

	if (pv_mtd_copy_fd(ubootab.free, kfd, UBOOTAB_HEADER_SIZE) < 0) {
		pv_log(DEBUG, "couldn't write kernel");
		close(kfd);
		return -1;
	}

	close(kfd);
	return 0;
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