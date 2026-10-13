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
#include <stdarg.h>
#include <stdlib.h>

#include "utils/tsh.h"
#include "utils/mtd.h"
#include "ubootab_header.h"
#include "config.h"
#include "bootloader.h"
#include "paths.h"

#define MODULE_NAME "uboot-ab"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define UBOOTAB_FW_CONFIG "/etc/fw_env.config"

static int run_command(const char *fmt, char *output, int size, ...)
{
	char cmd[1024];
	char err[1024] = { 0 };
	va_list args;
	int n;

	va_start(args, size);
	n = vsnprintf(cmd, sizeof(cmd), fmt, args);
	va_end(args);
	if (n < 0 || n >= (int)sizeof(cmd)) {
		pv_log(DEBUG, "couldn't build command. fmt: %s", fmt);
		return -1;
	}

	if (tsh_run_output(cmd, 2, output, size, err, sizeof(err)) == -1) {
		pv_log(DEBUG, "command failed %s", err);
		return -1;
	}

	return 0;
}

static char *ubootab_get_env_key(char *key)
{
	char buf[4096] = { 0 };
	size_t n;

	if (run_command("fw_printenv -n %s", buf, sizeof(buf), key))
		return NULL;

	n = strlen(buf);
	while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';

	return n ? strdup(buf) : NULL;
}

static int ubootab_set_env_key(char *key, char *value)
{
	return run_command("fw_setenv %s %s", NULL, 0, key, value);
}

static int ubootab_unset_env_key(char *key)
{
	return run_command("fw_setenv %s", NULL, 0, key);
}

static int write_fw_env_file_entry(int fd, const char *name)
{
	struct pv_mtd *mtd = pv_mtd_from_name(name);

	if (!mtd) {
		pv_log(DEBUG, "couldn't find partition %s", name);
		return -1;
	}

	int offset = pv_config_get_int(PV_BOOTLOADER_UBOOTAB_ENV_OFFSET);
	int size = pv_config_get_int(PV_BOOTLOADER_UBOOTAB_ENV_SIZE);
	int n = dprintf(fd, "%s\t0x%x\t0x%x\t0x%x\t0x%x\n", mtd->dev, offset,
			size, (unsigned int)mtd->erasesize,
			(unsigned int)(mtd->size / mtd->erasesize));
	pv_mtd_free(mtd);

	return n < 0 ? -1 : 0;
}

static int setup_fw_utils()
{
	unlink(UBOOTAB_FW_CONFIG);

	int ret = -1;
	errno = 0;
	int fd = open(UBOOTAB_FW_CONFIG, O_WRONLY | O_CREAT | O_CLOEXEC, 0664);

	if (fd < 0) {
		pv_log(DEBUG, "couldn't write config file: %s (%d)",
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

static void ubootab_free()
{
}

static int ubootab_init()
{
	setup_fw_utils();

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

static int read_header(struct pv_mtd *mtd, struct ubootab_header *hdr)
{
	char buf[UBOOTAB_HEADER_SIZE];

	if (pv_mtd_read(mtd, 0, buf, sizeof(buf)) < 0 ||
	    ubootab_header_parse(buf, sizeof(buf), hdr)) {
		hdr->rev[0] = '\0';
		return -1;
	}

	return 0;
}

static int write_fit(struct pv_mtd *mtd, const char *rev)
{
	char head[UBOOTAB_HEADER_SIZE];
	struct stat st;
	int ret = -1;
	int fd = get_kernel_fd(rev);

	if (fd < 0)
		return -1;

	if (fstat(fd, &st) || ubootab_header_format(head, rev, st.st_size)) {
		pv_log(WARN, "couldn't build the header for rev %s", rev);
		goto out;
	}

	ret = pv_mtd_write_image(mtd, head, sizeof(head), fd, st.st_size);
out:
	close(fd);

	return ret;
}

// pv_rev unset means nothing was ever committed: the factory revision
static char *committed_rev(void)
{
	char *rev = ubootab_get_env_key("pv_rev");

	return rev ? rev : strdup("0");
}

static int ubootab_install_update(char *rev)
{
	struct ubootab_header ha, hb;
	struct pv_mtd *parts[2];
	char *pv_rev = committed_rev();
	int ret = -1, target;

	parts[0] = pv_mtd_from_name(
		pv_config_get_str(PV_BOOTLOADER_UBOOTAB_A_NAME));
	parts[1] = pv_mtd_from_name(
		pv_config_get_str(PV_BOOTLOADER_UBOOTAB_B_NAME));
	if (!parts[0] || !parts[1] || !pv_rev) {
		pv_log(ERROR, "couldn't find the fit partitions");
		goto out;
	}

	read_header(parts[0], &ha);
	read_header(parts[1], &hb);
	// the partition holding pv_rev is never touched, it is the fallback
	target = ubootab_pick_inactive(&ha, &hb, pv_rev);
	pv_log(INFO, "writing rev %s into %s, rev %s stays in the other", rev,
	       parts[target]->name, pv_rev);

	ret = write_fit(parts[target], rev);
	if (ret)
		pv_log(ERROR, "couldn't write rev %s into %s", rev,
		       parts[target]->name);
out:
	pv_mtd_free(parts[0]);
	pv_mtd_free(parts[1]);
	free(pv_rev);

	return ret;
}

static int ubootab_flush_env()
{
	return 0;
}

const struct bl_ops ubootab_ops = {
	.free = ubootab_free,
	.init = ubootab_init,
	.set_env_key = ubootab_set_env_key,
	.unset_env_key = ubootab_unset_env_key,
	.get_env_key = ubootab_get_env_key,
	.flush_env = ubootab_flush_env,
	.install_update = ubootab_install_update,
	.commit_update = NULL,
	.fail_update = NULL,
};
