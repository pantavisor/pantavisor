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
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <errno.h>
#include <libgen.h>

#include "utils/tsh.h"
#include "utils/fitimg.h"
#include "utils/mtd.h"
#include "utils/list.h"
#include "config.h"
#include "bootloader.h"
#include "paths.h"

#define MODULE_NAME "uboot-ab"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define UBOOTAB_HEADER_SIZE (4096)
#define UBOOTAB_FW_CONFIG "/etc/fw_env.config"
#define UBOOTAB_HEADER_TMPL "fit_rev=%s"

struct ubootab {
	struct pv_mtd *active;
	struct pv_mtd *inactive;
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

	int len = vsnprintf(cmd, 0, fmt, args) + 1;
	if (len < 0)
		goto out;

	cmd = calloc(len, sizeof(char));
	if (!cmd)
		goto out;

	va_start(args, size);
	int n = vsnprintf(cmd, len, fmt, args);
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
	pv_mtd_seek(mtd, 0, SEEK_SET);
	if (pv_mtd_read(mtd, buf, UBOOTAB_HEADER_SIZE) < 0)
		return false;

	pv_log(DEBUG, "header: %s", buf);
	char *header = buf + strlen(UBOOTAB_HEADER_TMPL) - 2;

	return !strncmp(header, rev, strlen(rev));
}

static int set_free_part(struct pv_mtd *a, struct pv_mtd *b)
{
	char *rev = ubootab.pv_try ? ubootab.pv_try : ubootab.pv_rev;

	if (header_has_rev(a, rev)) {
		ubootab.active = a;
		ubootab.inactive = b;
	} else if (header_has_rev(b, rev)) {
		ubootab.active = b;
		ubootab.inactive = a;
	} else {
		pv_log(DEBUG, "couldn't find the current active part");
		return -1;
	}
	return 0;
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
	free(mtd);

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

static int ubootab_init()
{
	if (ubootab.init)
		return 0;

	setup_fw_utils();

	struct pv_mtd *a = pv_mtd_from_name(
		pv_config_get_str(PV_BOOTLOADER_UBOOTAB_A_NAME));
	struct pv_mtd *b = pv_mtd_from_name(
		pv_config_get_str(PV_BOOTLOADER_UBOOTAB_B_NAME));

	if (!a || !b) {
		pv_log(WARN, "couldn't initialize bootloader");
		return -1;
	}

	ubootab.pv_rev = ubootab_get_env_key("pv_rev");
	ubootab.pv_try = ubootab_get_env_key("pv_try");

	if (set_free_part(a, b) != 0)
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

static int write_kernel_header(struct pv_mtd *mtd, const char *rev)
{
	char header[UBOOTAB_HEADER_SIZE] = { 0 };
	if (snprintf(header, UBOOTAB_HEADER_SIZE, UBOOTAB_HEADER_TMPL, rev) < 0)
		return -1;

	pv_mtd_seek(mtd, 0, SEEK_SET);
	if (pv_mtd_write(mtd, header, UBOOTAB_HEADER_SIZE) < 0)
		return -1;
	return 0;
}

static int get_hashes_from_fd(int fd, struct dl_list *list)
{
	struct pv_fit *fit = pv_fit_new(fd);
	if (!fit)
		return 0;

	int len = pv_fit_get_signatures(fit, list);
	pv_fit_free(fit);

	return len;
}

static int get_hashes_from_fit(const char *rev, struct dl_list *list)
{
	int fd = get_kernel_fd(rev);
	if (fd < 0)
		return 0;

	int len = get_hashes_from_fd(fd, list);
	close(fd);
	return len;
}

static int get_hashes_from_part(struct pv_mtd *mtd, struct dl_list *list)
{
	int fd = memfd_create("temp", MFD_CLOEXEC);
	if (fd < 0)
		return 0;

	pv_mtd_seek(mtd, UBOOTAB_HEADER_SIZE, SEEK_SET);
	pv_mtd_copy_to_fd(mtd, fd, mtd->size - UBOOTAB_HEADER_SIZE);

	int len = get_hashes_from_fd(fd, list);
	close(fd);

	return len;
}

static bool is_kernel_new(const char *rev)
{
	bool ret = true;
	struct dl_list flst;
	struct dl_list mlst;

	dl_list_init(&flst);
	dl_list_init(&mlst);

	int flen = get_hashes_from_fit(rev, &flst);
	int mlen = get_hashes_from_part(ubootab.active, &mlst);

	pv_log(DEBUG, "signatures in file: %d", flen);
	pv_log(DEBUG, "signatures in mtd: %d", mlen);

	if (flen != mlen)
		goto out;

	struct pv_fit_prop *hsf, *tmp;
	struct pv_fit_prop *hsm =
		dl_list_first(&mlst, struct pv_fit_prop, list);

	dl_list_for_each_safe(hsf, tmp, &flst, struct pv_fit_prop, list)
	{
		if (hsf->len != hsm->len)
			goto out;

		for (uint32_t i = 0; i < hsf->len / sizeof(uint32_t); ++i) {
			if (hsf->data[i] != hsm->data[i])
				goto out;
		}
		hsm = dl_list_entry(hsm->list.next, struct pv_fit_prop, list);
	}
	ret = false;

out:
	dl_list_for_each_safe(hsf, tmp, &flst, struct pv_fit_prop, list)
	{
		pv_fit_prop_free(hsf);
	}

	dl_list_for_each_safe(hsm, tmp, &mlst, struct pv_fit_prop, list)
	{
		pv_fit_prop_free(hsm);
	}

	return ret;
}

static int update_kernel_header(struct pv_mtd *mtd, const char *rev)
{
	int ret = -1;
	char *buf = calloc(mtd->erasesize, sizeof(char));
	if (!buf)
		goto out;

	pv_mtd_seek(mtd, 0, SEEK_SET);
	if (pv_mtd_read(mtd, buf, mtd->erasesize) < 0)
		goto out;

	memset(buf, 0, UBOOTAB_HEADER_SIZE);
	snprintf(buf, UBOOTAB_HEADER_SIZE, UBOOTAB_HEADER_TMPL, rev);

	pv_mtd_erase(mtd, 0, mtd->erasesize);
	pv_mtd_seek(mtd, 0, SEEK_SET);
	pv_mtd_write(mtd, buf, mtd->erasesize);

	ret = 0;
out:
	if (buf)
		free(buf);

	return ret;
}

static int write_kernel(const char *rev)
{
	if (!is_kernel_new(rev)) {
		pv_log(DEBUG,
		       "kernel has not changed, no partition swap is needed");
		if (update_kernel_header(ubootab.active, rev) == 0)
			return 0;

		pv_log(WARN,
		       "partition update failed, trying to use the other one");
	}

	pv_log(DEBUG, "writting kernel for rev = %s at part %s", rev,
	       ubootab.inactive->name);

	pv_mtd_erase(ubootab.inactive, 0, ubootab.inactive->size);

	if (write_kernel_header(ubootab.inactive, rev) != 0) {
		pv_log(WARN, "couldn't write kernel header, update failed");
		return -1;
	}

	int kern_fd = get_kernel_fd(rev);
	if (kern_fd < 0) {
		pv_log(DEBUG, "couldn't open kernel image");
		return -1;
	}

	int ret = -1;
	struct stat st = { 0 };
	if (fstat(kern_fd, &st) != 0) {
		pv_log(DEBUG, "couldn't stat kernel fd");
		goto out;
	}

	if (pv_mtd_copy_from_fd(ubootab.inactive, kern_fd, st.st_size) < 0) {
		pv_log(DEBUG, "couldn't write kernel");
		goto out;
	}

	ret = 0;

out:
	close(kern_fd);

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