/*
 * Copyright (c) 2018-2025 Pantacor Ltd.
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
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>
#include <linux/limits.h>

#include "bootloader.h"
#include "config.h"
#include "paths.h"
#include "utils/str.h"
#include "utils/fs.h"

#define MODULE_NAME "uboot"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static char *pv_env = 0;
static char *uboot_txt = 0;
static char mtd_env_str[32];
static int single_env;

#define MTD_MATCH "dev:    size   erasesize  name\n"
#define MTD_ENV "pv-env"
#define MTD_ENV_SIZE 65536
#define UBOOT_ENV_SIZE 1024

static void uboot_free()
{
	if (uboot_txt)
		free(uboot_txt);
}

static int uboot_init()
{
	int fd, ret;
	struct stat st;
	char buf[PATH_MAX];
	char *next;

	// already init'd?
	if (uboot_txt)
		return 0;

	// setup uboot.txt location
	pv_paths_storage_boot_file(buf, PATH_MAX, UBOOTTXT_FNAME);
	uboot_txt = strdup(buf);

	pv_log(DEBUG, "uboot.txt@%s", uboot_txt);

	// get mtd_path from config or else use default
	single_env = pv_config_get_bool(PV_BOOTLOADER_MTD_ONLY);
	const char *mtd_path = pv_config_get_str(PV_BOOTLOADER_MTD_ENV);
	if (mtd_path)
		memcpy(mtd_env_str, mtd_path, strlen(mtd_path));
	else
		memcpy(mtd_env_str, MTD_ENV, sizeof(MTD_ENV));

	// find pv-env for trying flag store
	if (stat("/proc/mtd", &st))
		return 0;

	fd = open("/proc/mtd", O_RDONLY);
	if (fd < 0) {
		pv_log(ERROR, "open failed for /proc/mtd: %s", strerror(errno));
		return -1;
	}

	ret = read(fd, buf, sizeof(MTD_MATCH));
	if (ret < 0) {
		pv_log(ERROR, "Failed to read from %zd bytes from /proc/mtd",
		       sizeof(MTD_MATCH));
		return -2;
	}

	if (strncmp(buf, MTD_MATCH, strlen(MTD_MATCH))) {
		pv_log(ERROR,
		       "First line of /proc/mtd does not match '%s' instead we have '%s'",
		       MTD_MATCH, buf);
		return -3;
	}

	char *ns, *ne;
	ret = read(fd, buf, sizeof(buf));
	next = buf;
	while (next && ((next - buf) < ret)) {
		char name[64];
		ns = strchr(next, '\"');
		if (!ns)
			break;
		ns += 1;
		ne = strchr(ns, '\"');
		if (!ne)
			break;
		strncpy(name, ns, ne - ns);
		name[ne - ns] = '\0';
		if (!strcmp(name, mtd_env_str)) {
			int idx = -1;
			sscanf(next, "mtd%d:", &idx);
			SNPRINTF_WTRUNC(buf, sizeof(buf), "/dev/mtd%d", idx);
			pv_env = strdup(buf);
			break;
		}
		next = ne + 2;
	}

	pv_log(DEBUG, "pv-env@%s", pv_env);

	return 0;
}

static char *uboot_get_env_key(char *key)
{
	int fd, n, len, ret;
	char *buf, *path, *value = NULL;

	path = uboot_txt;
	if (single_env) {
		path = pv_env;
		len = MTD_ENV_SIZE;
	} else {
		len = UBOOT_ENV_SIZE;
	}

	fd = open(path, O_RDONLY);
	if (!fd)
		return value;

	lseek(fd, 0, SEEK_SET);
	buf = calloc(len, sizeof(char));
	ret = read(fd, buf, len);
	close(fd);

	n = strlen(key);

	int k = 0;
	for (int i = 0; i < ret; i++) {
		if (buf[i] != '\0')
			continue;

		if (!strncmp(buf + k, key, n)) {
			value = strdup(buf + k + n + 1);
			break;
		}
		k = i + 1;
	}
	free(buf);

	return value;
}

// this always happens in uboot.txt
static int uboot_set_env_key(char *key, char *value)
{
	int fd, ret = -1, res, len;
	unsigned char old[MTD_ENV_SIZE] = { 0 };
	unsigned char new[MTD_ENV_SIZE] = { 0 };
	char *s, *d, *path;
	char v[128] = { 0 };

	pv_log(DEBUG, "setting boot env key %s with value %s", key, value);

	path = uboot_txt;
	if (single_env) {
		path = pv_env;
		len = MTD_ENV_SIZE * sizeof(char);
	} else {
		len = UBOOT_ENV_SIZE;
	}

	fd = open(path, O_RDWR | O_CREAT | O_SYNC, 0600);
	if (fd < 0) {
		pv_log(ERROR, "open failed for %s: %s", path, strerror(errno));
		goto out;
	}

	lseek(fd, 0, SEEK_SET);
	res = read(fd, old, len);
	close(fd);
	pv_fs_path_sync(path);

	d = (char *)new;
	for (uint16_t i = 0; i < res; i++) {
		if ((old[i] == 0xFF && old[i + 1] == 0xFF) ||
		    (old[i] == '\0' && old[i + 1] == '\0'))
			break;

		if (old[i] == '\0')
			continue;

		s = (char *)old + i;
		len = strlen(s);
		if (memcmp(s, key, strlen(key))) {
			memcpy(d, s, len + 1);
			d += len + 1;
		}
		i += len;
	}

	SNPRINTF_WTRUNC(v, sizeof(v), "%s=%s", key, value);

	memcpy(d, v, strlen(v) + 1);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		pv_log(ERROR, "open failed for %s: %s", path, strerror(errno));
		goto out;
	}

	if (single_env) {
		erase_info_t ei;
		mtd_info_t mi;
		ioctl(fd, MEMGETINFO, &mi);
		ei.start = 0;
		ei.length = mi.erasesize;
		if (ioctl(fd, MEMUNLOCK, &ei))
			pv_log(DEBUG, "ioctl: MEMUNLOCK errno=%s",
			       strerror(errno));
		if (ioctl(fd, MEMERASE, &ei))
			pv_log(DEBUG, "ioctl: MEMERASE errno=%s",
			       strerror(errno));
	}
	lseek(fd, 0, SEEK_SET);
	write(fd, new, sizeof(new));
	fsync(fd);
	close(fd);
	pv_fs_path_sync(path);

	ret = 0;

out:
	return ret;
}

// this always happens in uboot.txt
static int uboot_unset_env_key(char *key)
{
	return uboot_set_env_key(key, "\0");
}

static int uboot_flush_env(void)
{
	int fd;
	erase_info_t ei;
	mtd_info_t mi;

	if (single_env) {
		uboot_unset_env_key("pv_trying");
		return 0;
	}

	if (!pv_env)
		return 0;

	if (!strstr(pv_env, "mtd"))
		return 0;

	fd = open(pv_env, O_RDWR | O_SYNC);
	if (fd < 0)
		return 0;

	char buf[32];
	read(fd, buf, sizeof(buf));
	buf[31] = '\0';
	pv_log(DEBUG, "Buf-dirty: '%s'", buf);

	ioctl(fd, MEMGETINFO, &mi);
	ei.start = 0;
	ei.length = mi.erasesize;
	if (ioctl(fd, MEMUNLOCK, &ei))
		pv_log(DEBUG, "ioctl: MEMUNLOCK errno=%s", strerror(errno));
	if (ioctl(fd, MEMERASE, &ei))
		pv_log(DEBUG, "ioctl: MEMERASE errno=%s", strerror(errno));

	close(fd);
	pv_fs_path_sync(pv_env);

	fd = open(pv_env, O_RDONLY);
	if (fd < 0) {
		pv_log(ERROR, "open failed for %s: %s", pv_env,
		       strerror(errno));
		return 0;
	}

	lseek(fd, 0, SEEK_SET);
	memset(buf, 0, sizeof(buf));
	read(fd, buf, sizeof(buf));
	buf[31] = '\0';
	pv_log(DEBUG, "Buf-clean: '%s'", buf);

	close(fd);

	return 0;
}

const struct bl_ops uboot_ops = {
	.free = uboot_free,
	.init = uboot_init,
	.set_env_key = uboot_set_env_key,
	.unset_env_key = uboot_unset_env_key,
	.get_env_key = uboot_get_env_key,
	.flush_env = uboot_flush_env,
	.install_update = NULL,
	.commit_update = NULL,
	.fail_update = NULL,
};
