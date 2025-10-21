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
#include <fcntl.h>
#include <errno.h>
#include <linux/limits.h>
#include <sys/stat.h>

#include "paths.h"
#include "bootloader.h"

#include "utils/str.h"
#include "utils/fs.h"

#define MODULE_NAME "grub"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define GRUB_HDR "# GRUB Environment Block\n"
#define HDR_SIZE sizeof(GRUB_HDR) - 1

static char *grub_env = 0;

static void grub_free()
{
	if (grub_env)
		free(grub_env);
}

static int grub_init()
{
	int fd, ret;
	char buf[PATH_MAX];
	struct stat st;

	if (grub_env)
		return 0;

	pv_paths_storage_boot_file(buf, PATH_MAX, GRUBENV_FNAME);
	grub_env = strdup(buf);

	if (stat(grub_env, &st))
		pv_log(ERROR, "unable to find grubenv");

	fd = open(grub_env, O_CREAT | O_RDWR | O_SYNC, 0600);
	if (fd < 0) {
		pv_log(ERROR, "unable to open/create grubenv");
		return -1;
	}

	ret = read(fd, buf, HDR_SIZE);
	if (ret != HDR_SIZE || memcmp(buf, GRUB_HDR, HDR_SIZE)) {
		pv_log(ERROR, "invalid grubenv, resetting contents");
		lseek(fd, 0, SEEK_SET);
		memset(buf, '#', sizeof(buf));
		memcpy(buf, GRUB_HDR, HDR_SIZE);
		if (write(fd, buf, sizeof(buf)) < 0) {
			pv_log(ERROR, "unable to initialize grubenv");
			close(fd);
			return -1;
		}
	}

	pv_log(INFO, "initialized grub environment block");
	close(fd);
	pv_fs_path_sync(grub_env);

	return 0;
}

static int read_grubenv(char *path, char *buf, int writable)
{
	int fd, ret;

	fd = open(path, writable ? O_RDWR | O_SYNC : O_RDONLY);
	if (fd < 0) {
		pv_log(ERROR, "unable to open grubenv");
		return -1;
	}

	ret = read(fd, buf, 1024);
	if (ret != 1024) {
		pv_log(ERROR, "invalid grubenv file");
		return -1;
	}

	if (memcmp(GRUB_HDR, buf, HDR_SIZE)) {
		pv_log(ERROR, "invalid grubenv header");
		return -1;
	}

	return fd;
}

static char *grub_get_env_key(char *key)
{
	int fd, len, klen;
	char buf[1024];
	char *next, *value = NULL;

	fd = read_grubenv(grub_env, buf, 0);
	if (fd < 0)
		return value;

	klen = strlen(key);
	next = buf + HDR_SIZE;
	len = strlen(buf) - HDR_SIZE;
	for (uint16_t i = HDR_SIZE; i < len; i++) {
		if (buf[i] != '\n')
			continue;

		// null terminate key/value pair
		buf[i] = '\0';

		if (!strncmp(next, key, klen)) {
			value = strdup(next + klen + 1);
			break;
		}
		next = buf + i + 1;
	}
	close(fd);

	return value;
}

static int grub_unset_env_key(char *key)
{
	int fd, ret;
	char old[1024];
	char new[1024];
	char *s, *d;

	pv_log(DEBUG, "unset boot env key %s", key);

	fd = read_grubenv(grub_env, old, 1);
	if (fd < 0)
		return -1;

	memset(new, '#', sizeof(new));
	d = new;
	memcpy(d, GRUB_HDR, HDR_SIZE);
	d += HDR_SIZE;

	// read all non-hit values into dest buf
	int len = 0;
	s = old + HDR_SIZE;
	for (uint16_t i = HDR_SIZE; i < (sizeof(old) - HDR_SIZE); i++) {
		if (old[i] != '\n') {
			len++;
			continue;
		}

		// copy each non-hit value
		if (memcmp(s, key, strlen(key))) {
			memcpy(d, s, len + 1);
			d += len + 1;
		}

		len = 0;
		s = old + i + 1;
	}

	lseek(fd, 0, SEEK_SET);
	ret = write(fd, new, sizeof(new));
	close(fd);
	pv_fs_path_sync(grub_env);
	if (ret != 1024) {
		pv_log(ERROR, "error writing grubenv");
		return -1;
	}

	return 0;
}

static int grub_set_env_key(char *key, char *value)
{
	int fd, ret;
	char old[1024];
	char new[1024];
	char *s, *d;

	pv_log(DEBUG, "set boot env key %s with value %s", key, value);

	fd = read_grubenv(grub_env, old, 1);
	if (fd < 0)
		return -1;

	memset(new, '#', sizeof(new));
	d = new;
	memcpy(d, GRUB_HDR, HDR_SIZE);
	d += HDR_SIZE;

	// read all non-hit values into dest buf
	int len = 0;
	s = old + HDR_SIZE;
	for (uint16_t i = HDR_SIZE; i < (sizeof(old) - HDR_SIZE); i++) {
		if (old[i] != '\n') {
			len++;
			continue;
		}

		// copy each non-hit value
		if (memcmp(s, key, strlen(key))) {
			memcpy(d, s, len + 1);
			d += len + 1;
		}

		len = 0;
		s = old + i + 1;
	}

	// convert value
	char v[128];
	SNPRINTF_WTRUNC(v, sizeof(v), "%s=%s\n", key, value);

	// write new key/value pair to destination
	memcpy(d, v, strlen(v));

	lseek(fd, 0, SEEK_SET);
	ret = write(fd, new, sizeof(new));
	close(fd);
	pv_fs_path_sync(grub_env);
	if (ret != 1024) {
		pv_log(ERROR, "error writing grubenv");
		return -1;
	}

	return 0;
}

static int grub_flush_env(void)
{
	return 0;
}

const struct bl_ops grub_ops = {
	.free = grub_free,
	.init = grub_init,
	.set_env_key = grub_set_env_key,
	.unset_env_key = grub_unset_env_key,
	.get_env_key = grub_get_env_key,
	.flush_env = grub_flush_env,
	.install_update = NULL,
	.commit_update = NULL,
	.fail_update = NULL,
};
