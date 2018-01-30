/*
 * Copyright (c) 2018 Pantacor Ltd.
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

#define MODULE_NAME			"uboot"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"

#include "bootloader.h"

static char *pv_env = 0;
static char *uboot_txt = 0;

#define MTD_MATCH	"dev:    size   erasesize  name\n"
#define MTD_ENV		"pv-env"

static int uboot_init(struct pantavisor_config *c)
{
	int fd, ret;
	struct stat st;
	char buf[4096];
	char *next;

	// already init'd?
	if (uboot_txt)
		return 0;

	// setup uboot.txt location
	sprintf(buf, "%s/boot/uboot.txt", c->storage.mntpoint);
	uboot_txt = strdup(buf);

	pv_log(DEBUG, "uboot.txt@%s", uboot_txt);

	// find pv-env for trying flag store
	if (stat("/proc/mtd", &st))
		return 0;

	fd = open("/proc/mtd", O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, sizeof(MTD_MATCH));
	if (ret < 0)
		return -1;

	if (!strcmp(buf, MTD_MATCH))
		return -1;

	char *ns, *ne;
	ret = read(fd, buf, sizeof(buf));
	next = buf;
	while (next && ((next-buf) < ret)) {
		char name[64];
		ns = strchr(next, '\"');
		if (!ns)
			break;
		ns += 1;
		ne = strchr(ns, '\"');
		if (!ne)
			break;
		strncpy(name, ns, ne - ns);
		name[ne-ns] = '\0';
		if (!strcmp(name, MTD_ENV)) {
			int idx = -1;
			sscanf(next, "mtd%d:", &idx);
			sprintf(buf, "/dev/mtd%d", idx);
			pv_env = strdup(buf);
			break;
		}
		next = ne + 2;
	}

	pv_log(DEBUG, "pv-env@%s", pv_env);

	return 0;
}

static int uboot_get_env_key(char *key)
{
	int fd, n;
	int value = 0;
	char *buf;
	struct stat st;

	if (stat(uboot_txt, &st))
		return -1;

	fd = open(uboot_txt, O_RDONLY);
	if (!fd)
		return -1;

	lseek(fd, 0, SEEK_SET);
	buf = calloc(1, st.st_size * sizeof(char));
	read(fd, buf, st.st_size);
	close(fd);

	n = strlen(key);

	int k = 0;
	for (int i = 0; i < st.st_size; i++) {
		if (buf[i] != '\0')
			continue;

		if (!strncmp(buf+k, key, n)) {
			value = atoi(buf+k+n+1);
			break;
		}
		k = i+1;
	}
	free(buf);

	return value;
}

// this always happens in uboot.txt
static int uboot_unset_env_key(char *key)
{
	int fd, ret;
	char old[1024] = { 0 };
	char new[1024] = { 0 };
	char *s, *d;

	fd = open(uboot_txt, O_CREAT | O_RDWR | O_SYNC, 0600);
	if (!fd)
		return 0;

	ret = read(fd, old, sizeof(old));
	if (ret < 0) {
		pv_log(ERROR, "error reading uboot.txt");
		return -1;
	}

	int len = 0;
	d = new;
	s = old;
	for (uint16_t i = 0; i < ret; i++) {
		if (old[i] == '\0')
			continue;

		s = old+i;
		len = strlen(s);
		if (memcmp(s, key, strlen(key))) {
			memcpy(d, s, len+1);
			d += len+1;
		}
		i += len;
		len = 0;
	}

	lseek(fd, 0, SEEK_SET);
	ret = write(fd, new, sizeof(new));
	fsync(fd);
	close(fd);

	return 0;
}
// this always happens in uboot.txt
static int uboot_set_env_key(char *key, int value)
{
	int fd, ret;
	char old[1024] = { 0 };
	char new[1024] = { 0 };
	char *s, *d;
	char v[128];

	fd = open(uboot_txt, O_CREAT | O_RDWR | O_SYNC, 0600);
	if (!fd)
		return 0;

	ret = read(fd, old, sizeof(old));
	if (ret < 0) {
		pv_log(ERROR, "error reading uboot.txt");
		return -1;
	}

	int len = 0;
	d = new;
	s = old;
	for (uint16_t i = 0; i < ret; i++) {
		if (old[i] == '\0')
			continue;

		s = old+i;
		len = strlen(s);
		if (memcmp(s, key, strlen(key))) {
			memcpy(d, s, len+1);
			d += len+1;
		}
		i += len;
		len = 0;
	}

	sprintf(v, "%s=%d\0", key, value);
	memcpy(d, v, strlen(v)+1);
	d += strlen(v)+1;

	lseek(fd, 0, SEEK_SET);
	ret = write(fd, new, sizeof(new));
	fsync(fd);
	close(fd);

	return 0;
}

static int uboot_flush_env(void)
{
	int fd;
	erase_info_t ei;
	mtd_info_t mi;

	if (!strstr(pv_env, "mtd"))
		return 0;

	fd = open(pv_env, O_RDWR | O_SYNC);
	if (fd < 0)
		return 0;

	char buf[32];
	read(fd, buf, sizeof(buf));
	buf[31] = '\0';
	pv_log(DEBUG, "Buf-dirty: '%s'\n", buf);

	ioctl(fd, MEMGETINFO, &mi);
	ei.start = 0;
	ei.length = mi.erasesize;
	if (ioctl(fd, MEMUNLOCK, &ei))
		pv_log(DEBUG, "ioctl: MEMUNLOCK errno=%s\n", strerror(errno));
	if (ioctl(fd, MEMERASE, &ei))
		pv_log(DEBUG, "ioctl: MEMERASE errno=%s\n", strerror(errno));

	close(fd);

	fd = open(pv_env, O_RDONLY);
	lseek(fd, 0, SEEK_SET);
	memset(buf, 0, sizeof(buf));
	read(fd, buf, sizeof(buf));
	buf[31] = '\0';
	pv_log(DEBUG, "Buf-clean: '%s'\n", buf);

	close(fd);

	return 0;
}

static int uboot_install_kernel(char *path)
{
	return 0;
}

const struct bl_ops uboot_ops = {
	.init		= uboot_init,
	.get_env_key	= uboot_get_env_key,
	.set_env_key	= uboot_set_env_key,
	.unset_env_key	= uboot_unset_env_key,
	.flush_env	= uboot_flush_env,
	.install_kernel	= uboot_install_kernel,
};
