/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>

#define MODULE_NAME			"bootloader"
#define sc_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "utils.h"

#include "bootloader.h"

static int bl_pvk_get_bank()
{
	int fd, bytes;
	int bank = -1;
	char *buf, *token;

	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -1;

	buf = calloc(1, sizeof(char) * (1024 + 1));
	bytes = read(fd, buf, sizeof(char)*1024);
	close(fd);

	token = strtok(buf, " ");
	while (token) {
		if (strncmp("sc_boot=", token, 8) == 0)
			bank = atoi(token + 8);
		token = strtok(NULL, " ");
	}
	free(buf);

	return bank;
}

static signed char bl_bank_from_rev(int rev)
{
	int fd;
	int b0_rev = -1, b1_rev = -1;

	fd = open("/dev/mtd3", O_RDONLY);
	lseek(fd, 0x14, SEEK_SET);
	read(fd, &b0_rev, sizeof(unsigned long));
	lseek(fd, 0x18, SEEK_SET);
	read(fd, &b1_rev, sizeof(unsigned long));

	sc_log(DEBUG, "b0_rev=%d b1_rev=%d\n", b0_rev, b1_rev);

	if (b0_rev == rev)
		return 0;
	else if (b1_rev == rev)
		return 1;

	return -1;
}

static int bl_is_pvk(struct systemc *sc)
{
	if (sc->config->bl_type == UBOOT_PVK)
		return 1;

	return 0;
}

static int uboot_set_try_rev(struct systemc *sc, int rev)
{
	int fd;
	char s[256];
	erase_info_t ei;
	unsigned long try = (unsigned long) rev;

	if (bl_is_pvk(sc)) {
		fd = open("/dev/mtd3", O_RDWR | O_SYNC);
		lseek(fd, 0x1c, SEEK_SET);
		write(fd, &try, sizeof(unsigned long));
		char bank = bl_bank_from_rev(sc->update->pending->rev);
		sc_log(DEBUG, "setting boot_bank=%d\n", bank);
		char header[4] = { 0x68, 0x00, 0x00, bank };
		lseek(fd, 0, SEEK_SET);
		write(fd, header, sizeof(header));
		fsync(fd);
		goto out;
	}

	fd = open("/dev/mtd2", O_RDWR | O_SYNC);
	if (!fd)
		return 0;

	ei.start = 0;
	ioctl(fd, MEMUNLOCK, &ei);
	ioctl(fd, MEMERASE, &ei);

	lseek(fd, 0, SEEK_SET);
	sprintf(s, "sc_try=%d\0", rev);
	write(fd, &s, strlen(s) + 1);

out:
	close(fd);

	return 1;
}

int sc_bl_set_try(struct systemc *sc, int rev)
{
	int fd;
	char s[256];

	if (strcmp(sc->config->storage.fstype, "ubifs") == 0)
		return uboot_set_try_rev(sc, rev);

	sprintf(s, "%s/boot/uboot.txt", sc->config->storage.mntpoint);
	fd = open(s, O_WRONLY | O_APPEND | O_SYNC);
	if (!fd)
		return 0;

	memset(s, 0, sizeof(s));
	sprintf(s, "sc_try=%d\0", rev);
	write(fd, s, strlen(s) + 1);
	sync();
	close(fd);

	return 1;
}

static int uboot_get_key_int(struct systemc *sc, char *key)
{
	int fd, n;
	int value = 0;
	char s[256];
	char *buf;
	struct stat st;

	if (strcmp(sc->config->storage.fstype, "ubifs") == 0)
		sprintf(s, "/dev/mtd2");
	else
		sprintf(s, "%s/boot/uboot.txt", sc->config->storage.mntpoint);
	stat(s, &st);

	fd = open(s, O_RDONLY);
	if (!fd)
		return -1;

	lseek(fd, 0, SEEK_SET);
	buf = calloc(1, st.st_size * sizeof(char));
	read(fd, buf, st.st_size);

	n = strlen(key);

	int k = 0;
	for (int i = 0; i < st.st_size; i++) {
		if (buf[i] != '\0')
			continue;

		if (strncmp(buf+k, key, n) == 0) {
			value = atoi(buf+k+n+1);
			break;
		}
		k = i+1;
	}
	free(buf);

	return value;
}

int sc_bl_get_current(struct systemc *sc)
{
	return uboot_get_key_int(sc, "sc_rev");
}

static int bl_pvk_get_try()
{
	int fd;
	unsigned long try = -1;

	// FIXME: should be configurable
	fd = open("/dev/mtd3", O_RDONLY);
	lseek(fd, 0x1c, SEEK_SET);
	read(fd, &try, sizeof(unsigned long));

	sc_log(DEBUG, "try_rev=%d\n", (int) try);

	return try;
}

int sc_bl_get_try(struct systemc *sc)
{
	if (bl_is_pvk(sc))
		return bl_pvk_get_try();

	return uboot_get_key_int(sc, "sc_try");
}

static void bl_pvk_set_current(int rev)
{
	int fd, bank;

	fd = open("/dev/mtd3", O_RDWR | O_SYNC);
	if (!fd) {
		sc_log(ERROR, "unable to open PVK header");
		return;
	}

	bank = bl_bank_from_rev(rev);

	// check if non-kernel update
	if (bank < 0) {
		bank = bl_pvk_get_bank();
		//write rev to bank
		lseek(fd, 0x14+(0x4*bank), SEEK_SET);
		write(fd, &rev, sizeof(unsigned long));
	}

	lseek(fd, 0, SEEK_SET);
	char buf[4] = { 0x68, 0x00, 0x00, bank };
	write(fd, buf, sizeof(buf));
}

void sc_bl_set_current(struct systemc *sc, int rev)
{
	int fd;
	char s[256];

	if (bl_is_pvk(sc)) {
		bl_pvk_set_current(rev);
		return;
	}

	sprintf(s, "%s/boot/uboot.txt", sc->config->storage.mntpoint);
	fd = open(s, O_RDWR | O_TRUNC | O_SYNC);
	memset(s, 0, sizeof(s));
	sprintf(s, "sc_rev=%d\0", rev);
	write(fd, s, strlen(s) + 1);
	sync();
	close(fd);
}

int sc_bl_install_kernel(struct systemc *sc, char *obj)
{
	int fd, obj_fd;
	int bytes, seek;
	unsigned long rev = (unsigned long) sc->update->pending->rev;
	char *buf;
	char bank = bl_bank_from_rev(sc->state->rev);

	sc_log(DEBUG, "current_bank=%d\n", bank);

	// first check if rev exists in a bank
	if (bl_bank_from_rev(rev) != -1)
		return 1;

	// install to opposite bank
	bank ^= 1;
	if (!bank)
		seek = 0x20;
	else
		seek = 0x380020;

	obj_fd = open(obj, O_RDONLY);
	if (!obj_fd) {
		sc_log(ERROR, "unable to open temp kernel file");
		return 0;
	}

	buf = calloc(1, 0x380000 * sizeof(char));

	// FIXME: bank size and mtd should be in config
	fd = open("/dev/mtd3", O_RDWR);

	// clear bank
	lseek(fd, seek, SEEK_SET);
	write(fd, buf, 0x380000);

	// read-in and write new kernel
	lseek(obj_fd, 0, SEEK_SET);
	bytes = read(obj_fd, buf, 0x380000);
	sc_log(DEBUG, "read %d bytes from %s\n", bytes, obj);
	lseek(fd, seek, SEEK_SET);
	bytes = write(fd, buf, bytes);
	sc_log(DEBUG, "wrote %d bytes to bank %d in /dev/mtd3\n", bytes, bank);

	// write revision of bank in h+0x14 or h+0x18
	lseek(fd, 0x14+(0x4*bank), SEEK_SET);
	write(fd, &rev, sizeof(unsigned long));

	close(obj_fd);
	close(fd);

	return 1;
}

int sc_bl_pvk_get_bank(struct systemc *sc)
{
	return bl_pvk_get_bank();
}

int sc_bl_pvk_get_rev(struct systemc *sc, int bank)
{
	int fd;
	unsigned long rev[2] = { 0 };

	fd = open("/dev/mtd3", O_RDONLY);
	lseek(fd, 0x14, SEEK_SET);
	read(fd, &rev[0], sizeof(unsigned long));
	lseek(fd, 0x18, SEEK_SET);
	read(fd, &rev[1], sizeof(unsigned long));

	sc_log(DEBUG, "rev[0]=%lu rev[1]=%lu\n", rev[0], rev[1]);

	return rev[bank];
}

int sc_bl_clear_update(struct systemc *sc)
{
	int fd;
	char buf[64] = { 0 };

	if (bl_is_pvk(sc)) {
		// FIXME: Should be config
		fd = open("/dev/mtd3", O_RDWR | O_SYNC);
		if (fd < 0) {
			sc_log(ERROR, "unable to read pvk data eader");
			return -1;
		}
		lseek(fd, 0, SEEK_SET);
		char bank = bl_bank_from_rev(sc->state->rev);
		char header[4] = { 0x68, 0x00, 0x00, bank };
		write(fd, header, sizeof(header));
		lseek(fd,  0x1c, SEEK_SET);
		memset(header, 0, 4);
		write(fd, header, sizeof(header));
	} else {
		// FIXME: Should be config
		fd = open("/dev/mtd2", O_RDWR | O_SYNC);
		if (fd < 0) {
			sc_log(ERROR, "unable to clear bootloader update buffer");
			return -1;
		}
		lseek(fd, 0, SEEK_SET);
		write(fd, buf, sizeof(buf));
	}

	sc_log(INFO, "cleared bootloader update buffer");
	close(fd);

	return 0;
}
