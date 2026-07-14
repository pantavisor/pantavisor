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

/*
 * EFI A/B bootloader ops for x86-64 EFI boot chain.
 *
 * Boot state flow:
 *   1. Stage1 (BOOTX64.EFI on ESP) reads/deletes one-shot PvTryBoot NV var,
 *      parses autoboot.txt, sets volatile PvBootPartition + PvBootTryBoot vars,
 *      chainloads stage2 from boot_a or boot_b partition.
 *   2. This module (efiab init) reads PvBootPartition and PvBootTryBoot from
 *      efivarfs, reads autoboot.txt from ESP via mcopy, reads pv_rev.txt from
 *      booted partition.
 *   3. On update: installs boot image to try partition, writes pv_rev.txt via
 *      mcopy, sets pv_try in efiab.txt, arms tryboot by writing PvTryBoot NV var.
 *   4. On commit: flips autoboot.txt (swap boot/try partitions), writes to ESP
 *      via mcopy.
 *
 * EFI variable GUID: a4e3e45c-b87f-4a56-9078-5f4e3a2d1c8b (from pvboot.h)
 * efivarfs path: /sys/firmware/efi/efivars/
 * Variable file format: 4-byte LE attributes prefix + data
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/fs.h>

#include "bootloader.h"
#include "paths.h"
#include "state.h"
#include "utils/fs.h"
#include "utils/pvsignals.h"
#include "utils/pvzlib.h"
#include "utils/str.h"
#include "utils/tsh.h"

#define MODULE_NAME "efiab"
#ifndef PVTEST
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#else
#define pv_log(level, msg, ...)                                                \
	printf("%s[%d]: ", MODULE_NAME, level);                                \
	printf(msg "\n", ##__VA_ARGS__)
#endif
#include "log.h"

#define EFIAB_VENDOR_GUID "a4e3e45c-b87f-4a56-9078-5f4e3a2d1c8b"
#define EFIVARFS_PATH "/sys/firmware/efi/efivars/"

/* EFI variable attributes */
#define EFI_VARIABLE_NON_VOLATILE 0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS 0x00000004

#define EFIAB_NV_ATTRS                                                         \
	(EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |         \
	 EFI_VARIABLE_RUNTIME_ACCESS)

#define UBOOT_ENV_SIZE 512

struct efiab_paths {
	int init;
	char *bootimg[3]; /* [0]=ESP, [1]=boot_a, [2]=boot_b */
	char *autoboot_tmp;
	char *pv_rev_tmp;
	char *efiab_txt;
};

static int autoboot_boot_partition = 0;
static int autoboot_try_partition = 0;
static uint32_t is_tryboot = 0;
static uint32_t partition = 0;
static char *boot_partition_rev = NULL;

static int _efiab_mark_tryboot(void);
static int _efiab_read_boot_partition_rev(void);

/*
 * Run an mtools command via tsh, wait for completion.
 * Returns 0 on success, -1 on failure.
 */
static int efiab_run_mtools(char *cmd)
{
	sigset_t oldset;
	pid_t p;
	int wstatus;

	pv_log(DEBUG, "mtools: %s", cmd);

	if (pvsignals_block_chld(&oldset)) {
		pv_log(ERROR, "Cannot block sigchld: %s", strerror(errno));
		return -1;
	}

	p = tsh_run(cmd, 0, NULL);
	if (p < 0) {
		pv_log(ERROR, "tsh_run '%s' failed: %s", cmd, strerror(errno));
		pvsignals_setmask(&oldset);
		return -1;
	}

	for (int i = 0; i < 10; i++) {
		pid_t wp = waitpid(p, &wstatus, WNOHANG);
		if (wp < 0) {
			pv_log(ERROR, "waitpid '%s' failed: %s", cmd,
			       strerror(errno));
			pvsignals_setmask(&oldset);
			return -1;
		}
		if (wp > 0) {
			pvsignals_setmask(&oldset);
			if (!WIFEXITED(wstatus)) {
				pv_log(ERROR, "'%s' killed by signal %d", cmd,
				       WTERMSIG(wstatus));
				return -1;
			}
			if (WEXITSTATUS(wstatus)) {
				pv_log(ERROR, "'%s' exited with status %d", cmd,
				       WEXITSTATUS(wstatus));
				return -1;
			}
			pv_log(DEBUG, "mtools ok: %s", cmd);
			return 0;
		}
		sleep(1);
	}
	pv_log(ERROR, "'%s' timed out after 10s", cmd);
	pvsignals_setmask(&oldset);
	return -1;
}

/* ------------------------------------------------------------------ */
/* EFI variable helpers (efivarfs)                                     */
/* ------------------------------------------------------------------ */

/*
 * Build the efivarfs file path for a given variable name.
 * Result: /sys/firmware/efi/efivars/{name}-{GUID}
 */
static void efiab_efivar_path(char *buf, size_t size, const char *name)
{
	snprintf(buf, size, EFIVARFS_PATH "%s-" EFIAB_VENDOR_GUID, name);
}

/*
 * Mount efivarfs if not already mounted.
 * Returns 0 on success, -1 on failure.
 */
static int efiab_mount_efivarfs(void)
{
	struct stat st;

	/* Check if efivarfs is already mounted */
	if (stat(EFIVARFS_PATH "PvBootPartition-" EFIAB_VENDOR_GUID, &st) ==
	    0) {
		pv_log(DEBUG, "efivarfs already accessible");
		return 0;
	}

	/* Try to mount */
	mkdir("/sys/firmware/efi/efivars", 0755);
	if (mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", 0,
		  NULL)) {
		if (errno == EBUSY) {
			pv_log(DEBUG, "efivarfs already mounted");
			return 0;
		}
		pv_log(ERROR, "Cannot mount efivarfs: %s", strerror(errno));
		return -1;
	}

	pv_log(DEBUG, "efivarfs mounted successfully");
	return 0;
}

/*
 * Read an EFI variable from efivarfs.
 * Skips the 4-byte attributes prefix, copies data to buf.
 * Returns number of data bytes read, or -1 on failure.
 */
static int efiab_read_efivar(const char *name, void *buf, size_t size)
{
	char path[PATH_MAX];
	uint32_t attrs;
	int fd;
	ssize_t r;

	efiab_efivar_path(path, sizeof(path), name);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pv_log(DEBUG, "Cannot open efivar %s: %s", path,
		       strerror(errno));
		return -1;
	}

	/* Read and skip 4-byte attributes prefix */
	r = read(fd, &attrs, sizeof(attrs));
	if (r != sizeof(attrs)) {
		pv_log(ERROR, "Cannot read efivar attrs %s: %s", name,
		       strerror(errno));
		close(fd);
		return -1;
	}

	r = read(fd, buf, size);
	close(fd);

	if (r < 0) {
		pv_log(ERROR, "Cannot read efivar data %s: %s", name,
		       strerror(errno));
		return -1;
	}

	return (int)r;
}

/*
 * Write an EFI variable to efivarfs.
 * efivarfs files have FS_IMMUTABLE_FL flag that must be cleared before writing.
 * File format: 4-byte LE attributes + data, written in a single write() call.
 * Returns 0 on success, -1 on failure.
 */
static int efiab_write_efivar(const char *name, uint32_t attrs,
			      const void *data, size_t size)
{
	char path[PATH_MAX];
	int fd;
	int flags;
	ssize_t w;
	size_t total = sizeof(attrs) + size;
	uint8_t *buf;

	efiab_efivar_path(path, sizeof(path), name);

	/* Try to clear immutable flag on existing file */
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == 0) {
			if (flags & FS_IMMUTABLE_FL) {
				flags &= ~FS_IMMUTABLE_FL;
				ioctl(fd, FS_IOC_SETFLAGS, &flags);
			}
		}
		close(fd);
	}

	/* Build single buffer: 4-byte LE attributes + data.
	 * efivarfs requires attributes and data in one write() call. */
	buf = malloc(total);
	if (!buf) {
		pv_log(ERROR, "Cannot allocate efivar write buffer for %s",
		       name);
		return -1;
	}
	memcpy(buf, &attrs, sizeof(attrs));
	memcpy(buf + sizeof(attrs), data, size);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pv_log(ERROR, "Cannot open efivar %s for write: %s", path,
		       strerror(errno));
		free(buf);
		return -1;
	}

	/* Single write: attrs + data */
	w = write(fd, buf, total);
	free(buf);
	if (w != (ssize_t)total) {
		pv_log(ERROR, "Cannot write efivar %s: %s (wrote %zd/%zu)",
		       name, strerror(errno), w, total);
		close(fd);
		return -1;
	}

	fsync(fd);
	close(fd);

	pv_log(DEBUG, "Wrote efivar %s (%zu bytes, attrs=0x%x)", name, size,
	       attrs);
	return 0;
}

/*
 * Read a UTF-16LE EFI variable, convert to ASCII string.
 * Returns malloc'd ASCII string, or NULL on failure.
 * Caller must free().
 */
static char *efiab_read_utf16_var(const char *name)
{
	uint8_t buf[256];
	int r;
	int len;
	char *str;

	r = efiab_read_efivar(name, buf, sizeof(buf));
	if (r <= 0)
		return NULL;

	/* UTF-16LE to ASCII: take every other byte */
	len = r / 2;
	str = calloc(len + 1, sizeof(char));
	if (!str)
		return NULL;

	for (int i = 0; i < len; i++) {
		uint16_t ch = buf[i * 2] | (buf[i * 2 + 1] << 8);
		if (ch == 0)
			break;
		str[i] = (char)(ch & 0x7f);
	}

	return str;
}

/*
 * Write a UINT8 EFI variable.
 * Returns 0 on success, -1 on failure.
 */
static int efiab_write_uint8_var(const char *name, uint32_t attrs, uint8_t val)
{
	return efiab_write_efivar(name, attrs, &val, sizeof(val));
}

/* ------------------------------------------------------------------ */
/* Boot state initialization                                           */
/* ------------------------------------------------------------------ */

static struct efiab_paths paths = {
	.init = 0,
	.bootimg = { "/dev/sda1", "/dev/sda2", "/dev/sda3" },
	.autoboot_tmp = "/tmp/autoboot.txt",
	.pv_rev_tmp = "/tmp/pv_rev.txt",
};

static int efiab_init_fw(struct efiab_paths *paths)
{
	int wstatus;
	size_t s, s1, r;
	sigset_t oldset;
	char autoboot_txt[513];
	char *cmdbuf = NULL;
	FILE *f;
	char *peek;
	char *end;
	char b;
	char *val;

	/* Mount efivarfs */
	if (efiab_mount_efivarfs()) {
		pv_log(ERROR, "Cannot mount efivarfs");
		return -1;
	}

	/* Read PvBootPartition — volatile var set by stage1 */
	val = efiab_read_utf16_var("PvBootPartition");
	if (val) {
		partition = (uint32_t)atoi(val);
		pv_log(DEBUG, "EFI PvBootPartition: %s (parsed: %u)", val,
		       partition);
		free(val);
	} else {
		pv_log(WARN,
		       "PvBootPartition not set (stage1 may not have run)");
	}

	/* Read PvBootTryBoot — volatile var set by stage1 */
	val = efiab_read_utf16_var("PvBootTryBoot");
	if (val) {
		is_tryboot = (uint32_t)atoi(val);
		pv_log(DEBUG, "EFI PvBootTryBoot: %s (parsed: %u)", val,
		       is_tryboot);
		free(val);
	} else {
		pv_log(DEBUG, "PvBootTryBoot not set (normal boot)");
		is_tryboot = 0;
	}

	/* Extract autoboot.txt from ESP (bootimg[0]) via mcopy */
	s = snprintf(cmdbuf, 0, "mcopy -n -i %s ::autoboot.txt %s",
		     paths->bootimg[0], paths->autoboot_tmp);

	cmdbuf = realloc(cmdbuf, (s + 1) * sizeof(char));
	if (!cmdbuf) {
		pv_log(ERROR, "Out of Memory (OOM) trying to allocate cmdbuf");
		return -1;
	}

	s1 = snprintf(cmdbuf, (s + 1), "mcopy -n -i %s ::autoboot.txt %s",
		      paths->bootimg[0], paths->autoboot_tmp);

	if (pvsignals_block_chld(&oldset)) {
		pv_log(ERROR, "Cannot block sigchld: %s", strerror(errno));
		free(cmdbuf);
		return -2;
	}

	if (s1 != s) {
		pv_log(ERROR,
		       "Error producing cmdbuf. size does not match expected size (%zd != %zd)",
		       s, s1);
		free(cmdbuf);
		return -2;
	}

	pid_t p = tsh_run(cmdbuf, 0, NULL);
	if (p < 0) {
		pv_log(ERROR, "tsh_run '%s' failed with error: %s\n", cmdbuf,
		       strerror(errno));
		pvsignals_setmask(&oldset);
		free(cmdbuf);
		return -1;
	}

	free(cmdbuf);

	for (int i = 0; i < 10; i++) {
		pid_t wp = waitpid(p, &wstatus, WNOHANG);
		if (wp < 0) {
			pv_log(ERROR,
			       "error running mcopy for autoboot.txt: %s",
			       strerror(errno));
			pvsignals_setmask(&oldset);
			return -1;
		}
		if (wp > 0) {
			if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
				pv_log(DEBUG,
				       "autoboot.txt retrieval from ESP failed with status %d",
				       WEXITSTATUS(wstatus));
				return -1;
			}
			break;
		}
		sleep(1);
	}
	pvsignals_setmask(&oldset);

	f = fopen(paths->autoboot_tmp, "r");
	if (!f) {
		pv_log(INFO, "Cannot open autoboot.txt: %s", strerror(errno));
		return -1;
	}

	r = fread(&autoboot_txt, 1, 512, f);

	if (r <= 0) {
		pv_log(ERROR, "Cannot read %s: %s", paths->autoboot_tmp,
		       strerror(errno));
		fclose(f);
		return -1;
	}
	fclose(f);

	/* set end marker if file does not have trailing 0 */
	autoboot_txt[r] = 0;

	/* parse autoboot.txt — same format as rpiab:
	 * [all]
	 * boot_partition=N
	 * [tryboot]
	 * boot_partition=M
	 */
	peek = strstr(autoboot_txt, "[all]");
	if (!peek) {
		pv_log(WARN,
		       "fail to find [all] in autoboot.txt; continue best guess");
		goto bestguess;
	}

	peek = strstr(peek, "boot_partition=");
	if (!peek) {
		pv_log(WARN,
		       "fail to find 'boot_partition=' for [all] in autoboot.txt; continue best guess");
		goto bestguess;
	}

	peek = peek + strlen("boot_partition=");
	if (peek > autoboot_txt + r) {
		pv_log(WARN,
		       "file too short to parse 'boot_partition='; continue best guess");
		goto bestguess;
	}
	end = peek;
	if (*end < '0' || *end > '9') {
		pv_log(WARN,
		       "boot_partition= for [all] has no number following it; continue best guess");
		goto bestguess;
	}
	while (*end >= '0' && *end <= '9') {
		end++;
	}

	b = *end;
	*end = 0;
	autoboot_boot_partition = atoi(peek);
	*end = b;

	pv_log(DEBUG, "Autoboot.txt: boot partition %d",
	       autoboot_boot_partition);

	peek = strstr(autoboot_txt, "[tryboot]");
	if (peek) {
		peek = strstr(peek, "boot_partition=");
		if (!peek)
			goto bestguess;

		peek = peek + strlen("boot_partition=");
		if (peek > autoboot_txt + r) {
			pv_log(WARN,
			       "file too short to parse 'boot_partition=' for [tryboot]; continue best guess");
			goto bestguess;
		}
		end = peek;
		if (*end < '0' || *end > '9') {
			pv_log(WARN,
			       "boot_partition= for [tryboot] has no number following it; continue best guess");
			goto bestguess;
		}
		while (*end >= '0' && *end <= '9') {
			end++;
		}
		b = *end;
		*end = 0;
		autoboot_try_partition = atoi(peek);
		*end = b;
		pv_log(DEBUG, "Autoboot.txt: try partition %d",
		       autoboot_try_partition);
		return 0;
	}
bestguess:
	if (!autoboot_boot_partition) {
		autoboot_boot_partition = 2;
		pv_log(WARN,
		       "error parsing autoboot.txt; setting boot partition to %d",
		       autoboot_boot_partition);
	}
	/* if we have no try_partition; guess one ... */
	if (autoboot_boot_partition == 3)
		autoboot_try_partition = 2;
	else
		autoboot_try_partition = 3;

	return 0;
}

/* ------------------------------------------------------------------ */
/* Init / Free                                                         */
/* ------------------------------------------------------------------ */

static void efiab_free(void)
{
}

static int efiab_init(void)
{
	char *b;
	const char *hay;

	pv_log(DEBUG, "efiab_init() enter");

	/* already init'd? */
	if (paths.init)
		return 0;

	b = malloc(PATH_MAX);

	if (getenv("PVTEST_PATH_BOOTIMG")) {
		paths.bootimg[0] = strdup(getenv("PVTEST_PATH_BOOTIMG"));
	}

	paths.bootimg[1] = strdup(paths.bootimg[0]);
	paths.bootimg[1][strlen(paths.bootimg[0]) - 1] = '2';
	paths.bootimg[2] = strdup(paths.bootimg[0]);
	paths.bootimg[2][strlen(paths.bootimg[0]) - 1] = '3';

	hay = getenv("PVTEST_PATH_TMP");
	if (hay) {
		size_t s = snprintf(NULL, 0, "%s/autoboot.txt", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/autoboot.txt", hay);
		paths.autoboot_tmp = strdup(b);
		s = snprintf(NULL, 0, "%s/pv_rev.txt", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/pv_rev.txt", hay);
		paths.pv_rev_tmp = strdup(b);
	} else {
		paths.autoboot_tmp = strdup(paths.autoboot_tmp);
		paths.pv_rev_tmp = strdup(paths.pv_rev_tmp);
	}

	hay = getenv("PVTEST_PATH_STORAGE_BOOT");
	if (hay) {
		size_t s = snprintf(NULL, 0, "%s/efiab.txt", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/efiab.txt", hay);
		paths.efiab_txt = strdup(b);
	} else {
		/* setup efiab.txt location */
#ifndef PVTEST
		pv_paths_storage_boot_file(b, PATH_MAX, EFIABTXT_FNAME);
		paths.efiab_txt = strdup(b);
#else
		printf("ERROR: must specify PVTEST_PATH_STORAGE_BOOT env in test\n");
		exit(1);
#endif
	}
	free(b);

	pv_log(DEBUG, "bootimg@%s", paths.bootimg[0]);
	pv_log(DEBUG, "bootimg2@%s", paths.bootimg[1]);
	pv_log(DEBUG, "bootimg3@%s", paths.bootimg[2]);
	pv_log(DEBUG, "efiab.txt@%s", paths.efiab_txt);
	pv_log(DEBUG, "autoboot.txt@%s", paths.autoboot_tmp);
	pv_log(DEBUG, "pv_rev.txt@%s", paths.pv_rev_tmp);

	if (efiab_init_fw(&paths)) {
		pv_log(ERROR, "efiab_init_fw() failed");
		return -1;
	}

	/*
	 * Derive the boot partition from autoboot.txt and tryboot state.
	 * PvBootPartition from stage1 is authoritative if available.
	 * If not set (e.g. no stage1), fall back to autoboot.txt + tryboot.
	 */
	if (partition == 0) {
		if (is_tryboot)
			partition = autoboot_try_partition;
		else
			partition = autoboot_boot_partition;
	}

	pv_log(DEBUG, "efiab_init: is_tryboot=%d partition=%d boot=%d try=%d",
	       is_tryboot, partition, autoboot_boot_partition,
	       autoboot_try_partition);

	/*
	 * Read pv_rev.txt from the boot partition we just booted from.
	 * This is used to validate that the partition matches our expected state.
	 * If the file doesn't exist (legacy image), boot_partition_rev remains NULL.
	 */
	if (_efiab_read_boot_partition_rev()) {
		pv_log(INFO,
		       "No pv_rev.txt on boot partition (legacy image or first boot)");
	}

	paths.init = 1;

	pv_log(DEBUG, "efiab_init() success");
	return 0;
}

/* ------------------------------------------------------------------ */
/* Env storage (efiab.txt) — same format as rpiab.txt                  */
/* ------------------------------------------------------------------ */

static char *efiab_get_env_key(char *key)
{
	int fd, n, len, ret;
	char *buf, *path, *value = NULL;

	path = paths.efiab_txt;
	len = UBOOT_ENV_SIZE;

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

static int efiab_set_env_key(char *key, char *value)
{
	int fd, ret = -1, res, len;
	char *s, *d, *path;
	char v[128] = { 0 };
	char old[UBOOT_ENV_SIZE] = { 0 };
	char new[UBOOT_ENV_SIZE] = { 0 };

	pv_log(DEBUG, "setting boot env key %s with value %s", key, value);

	path = paths.efiab_txt;
	len = UBOOT_ENV_SIZE;

	fd = open(path, O_RDWR | O_CREAT | O_SYNC, 0600);
	if (fd < 0) {
		pv_log(FATAL, "open bootloader file failed for %s: %s", path,
		       strerror(errno));
		goto out;
	}

	lseek(fd, 0, SEEK_SET);
	res = read(fd, old, len);

	d = (char *)new;
	for (uint16_t i = 0; i < res; i++) {
		if ((old[i] == '\xFF' && old[i + 1] == '\xFF') ||
		    (old[i] == '\0' && old[i + 1] == '\0'))
			break;

		if (old[i] == '\0')
			continue;

		/* skip garbage before (start with alpha) */
		if (old[i] < 'A' || old[i] > 'z')
			continue;

		s = (char *)old + i;
		len = strlen(s);
		/* remove garbage from end */
		for (int j = 0; j < len; j++) {
			/* anything below ! and above ~ is invalid and we cut it */
			if (old[j] <= '!' || old[j] >= '~')
				old[j] = 0;
		}
		/* get new len */
		len = strlen(s);
		if (memcmp(s, key, strlen(key))) {
			memcpy(d, s, len + 1);
			d += len + 1;
		}
		i += len;
	}

	SNPRINTF_WTRUNC(v, sizeof(v) - 1, "%s=%s", key, value);

	memcpy(d, v, strlen(v) + 1);

	lseek(fd, 0, SEEK_SET);
	write(fd, new, sizeof(new));
	fsync(fd);
	close(fd);
	pv_fs_path_sync(path);

	ret = 0;

	/*
	 * If we just set pv_try with a non-empty value, arm the tryboot flag.
	 * This is the "commit point" — after this, next reboot will boot
	 * from the try partition.
	 *
	 * Order of operations:
	 *   1. Boot image installed (install_update)
	 *   2. pv_rev.txt written (install_update)
	 *   3. pv_try stored in efiab.txt (this function, above)
	 *   4. PvTryBoot EFI var set (this function, below) <- commit point
	 */
	if (strcmp(key, "pv_try") == 0 && value && strlen(value) > 0) {
		pv_log(INFO, "pv_try set to '%s', arming tryboot via EFI var",
		       value);
		if (_efiab_mark_tryboot()) {
			pv_log(ERROR, "failed to arm PvTryBoot EFI variable");
			ret = -1;
		}
	}

out:
	return ret;
}

static int efiab_unset_env_key(char *key)
{
	return efiab_set_env_key(key, "\0");
}

static int efiab_flush_env(void)
{
	return 0;
}

/* ------------------------------------------------------------------ */
/* Tryboot: write PvTryBoot EFI variable                               */
/* ------------------------------------------------------------------ */

static int _efiab_mark_tryboot(void)
{
	uint8_t val = 0x01;
	int rv;

	pv_log(INFO, "Writing PvTryBoot EFI variable (NV, value=0x01)");

	rv = efiab_write_uint8_var("PvTryBoot", EFIAB_NV_ATTRS, val);
	if (rv) {
		pv_log(ERROR, "Failed to write PvTryBoot EFI variable");
		return -1;
	}

	/* Read back to verify */
	uint8_t readback = 0;
	int r = efiab_read_efivar("PvTryBoot", &readback, sizeof(readback));
	if (r == sizeof(readback) && readback == val) {
		pv_log(INFO, "PvTryBoot EFI variable verified: 0x%02x",
		       readback);
	} else {
		pv_log(WARN, "PvTryBoot readback mismatch (r=%d, val=0x%02x)",
		       r, readback);
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* Install update: write boot image + pv_rev.txt to try partition      */
/* ------------------------------------------------------------------ */

static int _efiab_install_trybootimg(char *rev)
{
	char imgpath[PATH_MAX];
	char trypath[PATH_MAX];
	struct stat st;
	int rv;
	off_t si;

#ifndef PVTEST
	pv_paths_storage_trail_pv_file(imgpath, PATH_MAX, rev, "efiboot.img");
	if (stat(imgpath, &st)) {
		pv_paths_storage_trail_pv_file(imgpath, PATH_MAX, rev,
					       "efiboot.img.gz");
	}
#else
	char *mock_bootimg = getenv("PVTEST_PATH_EFIBOOT");
	if (!mock_bootimg) {
		pv_log(ERROR,
		       "no PVTEST_PATH_EFIBOOT env set; point it to the boot.img to install");
		return -1;
	}
	memcpy(imgpath, mock_bootimg, strlen(mock_bootimg));
	imgpath[strlen(mock_bootimg)] = '\0';
#endif

	rv = stat(imgpath, &st);
	if (rv) {
		pv_log(ERROR, "efiboot.img io error %s: %s", imgpath,
		       strerror(errno));
		return -3;
	}

	sprintf(trypath, "%s", paths.bootimg[autoboot_try_partition - 1]);
	pv_log(INFO, "Installing efiab boot.img on try path partition %d: %s",
	       autoboot_try_partition, trypath);

	FILE *tryf = fopen(imgpath, "r");
	if (!tryf) {
		pv_log(ERROR, "Unable to open efiab image source path: %s - %s",
		       imgpath, strerror(errno));
		return -5;
	}
	FILE *tryp = fopen(trypath, "w");
	if (!tryp) {
		pv_log(ERROR,
		       "Unable to open efiab image try part path: %s - %s",
		       trypath, strerror(errno));
		fclose(tryf);
		return -5;
	}

	/* gzip install */
	if (!strcmp(imgpath + strlen(imgpath) - 3, ".gz")) {
		pv_log(DEBUG, "Installing bootimg %s with .gz compression %s",
		       imgpath, trypath);
		rv = pv_zlib_uncompress(tryf, tryp);
		if (rv) {
			pv_zlib_report_error(rv, tryf, tryp);
			pv_log(ERROR, "Unable install gzipped bootimg %s",
			       trypath);
			fclose(tryf);
			fclose(tryp);
			return -1;
		}
	} else {
		pv_log(DEBUG, "Installing bootimg with no compression %s -> %s",
		       imgpath, trypath);

		char *b = malloc(1024 * 1024);

		for (si = 0; si < st.st_size; si = si + (1024 * 1024)) {
			int rc, wc;
			rc = fread(b, 1, (1024 * 1024), tryf);
			if (rc < 0) {
				pv_log(ERROR,
				       "unable to finish write; too large boot.img for partition");
				goto close_err;
			}
			if (!rc)
				break;
			wc = fwrite(b, 1, rc, tryp);
			if (wc != rc) {
				pv_log(ERROR,
				       "unable to finish write; too large boot.img for partition");
				goto close_err;
			}
			continue;
		close_err:
			fclose(tryf);
			fclose(tryp);
			free(b);
			return -4;
		}
		free(b);
	}
	fflush(tryp);
	fsync(fileno(tryp));
	fclose(tryf);
	fclose(tryp);
	pv_log(INFO, "Installing efiab boot.img finished. %s", trypath);

	return 0;
}

/*
 * Read pv_rev.txt from the currently booted partition.
 * Returns 0 on success, -1 if pv_rev.txt not found.
 */
static int _efiab_read_boot_partition_rev(void)
{
	int wstatus;
	size_t s, r;
	sigset_t oldset;
	char *cmdbuf = NULL;
	char buf[256] = { 0 };
	FILE *f;
	pid_t p;
	int pv_rev_txt_found = 0;

	pv_log(DEBUG, "reading pv_rev.txt from boot partition %d", partition);

	s = snprintf(NULL, 0, "mcopy -n -i %s ::pv_rev.txt %s",
		     paths.bootimg[partition - 1], paths.pv_rev_tmp) +
	    1;

	cmdbuf = malloc(s);
	if (!cmdbuf) {
		pv_log(ERROR, "OOM allocating cmdbuf");
		return -1;
	}

	snprintf(cmdbuf, s, "mcopy -n -i %s ::pv_rev.txt %s",
		 paths.bootimg[partition - 1], paths.pv_rev_tmp);

	if (pvsignals_block_chld(&oldset)) {
		free(cmdbuf);
		return -1;
	}

	p = tsh_run(cmdbuf, 0, NULL);
	if (p < 0) {
		pv_log(DEBUG, "tsh_run '%s' failed: %s", cmdbuf,
		       strerror(errno));
		pvsignals_setmask(&oldset);
		free(cmdbuf);
		return -1;
	}
	free(cmdbuf);

	for (int i = 0; i < 10; i++) {
		pid_t wp = waitpid(p, &wstatus, WNOHANG);
		if (wp < 0) {
			pvsignals_setmask(&oldset);
			return -1;
		}
		if (wp > 0) {
			if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
				pv_log(DEBUG,
				       "pv_rev.txt not found on partition %d",
				       partition);
				pvsignals_setmask(&oldset);
				return -1;
			}
			pv_rev_txt_found = 1;
			break;
		}
		sleep(1);
	}
	pvsignals_setmask(&oldset);

	if (!pv_rev_txt_found)
		return -1;

	f = fopen(paths.pv_rev_tmp, "r");
	if (!f) {
		pv_log(WARN, "Cannot open extracted pv_rev.txt");
		return -1;
	}

	r = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);

	if (r <= 0) {
		pv_log(WARN, "Empty pv_rev.txt");
		return -1;
	}

	/* Trim whitespace/newline */
	buf[r] = '\0';
	char *endp = buf + strlen(buf) - 1;
	while (endp > buf && (*endp == '\n' || *endp == '\r' || *endp == ' '))
		*endp-- = '\0';

	if (boot_partition_rev)
		free(boot_partition_rev);
	boot_partition_rev = strdup(buf);
	pv_log(INFO, "Boot partition revision (from pv_rev.txt): %s",
	       boot_partition_rev);

	return 0;
}

/*
 * Write pv_rev.txt to the try boot partition.
 */
static int _efiab_write_pv_rev_txt(const char *rev)
{
	int wstatus;
	size_t s;
	sigset_t oldset;
	char *cmdbuf = NULL;
	FILE *f;
	pid_t p;

	pv_log(INFO, "writing pv_rev.txt to tryboot partition");

	f = fopen(paths.pv_rev_tmp, "w");
	if (!f) {
		pv_log(ERROR, "Cannot create pv_rev.txt temp file %s: %s",
		       paths.pv_rev_tmp, strerror(errno));
		return -1;
	}
	fprintf(f, "%s\n", rev);
	fclose(f);

	s = snprintf(NULL, 0, "mcopy -o -i %s %s ::pv_rev.txt",
		     paths.bootimg[autoboot_try_partition - 1],
		     paths.pv_rev_tmp) +
	    1;

	cmdbuf = malloc(s);
	if (!cmdbuf) {
		pv_log(ERROR, "OOM allocating cmdbuf");
		return -1;
	}

	snprintf(cmdbuf, s, "mcopy -o -i %s %s ::pv_rev.txt",
		 paths.bootimg[autoboot_try_partition - 1], paths.pv_rev_tmp);

	if (pvsignals_block_chld(&oldset)) {
		pv_log(ERROR, "Cannot block sigchld: %s", strerror(errno));
		free(cmdbuf);
		return -1;
	}

	pv_log(DEBUG, "copying pv_rev.txt to boot partition: %s", cmdbuf);

	p = tsh_run(cmdbuf, 0, NULL);
	if (p < 0) {
		pv_log(ERROR, "tsh_run '%s' failed: %s", cmdbuf,
		       strerror(errno));
		pvsignals_setmask(&oldset);
		free(cmdbuf);
		return -1;
	}
	free(cmdbuf);

	for (int i = 0; i < 10; i++) {
		pid_t wp = waitpid(p, &wstatus, WNOHANG);
		if (wp < 0) {
			pv_log(ERROR, "waitpid failed: %s", strerror(errno));
			pvsignals_setmask(&oldset);
			return -1;
		}
		if (wp > 0) {
			if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
				pv_log(ERROR,
				       "mcopy pv_rev.txt failed with status %d",
				       WEXITSTATUS(wstatus));
				pvsignals_setmask(&oldset);
				return -1;
			}
			break;
		}
		sleep(1);
	}
	pvsignals_setmask(&oldset);

	pv_log(INFO, "pv_rev.txt written successfully");
	return 0;
}

static int efiab_install_update(char *rev)
{
	if (_efiab_install_trybootimg(rev)) {
		pv_log(ERROR, "Error installing tryboot image.");
		return -1;
	}

	if (_efiab_write_pv_rev_txt(rev)) {
		pv_log(ERROR, "Error writing pv_rev.txt to tryboot partition");
		return -1;
	}

	/*
	 * NOTE: PvTryBoot is NOT set here.
	 * It will be set in efiab_set_env_key() when pv_try is written,
	 * ensuring the correct order:
	 *   1. Boot image installed
	 *   2. pv_rev.txt written
	 *   3. pv_try stored in efiab.txt
	 *   4. PvTryBoot EFI var set (commit point)
	 */

	pv_log(INFO, "Install update prepared (tryboot not yet armed).");
	return 0;
}

/* ------------------------------------------------------------------ */
/* Commit: flip autoboot.txt                                           */
/* ------------------------------------------------------------------ */

static int efiab_commit_update(void)
{
	size_t s;
	char *cmdbuf = NULL, *cmdbuf2 = NULL;
	sigset_t oldset;
	pid_t p;
	int wstatus;

	/* flip try and normal boot */
	char autoconf_buf[512] = { 0 };
	s = snprintf(autoconf_buf, 512,
		     "[all]\n"
		     "tryboot_a_b=1\n"
		     "boot_partition=%d\n"
		     "[tryboot]\n"
		     "boot_partition=%d\n",
		     autoboot_try_partition, autoboot_boot_partition);

	pv_log(DEBUG, "Creating autoboot.txt: %s", autoconf_buf);

	FILE *f = fopen(paths.autoboot_tmp, "w");
	if (!f) {
		pv_log(ERROR, "Cannot open autoboot.txt tmp for write %s: %s",
		       paths.autoboot_tmp, strerror(errno));
		return -1;
	}
	if (!fwrite(autoconf_buf, 1, s + 1, f)) {
		pv_log(ERROR, "Cannot write to autoboot.txt %s: %s",
		       paths.autoboot_tmp, strerror(errno));
		return -1;
	}
	fclose(f);

	/* copy the file to ESP */
	s = snprintf(cmdbuf, 0, "mcopy -o -i %s %s ::autoboot.txt",
		     paths.bootimg[0], paths.autoboot_tmp) +
	    1;
	cmdbuf2 = realloc(cmdbuf, s * sizeof(char));
	if (!cmdbuf2) {
		if (cmdbuf)
			free(cmdbuf);
		pv_log(ERROR, "Cannot allocate memory for cmdbuf");
		return -1;
	}
	cmdbuf = cmdbuf2;
	cmdbuf2 = NULL;

	snprintf(cmdbuf, s, "mcopy -o -i %s %s ::autoboot.txt",
		 paths.bootimg[0], paths.autoboot_tmp);

	if (pvsignals_block_chld(&oldset)) {
		pv_log(ERROR, "Cannot block sigchld: %s", strerror(errno));
		free(cmdbuf);
		return -2;
	}

	pv_log(DEBUG, "copying patched autoboot.txt to ESP: %s", cmdbuf);
	p = tsh_run(cmdbuf, 0, NULL);
	if (p < 0) {
		pv_log(ERROR, "tsh_run '%s' failed with error: %s\n", cmdbuf,
		       strerror(errno));
		pvsignals_setmask(&oldset);
		free(cmdbuf);
		return -1;
	}

	free(cmdbuf);
	for (int i = 0; i < 10; i++) {
		pid_t wp = waitpid(p, &wstatus, WNOHANG);
		if (wp < 0) {
			pv_log(INFO, "error running mcopy for autoboot.txt: %s",
			       strerror(errno));
			pvsignals_setmask(&oldset);
			return -1;
		}
		if (wp > 0) {
			if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
				pv_log(INFO,
				       "autoboot copy failed with status %d",
				       WEXITSTATUS(wstatus));
				pvsignals_setmask(&oldset);
				return -1;
			}

			break;
		}
		sleep(1);
	}

	pvsignals_setmask(&oldset);

	pv_log(INFO, "committing tryboot to autoboot.txt done.");

	return 0;
}

/* ------------------------------------------------------------------ */
/* Fail update                                                         */
/* ------------------------------------------------------------------ */

static int efiab_fail_update(void)
{
	return -1;
}

/* ------------------------------------------------------------------ */
/* Validate boot state                                                 */
/* ------------------------------------------------------------------ */

/*
 * Validate boot state and determine the current revision.
 *
 * Same logic as rpiab_validate_state — checks pv_rev.txt on boot partition
 * against stored pv_try/pv_done and tryboot flag.
 */
static int efiab_validate_state(const char *pv_try, const char *pv_done,
				char **pv_rev_out)
{
	const char *partition_rev = boot_partition_rev;
	int has_pv_try = (pv_try && strlen(pv_try) > 0);

	*pv_rev_out = NULL;

	/* No pv_rev.txt on boot partition — legacy/factory image */
	if (!partition_rev) {
		pv_log(INFO,
		       "No pv_rev.txt on boot partition, using default from env");
		return 0;
	}

	pv_log(DEBUG,
	       "Validating boot state: tryboot=%d, pv_try=%s, pv_done=%s, partition_rev=%s",
	       is_tryboot, pv_try ? pv_try : "(null)", pv_done, partition_rev);

	if (is_tryboot) {
		/* We're in a tryboot */
		if (!has_pv_try) {
			pv_log(ERROR, "Tryboot active but no pv_try stored");
			return -1;
		}

		if (strcmp(partition_rev, pv_try) != 0) {
			pv_log(ERROR,
			       "Partition mismatch: booted rev=%s but pv_try=%s",
			       partition_rev, pv_try);
			return -1;
		}

		pv_log(INFO, "Tryboot state valid: trying revision %s", pv_try);
		*pv_rev_out = strdup(pv_try);
		return 0;

	} else {
		/* Normal boot (not tryboot) */
		if (has_pv_try) {
			/*
			 * Normal boot but pv_try is set!
			 * This means early rollback — stage1 did not see
			 * PvTryBoot or tryboot failed before reaching
			 * pantavisor.
			 */
			pv_log(WARN,
			       "Early rollback detected: pv_try=%s was set but we booted normally",
			       pv_try);
			pv_log(WARN,
			       "Update to revision %s failed before reaching pantavisor",
			       pv_try);

			if (strcmp(partition_rev, pv_done) != 0) {
				pv_log(WARN,
				       "Partition rev=%s != pv_done=%s (expected during early rollback)",
				       partition_rev, pv_done);
			}

			pv_log(INFO,
			       "Early rollback: using committed revision %s",
			       pv_done);
			*pv_rev_out = strdup(pv_done);
			return 0;
		}

		if (strcmp(partition_rev, pv_done) != 0) {
			pv_log(ERROR,
			       "Partition mismatch: booted rev=%s but pv_rev=%s",
			       partition_rev, pv_done);
			return -1;
		}

		pv_log(INFO, "Normal boot state valid: revision %s", pv_done);
		*pv_rev_out = strdup(pv_done);
		return 0;
	}
}

/* ------------------------------------------------------------------ */
/* bl_ops export                                                       */
/* ------------------------------------------------------------------ */

const struct bl_ops efiab_ops = {
	.free = efiab_free,
	.init = efiab_init,
	.set_env_key = efiab_set_env_key,
	.unset_env_key = efiab_unset_env_key,
	.get_env_key = efiab_get_env_key,
	.flush_env = efiab_flush_env,
	.install_update = efiab_install_update,
	.commit_update = efiab_commit_update,
	.fail_update = efiab_fail_update,
	.validate_state = efiab_validate_state,
};
