/*
 * Copyright (c) 2023-2024 Pantacor Ltd.
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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>
#include <linux/limits.h>

#include <byteswap.h>

#include "bootloader.h"
#include "paths.h"
#include "state.h"
#include "utils/fs.h"
#include "utils/pvsignals.h"
#include "utils/pvzlib.h"
#include "utils/str.h"
#include "utils/tsh.h"

#define MODULE_NAME "rpiab"
#ifndef PVTEST
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#else
#define pv_log(level, msg, ...)                                                \
	printf("%s[%d]: ", MODULE_NAME, level);                                \
	printf(msg "\n", ##__VA_ARGS__)
#endif
#include "log.h"

enum {
	RPI_FIRMWARE_SET_REBOOT_FLAGS = 0x00038064,
};

struct rpiab_paths {
	int init;
	char *bootimg[3];
	char *dtb_partition;
	char *dtb_tryboot;
	char *boot_mode;
	char *autoboot_tmp;
	char *cmdline_tmp;
	char *rpiab_txt;
};

static int autoboot_boot_partition = 0;
static int autoboot_try_partition = 0;
static uint32_t is_tryboot = 0;
static uint32_t boot_mode = 0;
static uint32_t partition = 0;
#define UBOOT_ENV_SIZE 512

static int mbox_property(int file_desc, void *buf);
static int mbox_open(void);
static void mbox_close(int file_desc);

static struct rpiab_paths paths = {
	.init = 0,
	.bootimg = { "/dev/mmcblk0p1", "/dev/mmcblk0p2", "/dev/mmcblk0p3" },
	.dtb_partition = "/proc/device-tree/chosen/bootloader/partition",
	.dtb_tryboot = "/proc/device-tree/chosen/bootloader/tryboot",
	.boot_mode = "/proc/device-tree/chosen/bootloader/boot-mode",
	.autoboot_tmp = "/tmp/autoboot.txt",
	.cmdline_tmp = "/tmp/cmdline.txt",
};

static int rpiab_init_fw(struct rpiab_paths *paths)
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

	// read bootloader chosen info from /proc/device-tree
	// note: numbers are big endian so you see bswap_32(...)
	f = fopen(paths->dtb_tryboot, "r");
	if (!f) {
		pv_log(ERROR, "Cannot open tryboot state on RPI: %s",
		       strerror(errno));
		return -1;
	}

	r = fread(&is_tryboot, 1, sizeof(is_tryboot), f);
	if (r < sizeof(is_tryboot)) {
		pv_log(ERROR, "Cannot read tryboot state on RPI from %s: %s",
		       paths->dtb_tryboot, strerror(errno));
		fclose(f);
		return -1;
	}
	fclose(f);
	is_tryboot = bswap_32(is_tryboot);
	pv_log(DEBUG, "RPI Tryboot state: %d", is_tryboot);

	f = fopen(paths->boot_mode, "r");
	if (!f) {
		pv_log(ERROR, "Cannot open boot-mode state on RPI: %s",
		       strerror(errno));
		return -1;
	}

	r = fread(&boot_mode, 1, sizeof(boot_mode), f);
	if (r < sizeof(boot_mode)) {
		pv_log(ERROR, "Cannot read boot_mode state on RPI from %s: %s",
		       paths->boot_mode, strerror(errno));
		fclose(f);
		return -1;
	}
	fclose(f);
	boot_mode = bswap_32(boot_mode);
	pv_log(DEBUG, "RPI Boot Mode: %d", boot_mode);

	// for now we only support boot mode sd card (1) and usb disk (4)
	if (boot_mode & 4) {
		paths->bootimg[0] = strdup("/dev/sda1");
		paths->bootimg[1] = strdup("/dev/sda2");
		paths->bootimg[2] = strdup("/dev/sda3");
	} else if (!(boot_mode & 1)) {
		pv_log(ERROR, "Boot mode not supported: %d", boot_mode);
		return -1;
	}

	f = fopen(paths->dtb_partition, "r");
	if (!f) {
		pv_log(ERROR, "Cannot open tryboot state on RPI: %s",
		       strerror(errno));
		return -1;
	}

	r = fread(&partition, 1, sizeof(partition), f);
	if (r < sizeof(partition)) {
		pv_log(ERROR, "Cannot read tryboot state on RPI: %s",
		       strerror(errno));
		fclose(f);
		return -1;
	}
	fclose(f);
	partition = bswap_32(partition);
	pv_log(DEBUG, "RPI Partition booted: %d", partition);

	// now we extract autoboot.txt from partition 0 with mcopy
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
		       "Error producing cmdbuf. size does not match expected size( %d != %d)",
		       s, s1);
		free(cmdbuf);
		return -2;
	}

	pid_t p = tsh_run(cmdbuf, 0, NULL);

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
				       "autoboot.txt extraxt from img failed with status %d",
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
		pv_log(INFO, "Cannot open tryboot state on RPI: %s",
		       strerror(errno));
		fclose(f);
		return -1;
	}

	r = fread(&autoboot_txt, 1, 512, f);

	if (r <= 0) {
		pv_log(ERROR, "Cannot read %s: %s; falling back to uboot",
		       paths->autoboot_tmp, strerror(errno));
		fclose(f);
		return -1;
	}
	fclose(f);

	// set end marker if file does not have trailing 0
	autoboot_txt[r] = 0;

	// parse autoboot.txt
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

	// if parsing fails we do a best guess to
	// boot something... rather than fail.
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
			       "boot_partition= for [all] has no number following it; continue best guess");
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
	// if we have no try_partition; guess one ...
	if (autoboot_boot_partition == 3)
		autoboot_try_partition = 2;
	else
		autoboot_try_partition = 3;

	return 0;
}

static int rpiab_init()
{
	char *b;
	const char *hay;

	// already init'd?
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
		size_t s = snprintf(b, 1, "%s/autoboot.txt", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/autoboot.txt", hay);
		paths.autoboot_tmp = strdup(b);
		s = snprintf(b, 1, "%s/cmdline.txt", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/cmdline.txt", hay);
		paths.cmdline_tmp = strdup(b);
	} else {
		paths.autoboot_tmp = strdup(paths.autoboot_tmp);
	}

	hay = getenv("PVTEST_PATH_DEVICE_TREE_BOOTLOADER");
	if (hay) {
		size_t s = snprintf(b, 1, "%s/partition", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/partition", hay);
		paths.dtb_partition = strdup(b);
		s = snprintf(b, 1, "%s/tryboot", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/tryboot", hay);
		paths.dtb_tryboot = strdup(b);
	} else {
		paths.dtb_partition = strdup(paths.dtb_partition);
		paths.dtb_tryboot = strdup(paths.dtb_tryboot);
	}

	hay = getenv("PVTEST_PATH_STORAGE_BOOT");
	if (hay) {
		size_t s = snprintf(b, 1, "%s/rpiab.txt", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/rpiab.txt", hay);
		paths.rpiab_txt = strdup(b);
	} else {
		// setup rpiab.txt location
#ifndef PVTEST
		pv_paths_storage_boot_file(b, PATH_MAX, RPIABTXT_FNAME);
		paths.rpiab_txt = strdup(b);
#else
		printf("ERROR: must specify PVTEST_PATH_STORAGE_BOOT env in test\n");
		exit(1);
#endif
	}
	free(b);

	pv_log(DEBUG, "bootimg@%s", paths.bootimg[0]);
	pv_log(DEBUG, "bootimg2@%s", paths.bootimg[1]);
	pv_log(DEBUG, "bootimg3@%s", paths.bootimg[2]);
	pv_log(DEBUG, "rpiab.txt@%s", paths.rpiab_txt);
	pv_log(DEBUG, "autoboot.txt@%s", paths.autoboot_tmp);
	pv_log(DEBUG, "dtb-partition@%s", paths.dtb_partition);
	pv_log(DEBUG, "dtb-tryboot@%s", paths.dtb_tryboot);
	pv_log(DEBUG, "dtb-bootmode@%s", paths.boot_mode);

	if (rpiab_init_fw(&paths)) {
		pv_log(ERROR, "rpiab_init_fw() failed");
		return -1;
	}

	paths.init = 1;

	return 0;
}

static char *rpiab_get_env_key(char *key)
{
	int fd, n, len, ret;
	char *buf, *path, *value = NULL;

	path = paths.rpiab_txt;
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

// this always happens in rpiab.txt
static int rpiab_set_env_key(char *key, char *value)
{
	int fd, ret = -1, res, len;
	char *s, *d, *path;
	char v[128] = { 0 };
	char old[UBOOT_ENV_SIZE] = { 0 };
	char new[UBOOT_ENV_SIZE] = { 0 };

	pv_log(DEBUG, "setting boot env key %s with value %s", key, value);

	path = paths.rpiab_txt;
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

		// skip garbage before (start with alpha)
		if (old[i] < 'A' || old[i] > 'z')
			continue;

		s = (char *)old + i;
		len = strlen(s);
		// remove garbage from end
		for (int j = 0; j < len; j++) {
			// anything below ! and above ~ is invalid and we cut it
			if (old[j] <= '!' || old[j] >= '~')
				old[j] = 0;
		}
		// get new len
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
out:
	return ret;
}

// this always happens in rpiab.txt
static int rpiab_unset_env_key(char *key)
{
	return rpiab_set_env_key(key, "\0");
}

static int rpiab_flush_env(void)
{
	return 0;
}

static int _rpiab_mark_tryboot()
{
	int rv = 0;
	unsigned args[256] = {};

	// here we mark tryboot through raspberry pi mailbox api
	// see vcmailbox(7)
	// 0 - size of request in bytes = 7 * sizeof(u32)
	// 1 - 0 for request code (here response success will be placed
	// 2 - tag: tag ID
	// 3 - tag: size of payload (1 word = 4 bytes)
	// 4 - tag: request ID (0 for bit 31 must be 0)
	// 5 - tag: the payload -> u32 0x1 (mark tryboot)
	// 6 - tag: end tag
	args[0] = 7 * sizeof(args[0]);
	args[1] = 0;
	args[2] = RPI_FIRMWARE_SET_REBOOT_FLAGS;
	args[3] = 4;
	args[4] = 0;
	args[5] = (uint32_t)0x1;
	args[6] = 0;

	int mbox = mbox_open();
	if (mbox < 0) {
		pv_log(ERROR, "Failed to open mbox for rpiab %s",
		       strerror(errno));
		return -5;
	}

	rv = mbox_property(mbox, args);
	if (rv < 0) {
		pv_log(ERROR, "Failed to write mbox property: %s",
		       strerror(errno));
		return -5;
	}
	mbox_close(mbox);

	return 0;
}

static int _rpiab_install_trybootimg(struct pv_state *pending)
{
	char imgpath[PATH_MAX];
	char trypath[PATH_MAX];
	struct stat st;
	int rv;
	off_t si;

	// if no bootimg, we can't install things.
	if (!pending->bsp.img.rpiab.bootimg) {
		return -1;
	}

#ifndef PVTEST
	pv_paths_storage_trail_pv_file(imgpath, PATH_MAX, pending->rev,
				       "rpiboot.img");
	if (stat(imgpath, &st)) {
		pv_paths_storage_trail_pv_file(imgpath, PATH_MAX, pending->rev,
					       "rpiboot.img.gz");
	}

#else
	char *mock_bootimg = getenv("PVTEST_PATH_RPIBOOT");
	if (!mock_bootimg) {
		pv_log(ERROR,
		       "no PVTEST_PATH_RPIBOOT env set; point it to the boot.img to install");
		return -1;
	}
	memcpy(imgpath, mock_bootimg, strlen(mock_bootimg));
#endif

	rv = stat(imgpath, &st);
	if (rv) {
		pv_log(ERROR, "rpiboot.img io error %s: %s", imgpath,
		       strerror(errno));
		return -3;
	}

	sprintf(trypath, "%s", paths.bootimg[autoboot_try_partition - 1]);
	pv_log(INFO, "Installing rpiab boot.img on try path partition %d: %s",
	       autoboot_try_partition, trypath);

	FILE *tryf = fopen(imgpath, "r");
	if (!tryf) {
		pv_log(ERROR, "Unable to open rpiab image souce path: %s - %s",
		       imgpath, strerror(errno));
		return -5;
	}
	FILE *tryp = fopen(trypath, "w");
	if (!tryp) {
		pv_log(ERROR,
		       "Unable to open rpiab image try part path: %s - %s",
		       trypath, strerror(errno));
		fclose(tryf);
		return -5;
	}

	// gzip install
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
			return -4;
		}
		free(b);
		b = NULL;
	}
	fflush(tryp);
	fsync(fileno(tryp));
	fclose(tryf);
	fclose(tryp);
	pv_log(INFO, "Installing rpiab boot.img finished. %s", trypath);

	return 0;
}

static char *trim_space(char *str)
{
	char *end;
	/* skip leading whitespace */
	while (isspace(*str)) {
		str = str + 1;
	}
	/* remove trailing whitespace */
	end = str + strlen(str) - 1;
	while (end > str && isspace(*end)) {
		end = end - 1;
	}
	/* write null character */
	*(end + 1) = '\0';
	return str;
}

static int _rpiab_setrev_trybootimg(struct pv_state *pending)
{
	int wstatus;
	size_t s;
	sigset_t oldset;
	char cmdline_buf[32257] = { 0 };
	char *cmdline_ptr;
	char *cmdbuf = NULL, *cmdbuf2 = NULL;
	;

	pv_log(INFO, "setrev on trybootimg");

	s = snprintf(cmdbuf, 0, "mcopy -n -i %s ::cmdline.txt %s",
		     paths.bootimg[autoboot_try_partition - 1],
		     paths.cmdline_tmp) +
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

	snprintf(cmdbuf, s, "mcopy -n -i %s ::cmdline.txt %s",
		 paths.bootimg[autoboot_try_partition - 1], paths.cmdline_tmp);

	if (pvsignals_block_chld(&oldset)) {
		pv_log(ERROR, "Cannot block sigchld: %s", strerror(errno));
		free(cmdbuf);
		return -2;
	}

	pv_log(DEBUG, "extracting cmdline.txt from boot.img");

	pid_t p = tsh_run(cmdbuf, 0, NULL);
	if (p < 0) {
		pv_log(ERROR, "tsh_run '%s' failed with error: %s\n", cmdbuf,
		       strerror(errno));
		return -1;
	}

	free(cmdbuf);
	for (int i = 0; i < 10; i++) {
		pid_t wp = waitpid(p, &wstatus, WNOHANG);
		if (wp < 0) {
			pv_log(INFO,
			       "error running mcopy for autoboot.txt extract: %s",
			       strerror(errno));
			pvsignals_setmask(&oldset);
			return -1;
		}
		if (wp > 0) {
			if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
				pv_log(DEBUG,
				       "cmdline.txt extract from image failed with status %d",
				       WEXITSTATUS(wstatus));
				return -1;
			}
			break;
		}
		sleep(1);
	}

	cmdbuf = NULL;
	pvsignals_setmask(&oldset);

	pv_log(DEBUG, "reading cmdline.txt");
	FILE *f = fopen(paths.cmdline_tmp, "r");

	if (!f) {
		pv_log(ERROR, "Cannot open cmdline.txt %s: %s",
		       paths.cmdline_tmp, strerror(errno));
		return -12;
	}

	s = fread(cmdline_buf, 1, sizeof(cmdline_buf), f);
	fclose(f);

	if (!s) {
		pv_log(ERROR, "Cannot proceed with empty cmdline.txt");
		return -1;
	}

	cmdline_buf[sizeof(cmdline_buf) - 1] = 0;

	// support 128 chars long pv_rev=... string
	if (s > sizeof(cmdline_buf) - 129) {
		pv_log(ERROR,
		       "cmdline.txt too large. we only support up to %llu bytes",
		       sizeof(cmdline_buf) - 129);
		return -1;
	}
	cmdline_buf[s + 1] = 0;

	cmdline_ptr = trim_space(cmdline_buf);
	char *peek = strstr(cmdline_ptr, "pv_rev=");

	// cut off any traling pv_rev= stanza
	if (peek)
		*peek = 0;

	// append pv_rev=REVISION to finish the patch...
	s = snprintf(cmdline_ptr + strlen(cmdline_ptr), 0, " pv_rev=%s",
		     pending->rev);

	snprintf(cmdline_ptr + strlen(cmdline_ptr), s + 1, " pv_rev=%s",
		 pending->rev);

	f = fopen(paths.cmdline_tmp, "w");
	fwrite(cmdline_ptr, 1, strlen(cmdline_ptr), f);
	fclose(f);

	pv_log(DEBUG, "synching cmdline.txt: %s", cmdline_ptr);

	//
	// now we copy the file to try_boot partition
	//
	s = snprintf(cmdbuf, 0, "mcopy -o -i %s %s ::cmdline.txt",
		     paths.bootimg[autoboot_try_partition - 1],
		     paths.cmdline_tmp) +
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

	snprintf(cmdbuf, s, "mcopy -o -i %s %s ::cmdline.txt",
		 paths.bootimg[autoboot_try_partition - 1], paths.cmdline_tmp);

	if (pvsignals_block_chld(&oldset)) {
		pv_log(ERROR, "Cannot block sigchld: %s", strerror(errno));
		free(cmdbuf);
		return -2;
	}

	pv_log(DEBUG, "copying patched cmdline.txt to bootimg: %s", cmdbuf);
	p = tsh_run(cmdbuf, 0, NULL);

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
				pv_log(DEBUG,
				       "cmdline.txt copy to image failed with status %d",
				       WEXITSTATUS(wstatus));
				return -1;
			}
			break;
		}
		sleep(1);
	}

	pvsignals_setmask(&oldset);

	pv_log(INFO, "setrev on trybootimg done.");
	return 0;
}

static int rpiab_install_update(struct pv_update *update)
{
	struct pv_state *pending = update->pending;

	if (_rpiab_install_trybootimg(pending)) {
		pv_log(ERROR, "Error installing tryboot image.");
		return -1;
	}

	if (_rpiab_setrev_trybootimg(pending)) {
		pv_log(ERROR, "Error setting pv_rev in tryboot");
		return -1;
	}

	if (_rpiab_mark_tryboot()) {
		pv_log(ERROR, "Error marking tryboot");
		return -1;
	}

	pv_log(INFO, "Install update finished.");
	return 0;
}

static int rpiab_commit_update()
{
	size_t s;
	char *cmdbuf = NULL, *cmdbuf2 = NULL;
	sigset_t oldset;
	pid_t p;
	int wstatus;

	// here we flip try and normal boot
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

	//
	// now we copy the file to autoboot partition
	//
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

	pv_log(DEBUG, "copying patched autoboot.txt to bootimg: %s", cmdbuf);
	p = tsh_run(cmdbuf, 0, NULL);

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
				pv_log(DEBUG,
				       "autoboot copy failed with status %d",
				       WEXITSTATUS(wstatus));
				return -1;
			}

			break;
		}
		sleep(1);
	}

	pvsignals_setmask(&oldset);

	return -1;
}

static int rpiab_fail_update(struct pv_update *update)
{
	return -1;
}

const struct bl_ops rpiab_ops = {
	.init = rpiab_init,
	.set_env_key = rpiab_set_env_key,
	.unset_env_key = rpiab_unset_env_key,
	.get_env_key = rpiab_get_env_key,
	.flush_env = rpiab_flush_env,
	.install_update = rpiab_install_update,
	.commit_update = rpiab_commit_update,
	.fail_update = rpiab_fail_update,
};

/*
Copyright (c) 2015 Raspberry Pi (Trading) Ltd.
All rights reserved.
Copyright (c) 2024 Pantacor Limited
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define DEVICE_FILE_NAME "/dev/vcio"
#define MAJOR_NUM 100
#define IOCTL_MBOX_PROPERTY _IOWR(MAJOR_NUM, 0, char *)

/*
 * use ioctl to send mbox property message
 */

static int mbox_property(int file_desc, void *buf)
{
	int ret_val = ioctl(file_desc, IOCTL_MBOX_PROPERTY, buf);

	if (ret_val < 0) {
		pv_log(ERROR, "ioctl_set_msg IOCTL_MBOX_PROPERTY failed:%d\n",
		       ret_val);
	}
	return ret_val;
}

static int mbox_open()
{
	int file_desc;

	// open a char device file used for communicating with kernel mbox driver
	file_desc = open(DEVICE_FILE_NAME, 0);
	if (file_desc < 0) {
		printf("Can't open device file: %s\n", DEVICE_FILE_NAME);
		printf("Try creating a device file with: sudo mknod %s c %d 0\n",
		       DEVICE_FILE_NAME, MAJOR_NUM);
		return -1;
	}
	return file_desc;
}

static void mbox_close(int file_desc)
{
	close(file_desc);
}
