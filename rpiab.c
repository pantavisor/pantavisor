/*
 * Copyright (c) 2023-2025 Pantacor Ltd.
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
#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <mtd/mtd-user.h>
#include <linux/limits.h>
#include <linux/watchdog.h>

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
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#else
#define pv_log(level, msg, ...)                                                \
	printf("%s[%d]: ", MODULE_NAME, level);                                \
	printf(msg "\n", ##__VA_ARGS__)
#endif
#include "log.h"

enum {
	RPI_FIRMWARE_GET_GENCMD_RESULT = 0x00030080,
	RPI_FIRMWARE_GET_REBOOT_FLAGS = 0x00030064,
	RPI_FIRMWARE_SET_REBOOT_FLAGS = 0x00038064,
};

/*
 * Minimum EEPROM bootloader version (Unix timestamp) for tryboot_a_b.
 * Pi 4: tryboot_a_b mode (correct partition numbering for A/B schemes)
 *       was added in pieeprom-2022-11-25, promoted to DEFAULT 2022-12-01.
 *       Earlier EEPROMs (e.g. 2022-08-02) report flipped partition numbers.
 * Pi 5: all EEPROM versions support tryboot_a_b.
 */
#define RPIAB_MIN_TRYBOOT_VERSION 1669334400

struct rpiab_paths {
	int init;
	char *bootimg[3];
	char *dtb_partition;
	char *dtb_tryboot;
	char *boot_mode;
	char *autoboot_tmp;
	char *pv_rev_tmp;
	char *rpiab_txt;
};

static int autoboot_boot_partition = 0;
static int autoboot_try_partition = 0;
static uint32_t is_tryboot = 0;
static uint32_t boot_mode = 0;
static uint32_t partition = 0;
static char *boot_partition_rev = NULL;
#define UBOOT_ENV_SIZE 512

static int mbox_property(int file_desc, void *buf);
static int mbox_open(void);
static void mbox_close(int file_desc);
static int _rpiab_mark_tryboot(void);
static int _rpiab_read_boot_partition_rev(void);

/*
 * Get the EEPROM bootloader version via mbox GET_GENCMD_RESULT (0x00030080).
 *
 * This sends "bootloader_version" to the VC firmware through /dev/vcio,
 * the same interface that vcgencmd uses. The response contains a
 * "timestamp XXXXXXXXXX" line with the EEPROM bootloader build date.
 *
 * Note: The DTB /proc/device-tree/chosen/bootloader/version shows the
 * VC firmware (start4.elf) version, NOT the EEPROM version.
 *
 * Returns the Unix timestamp, or 0 on failure.
 */
#define GENCMD_MAX_STRING 1024
static uint32_t rpiab_get_eeprom_version(void)
{
	/*
	 * Buffer layout (same as vcgencmd from raspberrypi/utils):
	 *   [0]   = total size in bytes
	 *   [1]   = request code (0)
	 *   [2]   = tag: GET_GENCMD_RESULT (0x00030080)
	 *   [3]   = tag: buffer length (1024)
	 *   [4]   = tag: request/response indicator
	 *   [5]   = tag: error code (0 in request)
	 *   [6..] = command string / response string (1024 bytes = 256 words)
	 *   [262] = end tag (0)
	 */
	unsigned p[263] = {};
	const char *cmd = "bootloader_version";
	int i = 0;
	uint32_t version = 0;
	char *ts;

	int mbox = mbox_open();
	if (mbox < 0)
		return 0;

	i = 0;
	p[i++] = 0; /* size - filled below */
	p[i++] = 0; /* request */
	p[i++] = RPI_FIRMWARE_GET_GENCMD_RESULT;
	p[i++] = GENCMD_MAX_STRING; /* buffer length */
	p[i++] = 0; /* request */
	p[i++] = 0; /* error code */
	memcpy(p + i, cmd, strlen(cmd) + 1);
	i += GENCMD_MAX_STRING >> 2;
	p[i++] = 0; /* end tag */
	p[0] = i * sizeof(unsigned);

	if (mbox_property(mbox, p) < 0) {
		mbox_close(mbox);
		return 0;
	}
	mbox_close(mbox);

	if (p[5] != 0) {
		pv_log(WARN, "bootloader_version command returned error %d",
		       p[5]);
		return 0;
	}

	/* Response string is at p[6], parse "timestamp XXXXXXXXXX" */
	ts = strstr((const char *)(p + 6), "timestamp ");
	if (ts) {
		version = (uint32_t)strtoul(ts + 10, NULL, 10);
	}

	return version;
}

static uint32_t bootloader_version = 0;

/*
 * Stage EEPROM recovery files on the bootsel partition.
 *
 * The bootsel partition carries platform-specific EEPROM firmware:
 *   recovery-2711.bin / pieeprom-2711.bin (Pi 4)
 *   recovery-2712.bin / pieeprom-2712.bin (Pi 5)
 *
 * This function detects the SoC, mounts bootsel, renames the correct
 * files to recovery.bin / pieeprom.upd, and reboots. The EEPROM
 * bootloader picks up recovery.bin at the very start of boot (before
 * config.txt), flashes the new EEPROM, and reboots again.
 */
/*
 * Run an mtools command via tsh, wait for completion.
 * Returns 0 on success, -1 on failure.
 */
static int rpiab_run_mtools(char *cmd)
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
		pv_log(ERROR, "tsh_run '%s' failed: %s", cmd,
		       strerror(errno));
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
				pv_log(ERROR, "'%s' killed by signal %d",
				       cmd, WTERMSIG(wstatus));
				return -1;
			}
			if (WEXITSTATUS(wstatus)) {
				pv_log(ERROR, "'%s' exited with status %d",
				       cmd, WEXITSTATUS(wstatus));
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

static void rpiab_stage_eeprom_update(void)
{
	const char *soc = NULL;
	const char *bootsel_dev;
	char compat[256] = {};
	char cmd[512];
	FILE *f;
	size_t r;

	/* Detect SoC from device tree compatible string.
	 * The compatible property is null-separated (e.g.
	 * "raspberrypi,4-model-b\0brcm,bcm2711\0"), so replace
	 * nulls with spaces to make it searchable with strstr. */
	f = fopen("/proc/device-tree/compatible", "r");
	if (!f) {
		pv_log(ERROR, "Cannot detect SoC type: %s", strerror(errno));
		return;
	}
	r = fread(compat, 1, sizeof(compat) - 1, f);
	fclose(f);
	for (size_t i = 0; i < r; i++) {
		if (compat[i] == '\0')
			compat[i] = ' ';
	}
	compat[r] = '\0';

	if (strstr(compat, "bcm2712"))
		soc = "2712";
	else if (strstr(compat, "bcm2711"))
		soc = "2711";
	else {
		pv_log(WARN, "Unknown SoC, cannot select EEPROM firmware");
		fprintf(stderr,
			"rpiab: unknown SoC - no EEPROM firmware available, cannot auto-update\n");
		return;
	}

	bootsel_dev = (boot_mode & 4) ? "/dev/sda1" : "/dev/mmcblk0p1";

	pv_log(INFO, "Staging EEPROM update for BCM%s from %s", soc,
	       bootsel_dev);
	fprintf(stderr, "rpiab: staging EEPROM update for BCM%s\n", soc);

	/* Check source file exists on bootsel via mdir */
	snprintf(cmd, sizeof(cmd),
		 "mdir -i %s ::pieeprom-%s.bin", bootsel_dev, soc);
	if (rpiab_run_mtools(cmd)) {
		pv_log(WARN, "No EEPROM firmware on bootsel for BCM%s", soc);
		fprintf(stderr, "rpiab: no pieeprom-%s.bin on bootsel\n", soc);
		return;
	}

	/* Clean up leftovers from a previous failed flash attempt */
	snprintf(cmd, sizeof(cmd),
		 "mdel -i %s ::RECOVERY.000", bootsel_dev);
	rpiab_run_mtools(cmd); /* ignore error — file may not exist */
	snprintf(cmd, sizeof(cmd),
		 "mdel -i %s ::pieeprom.upd", bootsel_dev);
	rpiab_run_mtools(cmd);
	snprintf(cmd, sizeof(cmd),
		 "mdel -i %s ::pieeprom.sig", bootsel_dev);
	rpiab_run_mtools(cmd);

	/* Copy pieeprom first — recovery.bin is the trigger that starts
	 * the flash process, so it must be created last.  We extract to
	 * /tmp then write back with the target name so the originals
	 * survive a failed flash and we can retry on next boot.
	 * (mcopy cannot copy within the same FAT image.) */
	snprintf(cmd, sizeof(cmd),
		 "mcopy -i %s ::pieeprom-%s.bin /tmp/pieeprom.upd",
		 bootsel_dev, soc);
	if (rpiab_run_mtools(cmd)) {
		pv_log(ERROR, "Failed to extract pieeprom-%s.bin from bootsel",
		       soc);
		return;
	}
	snprintf(cmd, sizeof(cmd),
		 "mcopy -o -i %s /tmp/pieeprom.upd ::pieeprom.upd",
		 bootsel_dev);
	if (rpiab_run_mtools(cmd)) {
		pv_log(ERROR, "Failed to write pieeprom.upd to bootsel");
		return;
	}
	/* Copy the signature file — recovery.bin verifies pieeprom.upd
	 * against pieeprom.sig (SHA256 hash) before flashing. */
	snprintf(cmd, sizeof(cmd),
		 "mcopy -i %s ::pieeprom-%s.sig /tmp/pieeprom.sig",
		 bootsel_dev, soc);
	if (rpiab_run_mtools(cmd)) {
		pv_log(ERROR, "Failed to extract pieeprom-%s.sig from bootsel",
		       soc);
		return;
	}
	snprintf(cmd, sizeof(cmd),
		 "mcopy -o -i %s /tmp/pieeprom.sig ::pieeprom.sig",
		 bootsel_dev);
	if (rpiab_run_mtools(cmd)) {
		pv_log(ERROR, "Failed to write pieeprom.sig to bootsel");
		return;
	}
	pv_log(INFO, "Staged pieeprom-%s.bin -> pieeprom.upd + pieeprom.sig",
	       soc);

	/* Now copy recovery — this arms the EEPROM flash */
	snprintf(cmd, sizeof(cmd),
		 "mcopy -i %s ::recovery-%s.bin /tmp/recovery.bin",
		 bootsel_dev, soc);
	if (rpiab_run_mtools(cmd)) {
		pv_log(ERROR, "Failed to extract recovery-%s.bin from bootsel",
		       soc);
		return;
	}
	snprintf(cmd, sizeof(cmd),
		 "mcopy -o -i %s /tmp/recovery.bin ::recovery.bin",
		 bootsel_dev);
	if (rpiab_run_mtools(cmd)) {
		pv_log(ERROR, "Failed to write recovery.bin to bootsel");
		return;
	}
	pv_log(INFO, "Staged recovery-%s.bin -> recovery.bin (armed)", soc);

	sync();

	/* Arm hardware watchdog as safety net in case reboot() hangs.
	 * We open /dev/watchdog directly rather than using pv_wdt_start()
	 * because the pantavisor config system isn't initialized yet. */
	{
		int wdt_fd = open("/dev/watchdog", O_RDWR | O_CLOEXEC);
		if (wdt_fd >= 0) {
			int timeout = 15;
			ioctl(wdt_fd, WDIOC_SETTIMEOUT, &timeout);
			pv_log(INFO,
			       "Watchdog armed (%ds) as reboot safety net",
			       timeout);
			/* Do NOT close — keeps watchdog ticking */
		} else {
			pv_log(WARN,
			       "Cannot arm watchdog for reboot safety: %s",
			       strerror(errno));
		}
	}

	fprintf(stderr,
		"rpiab: EEPROM update staged, rebooting for flash...\n");
	sleep(2);
	reboot(RB_AUTOBOOT);

	/* Should not reach here — watchdog will reset if reboot() hangs */
	while (1)
		sleep(1);
}

static struct rpiab_paths paths = {
	.init = 0,
	.bootimg = { "/dev/mmcblk0p1", "/dev/mmcblk0p2", "/dev/mmcblk0p3" },
	.dtb_partition = "/proc/device-tree/chosen/bootloader/partition",
	.dtb_tryboot = "/proc/device-tree/chosen/bootloader/tryboot",
	.boot_mode = "/proc/device-tree/chosen/bootloader/boot-mode",
	.autoboot_tmp = "/tmp/autoboot.txt",
	.pv_rev_tmp = "/tmp/pv_rev.txt",
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
	pv_log(DEBUG, "RPI Tryboot state: %ju", is_tryboot);

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
	pv_log(DEBUG, "RPI Boot Mode: %ju", boot_mode);

	/* Check EEPROM bootloader version via mbox GET_GENCMD_RESULT */
	bootloader_version = rpiab_get_eeprom_version();
	if (bootloader_version) {
		pv_log(INFO, "EEPROM bootloader version: %u", bootloader_version);
		fprintf(stderr, "rpiab: eeprom version=%u\n",
			bootloader_version);
		if (bootloader_version < RPIAB_MIN_TRYBOOT_VERSION) {
			pv_log(ERROR,
			       "EEPROM bootloader version %u is too old for tryboot "
			       "(need >= %u / 2022-01-25)",
			       bootloader_version, RPIAB_MIN_TRYBOOT_VERSION);
			fprintf(stderr,
				"rpiab: ERROR: EEPROM too old for tryboot! version=%u need>=%u\n",
				bootloader_version, RPIAB_MIN_TRYBOOT_VERSION);
			/* Try to stage auto-update from bootsel partition.
			 * If successful, this reboots and never returns.
			 * If firmware files are not available, fall through
			 * to return -1 (pantavisor exits, kernel panics,
			 * reboots after panic=5 seconds). */
			rpiab_stage_eeprom_update();
			return -1;
		}
	} else {
		pv_log(WARN, "Could not query EEPROM version via mbox");
	}

	// for now we only support boot mode sd card (1) and usb disk (4)
	if (boot_mode & 4) {
		paths->bootimg[0] = strdup("/dev/sda1");
		paths->bootimg[1] = strdup("/dev/sda2");
		paths->bootimg[2] = strdup("/dev/sda3");
	} else if (!(boot_mode & 1)) {
		pv_log(ERROR, "Boot mode not supported: %ju", boot_mode);
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
	pv_log(DEBUG, "RPI Partition booted: %ju", partition);

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
				       "autoboot.txt retrieval from bootimage failed with status %d",
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

static void rpiab_free()
{
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

	hay = getenv("PVTEST_PATH_DEVICE_TREE_BOOTLOADER");
	if (hay) {
		size_t s = snprintf(NULL, 0, "%s/partition", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/partition", hay);
		paths.dtb_partition = strdup(b);
		s = snprintf(NULL, 0, "%s/tryboot", hay) + 1;
		b = realloc(b, s);
		snprintf(b, s, "%s/tryboot", hay);
		paths.dtb_tryboot = strdup(b);
	} else {
		paths.dtb_partition = strdup(paths.dtb_partition);
		paths.dtb_tryboot = strdup(paths.dtb_tryboot);
	}

	hay = getenv("PVTEST_PATH_STORAGE_BOOT");
	if (hay) {
		size_t s = snprintf(NULL, 0, "%s/rpiab.txt", hay) + 1;
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
	pv_log(DEBUG, "pv_rev.txt@%s", paths.pv_rev_tmp);
	pv_log(DEBUG, "dtb-partition@%s", paths.dtb_partition);
	pv_log(DEBUG, "dtb-tryboot@%s", paths.dtb_tryboot);
	pv_log(DEBUG, "dtb-bootmode@%s", paths.boot_mode);

	if (rpiab_init_fw(&paths)) {
		pv_log(ERROR, "rpiab_init_fw() failed");
		return -1;
	}

	/*
	 * Derive the boot partition from autoboot.txt and tryboot state.
	 * The DTB partition field is unreliable (e.g. Pi 5 reports 0).
	 */
	if (is_tryboot)
		partition = autoboot_try_partition;
	else
		partition = autoboot_boot_partition;

	pv_log(DEBUG, "rpiab_init: is_tryboot=%d partition=%d boot=%d try=%d",
	       is_tryboot, partition, autoboot_boot_partition, autoboot_try_partition);
	fprintf(stderr, "rpiab: is_tryboot=%d partition=%d boot=%d try=%d\n",
		is_tryboot, partition, autoboot_boot_partition, autoboot_try_partition);

	/*
	 * Read pv_rev.txt from the boot partition we just booted from.
	 * This is used to validate that the partition matches our expected state.
	 * If the file doesn't exist (legacy image), boot_partition_rev remains NULL.
	 */
	if (_rpiab_read_boot_partition_rev()) {
		pv_log(INFO, "No pv_rev.txt on boot partition (legacy image or first boot)");
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

	/*
	 * If we just set pv_try with a non-empty value, arm the tryboot flag.
	 * This is the "commit point" - after this, next reboot will boot
	 * from the try partition.
	 *
	 * Order of operations:
	 *   1. Boot image installed (install_update)
	 *   2. pv_rev.txt written (install_update)
	 *   3. pv_try stored in rpiab.txt (this function, above)
	 *   4. Tryboot flag set (this function, below) <- commit point
	 */
	if (strcmp(key, "pv_try") == 0 && value && strlen(value) > 0) {
		pv_log(INFO, "pv_try set to '%s', arming tryboot flag", value);
		if (_rpiab_mark_tryboot()) {
			pv_log(ERROR, "failed to arm tryboot flag");
			ret = -1;
		}
	}

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
		mbox_close(mbox);
		return -5;
	}

	if (args[1] != 0x80000000) {
		pv_log(ERROR, "mbox SET_REBOOT_FLAGS response: 0x%x (expected 0x80000000)",
		       args[1]);
		mbox_close(mbox);
		return -5;
	}

	pv_log(INFO, "tryboot flag set via mbox (response: 0x%x)", args[1]);

	/* Read back to verify the flag was actually set */
	memset(args, 0, sizeof(args));
	args[0] = 7 * sizeof(args[0]);
	args[1] = 0;
	args[2] = RPI_FIRMWARE_GET_REBOOT_FLAGS;
	args[3] = 4;
	args[4] = 0;
	args[5] = 0;
	args[6] = 0;

	rv = mbox_property(mbox, args);
	if (rv >= 0 && args[1] == 0x80000000) {
		pv_log(INFO, "tryboot flag readback: flags=0x%x (bit0=%d)",
		       args[5], args[5] & 1);
	} else {
		pv_log(WARN, "tryboot flag readback failed (rv=%d, resp=0x%x)",
		       rv, args[1]);
	}

	mbox_close(mbox);

	return 0;
}

static int _rpiab_install_trybootimg(char *rev)
{
	char imgpath[PATH_MAX];
	char trypath[PATH_MAX];
	struct stat st;
	int rv;
	off_t si;

#ifndef PVTEST
	pv_paths_storage_trail_pv_file(imgpath, PATH_MAX, rev, "rpiboot.img");
	if (stat(imgpath, &st)) {
		pv_paths_storage_trail_pv_file(imgpath, PATH_MAX, rev,
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

/*
 * Read pv_rev.txt from the currently booted partition.
 * This tells us what revision that partition was installed for.
 *
 * If pv_rev.txt doesn't exist (legacy/factory image), boot_partition_rev
 * stays NULL and bootloader.c will use the default from environment.
 *
 * Returns 0 on success, -1 if pv_rev.txt not found.
 */
static int _rpiab_read_boot_partition_rev(void)
{
	int wstatus;
	size_t s, r;
	sigset_t oldset;
	char *cmdbuf = NULL;
	char buf[256] = { 0 };
	FILE *f;
	pid_t p;
	int pv_rev_txt_found = 0;

	/* 'partition' is the partition number we booted from */
	pv_log(DEBUG, "reading pv_rev.txt from boot partition %d", partition);

	s = snprintf(NULL, 0, "mcopy -n -i %s ::pv_rev.txt %s",
		     paths.bootimg[partition - 1],
		     paths.pv_rev_tmp) + 1;

	cmdbuf = malloc(s);
	if (!cmdbuf) {
		pv_log(ERROR, "OOM allocating cmdbuf");
		return -1;
	}

	snprintf(cmdbuf, s, "mcopy -n -i %s ::pv_rev.txt %s",
		 paths.bootimg[partition - 1],
		 paths.pv_rev_tmp);

	if (pvsignals_block_chld(&oldset)) {
		free(cmdbuf);
		return -1;
	}

	p = tsh_run(cmdbuf, 0, NULL);
	if (p < 0) {
		pv_log(DEBUG, "tsh_run '%s' failed: %s", cmdbuf, strerror(errno));
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
				pv_log(DEBUG, "pv_rev.txt not found on partition %d",
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

	/* Read the extracted file */
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
	char *end = buf + strlen(buf) - 1;
	while (end > buf && (*end == '\n' || *end == '\r' || *end == ' '))
		*end-- = '\0';

	if (boot_partition_rev)
		free(boot_partition_rev);
	boot_partition_rev = strdup(buf);
	pv_log(INFO, "Boot partition revision (from pv_rev.txt): %s", boot_partition_rev);

	return 0;
}

/*
 * Write pv_rev.txt to the try boot partition.
 * This file contains just the revision string, used to verify
 * that the boot partition matches the expected revision.
 */
static int _rpiab_write_pv_rev_txt(const char *rev)
{
	int wstatus;
	size_t s;
	sigset_t oldset;
	char *cmdbuf = NULL;
	FILE *f;
	pid_t p;

	pv_log(INFO, "writing pv_rev.txt to tryboot partition");

	/* Write revision to temp file */
	f = fopen(paths.pv_rev_tmp, "w");
	if (!f) {
		pv_log(ERROR, "Cannot create pv_rev.txt temp file %s: %s",
		       paths.pv_rev_tmp, strerror(errno));
		return -1;
	}
	fprintf(f, "%s\n", rev);
	fclose(f);

	/* Copy to try partition via mcopy */
	s = snprintf(NULL, 0, "mcopy -o -i %s %s ::pv_rev.txt",
		     paths.bootimg[autoboot_try_partition - 1],
		     paths.pv_rev_tmp) + 1;

	cmdbuf = malloc(s);
	if (!cmdbuf) {
		pv_log(ERROR, "OOM allocating cmdbuf");
		return -1;
	}

	snprintf(cmdbuf, s, "mcopy -o -i %s %s ::pv_rev.txt",
		 paths.bootimg[autoboot_try_partition - 1],
		 paths.pv_rev_tmp);

	if (pvsignals_block_chld(&oldset)) {
		pv_log(ERROR, "Cannot block sigchld: %s", strerror(errno));
		free(cmdbuf);
		return -1;
	}

	pv_log(DEBUG, "copying pv_rev.txt to boot partition: %s", cmdbuf);

	p = tsh_run(cmdbuf, 0, NULL);
	if (p < 0) {
		pv_log(ERROR, "tsh_run '%s' failed: %s", cmdbuf, strerror(errno));
		pvsignals_setmask(&oldset);
		free(cmdbuf);
		return -1;
	}
	free(cmdbuf);

	/* Wait for mcopy to complete */
	for (int i = 0; i < 10; i++) {
		pid_t wp = waitpid(p, &wstatus, WNOHANG);
		if (wp < 0) {
			pv_log(ERROR, "waitpid failed: %s", strerror(errno));
			pvsignals_setmask(&oldset);
			return -1;
		}
		if (wp > 0) {
			if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus)) {
				pv_log(ERROR, "mcopy pv_rev.txt failed with status %d",
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

static int rpiab_install_update(char *rev)
{
	if (_rpiab_install_trybootimg(rev)) {
		pv_log(ERROR, "Error installing tryboot image.");
		return -1;
	}

	if (_rpiab_write_pv_rev_txt(rev)) {
		pv_log(ERROR, "Error writing pv_rev.txt to tryboot partition");
		return -1;
	}

	/*
	 * NOTE: Tryboot flag is NOT set here.
	 * It will be set in rpiab_set_env_key() when pv_try is written,
	 * ensuring the correct order:
	 *   1. Boot image installed
	 *   2. pv_rev.txt written
	 *   3. pv_try stored in rpiab.txt
	 *   4. Tryboot flag set (commit point)
	 */

	pv_log(INFO, "Install update prepared (tryboot not yet armed).");
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

static int rpiab_fail_update()
{
	return -1;
}


/*
 * Validate boot state and determine the current revision.
 *
 * This checks that the boot partition revision (from pv_rev.txt or env)
 * matches what we expect based on stored state (pv_try, pv_done) and
 * the tryboot flag.
 *
 * pv_try: stored pv_try value (may be NULL)
 * pv_done: stored pv_rev/pv_done value
 * pv_rev_out: output - the revision to use as current (caller frees)
 *
 * Returns: 0 on success, -1 on error (causes bootloader init to fail)
 */
static int rpiab_validate_state(const char *pv_try, const char *pv_done,
				char **pv_rev_out)
{
	const char *partition_rev = boot_partition_rev;
	int has_pv_try = (pv_try && strlen(pv_try) > 0);

	*pv_rev_out = NULL;

	/* No pv_rev.txt on boot partition - legacy/factory image */
	if (!partition_rev) {
		pv_log(INFO, "No pv_rev.txt on boot partition, using default from env");
		fprintf(stderr, "rpiab: no pv_rev.txt on boot partition, using env default\n");
		/* Return NULL to let bootloader.c use pv_rev from environment */
		return 0;
	}

	pv_log(DEBUG, "Validating boot state: tryboot=%d, pv_try=%s, pv_done=%s, partition_rev=%s",
	       is_tryboot,
	       pv_try ? pv_try : "(null)",
	       pv_done,
	       partition_rev);
	fprintf(stderr, "rpiab: validate tryboot=%d pv_try=%s pv_done=%s part_rev=%s\n",
		is_tryboot,
		pv_try ? pv_try : "(null)",
		pv_done,
		partition_rev);

	if (is_tryboot) {
		/* We're in a tryboot */
		if (!has_pv_try) {
			/* Tryboot but no pv_try set - shouldn't happen */
			pv_log(ERROR, "Tryboot active but no pv_try stored");
			return -1;
		}

		if (strcmp(partition_rev, pv_try) != 0) {
			/* Boot partition revision doesn't match what we expected to try */
			pv_log(ERROR, "Partition mismatch: booted rev=%s but pv_try=%s",
			       partition_rev, pv_try);
			return -1;
		}

		/* Tryboot and revision matches - use pv_try as current */
		pv_log(INFO, "Tryboot state valid: trying revision %s", pv_try);
		fprintf(stderr, "rpiab: tryboot valid, using revision %s\n", pv_try);
		*pv_rev_out = strdup(pv_try);
		return 0;

	} else {
		/* Normal boot (not tryboot) */
		if (has_pv_try) {
			/*
			 * Normal boot but pv_try is set!
			 * This means one of:
			 * - Power loss before tryboot flag was set
			 * - Very early crash in tryboot, RPi auto-rolled back
			 * - Tryboot succeeded but flag was consumed by reboot
			 *
			 * We may have booted from the try partition with a
			 * different pv_rev.txt than pv_done. This is expected:
			 * skip the partition_rev check and use pv_done.
			 * Pantavisor will detect this condition (pv_try set but
			 * running pv_done) and handle it appropriately.
			 */
			fprintf(stderr, "rpiab: early rollback! pv_try=%s but is_tryboot=0\n", pv_try);
			pv_log(WARN, "Early rollback detected: pv_try=%s was set but we booted normally",
			       pv_try);
			pv_log(WARN, "Update to revision %s failed before reaching pantavisor",
			       pv_try);

			if (strcmp(partition_rev, pv_done) != 0) {
				pv_log(WARN, "Partition rev=%s != pv_done=%s (expected during early rollback)",
				       partition_rev, pv_done);
			}

			pv_log(INFO, "Early rollback: using committed revision %s", pv_done);
			*pv_rev_out = strdup(pv_done);
			return 0;
		}

		if (strcmp(partition_rev, pv_done) != 0) {
			/* Boot partition doesn't match committed revision */
			pv_log(ERROR, "Partition mismatch: booted rev=%s but pv_rev=%s",
			       partition_rev, pv_done);
			return -1;
		}

		/* Normal boot, revision matches - all good */
		pv_log(INFO, "Normal boot state valid: revision %s", pv_done);
		*pv_rev_out = strdup(pv_done);
		return 0;
	}
}

const struct bl_ops rpiab_ops = {
	.free = rpiab_free,
	.init = rpiab_init,
	.set_env_key = rpiab_set_env_key,
	.unset_env_key = rpiab_unset_env_key,
	.get_env_key = rpiab_get_env_key,
	.flush_env = rpiab_flush_env,
	.install_update = rpiab_install_update,
	.commit_update = rpiab_commit_update,
	.fail_update = rpiab_fail_update,
	.validate_state = rpiab_validate_state,
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
