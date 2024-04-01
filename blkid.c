/* blkid.c - Prints type, label and UUID of filesystem(s).
 *
 * Copyright 2013 Brad Conroy <bconroy@uis.edu>
 *
 * See ftp://ftp.kernel.org/pub/linux/utils/util-linux/v2.24/libblkid-docs/api-index-full.html
 * TODO: -U and -L should require arguments
*/

/*
 * Copyright (c) 2019 Pantacor Ltd.
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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <linux/limits.h>

#include "blkid.h"
#include "utils/math.h"
#include "str.h"
#include "log.h"
#include "utils/fs.h"
#include "config.h"

#define MODULE_NAME "blkid"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)

static char toybuf[4096];

struct fstype {
	char *name;
	uint64_t magic;
	int magic_len, magic_offset, uuid_off, label_len, label_off;
};

static const struct fstype fstypes[] = {
	{ "ext2", 0xEF53, 2, 1080, 1128, 16,
	  1144 }, // keep this first for ext3/4 check
	{ "swap", 0x4341505350415753LL, 8, 4086, 1036, 15, 1052 },
	// NTFS label actually 8/16 0x4d80 but horrible: 16 bit wide characters via
	// codepage, something called a uuid that's only 8 bytes long...
	{ "ntfs", 0x5346544e, 4, 3, 0x48, 0, 0 },

	{ "adfs", 0xadf5, 2, 0xc00, 0, 0, 0 },
	{ "bfs", 0x1badface, 4, 0, 0, 0, 0 },
	{ "btrfs", 0x4D5F53665248425FULL, 8, 65600, 65803, 256, 65819 },
	{ "cramfs", 0x28cd3d45, 4, 0, 0, 16, 48 },
	{ "f2fs", 0xF2F52010, 4, 1024, 1132, 512, 0x47c },
	{ "jfs", 0x3153464a, 4, 32768, 32920, 16, 32904 },
	{ "nilfs", 0x3434, 2, 1030, 1176, 80, 1192 },
	{ "reiserfs", 0x724573496552ULL, 6, 8244, 8276, 16, 8292 },
	{ "reiserfs", 0x724573496552ULL, 6, 65588, 65620, 16, 65636 },
	{ "romfs", 0x2d6d6f72, 4, 0, 0, 0, 0 },
	{ "squashfs", 0x73717368, 4, 0, 0, 0, 0 },
	{ "xiafs", 0x012fd16d, 4, 572, 0, 0, 0 },
	{ "xfs", 0x42534658, 4, 0, 32, 12, 108 },
	{ "vfat", 0x3233544146ULL, 5, 82, 67, 11, 71 }, // fat32
	{ "vfat", 0x31544146, 4, 54, 39, 11, 43 } // fat1
};

// If *a starts with b, advance *a past it and return 1, else return 0;
static int strstart(char **a, char *b)
{
	int len = strlen(b), i = !strncmp(*a, b, len);

	if (i)
		*a += len;

	return i;
}

static int readall(int fd, char *buf, int len)
{
	int ret = 0;
read_again:
	ret = read(fd, buf, len);
	if (ret < 0 && errno == EINTR)
		goto read_again;
	return ret;
}

static void store_tag(char *tag, char *buf, struct blkid_info *info)
{
	if (strncmp(tag, "TYPE", strlen("TYPE")) == 0) {
		info->fstype = strdup(buf);
	} else if (strncmp(tag, "LABEL", strlen("LABEL")) == 0) {
		info->label = strdup(buf);
	} else if (strncmp(tag, "UUID", strlen("UUID")) == 0) {
		info->uuid = strdup(buf);
	} else if (strncmp(tag, "SEC_TYPE", strlen("SEC_TYPE")) == 0) {
		info->sec_type = strdup(buf);
	}
}

static void do_blkid(int fd, char *name, struct blkid_info *info)
{
	int off = 0, i, j, len;
	char buf[128], *type, *s;

	for (;;) {
		int pass = 0;

		// Read next block of data
		len = readall(fd, toybuf, sizeof(toybuf));
		if (len != sizeof(toybuf))
			return;

		// Iterate through types in range
		for (i = 0; i < ARRAY_LEN(fstypes); i++) {
			uint64_t test;

			// Skip tests not in this 4k block
			if (fstypes[i].magic_offset >
			    off + (ssize_t)sizeof(toybuf)) {
				pass++;
				continue;
			}
			if (fstypes[i].magic_offset < off)
				continue;

			// Populate 64 bit little endian magic value
			test = 0;
			for (j = 0; j < fstypes[i].magic_len; j++)
				test += (((uint64_t)toybuf
						  [j + fstypes[i].magic_offset -
						   off]) &
					 0xff)
					<< (8 * j);
			if (test == fstypes[i].magic)
				break;
		}

		if (i == ARRAY_LEN(fstypes)) {
			off += len;
			if (pass)
				continue;
			return;
		}
		break;
	}

	// distinguish ext2/3/4
	type = fstypes[i].name;
	if (!i) {
		if (toybuf[1116] & 4)
			type = "ext3";
		if (toybuf[1120] & 64)
			type = "ext4";
	}

	len = fstypes[i].label_len;
	if (len) {
		s = toybuf + fstypes[i].label_off - off;
		if (!strcmp(type, "vfat")) {
			store_tag("SEC_TYPE", "msdos", info);
			while (len && s[len - 1] == ' ')
				len--;
			if (strstart(&s, "NO NAME"))
				len = 0;
		}
		// TODO: special case NTFS $VOLUME_NAME here...
		if (len) {
			if (!strcmp(type, "f2fs")) {
				// Convert UTF16LE to ASCII by replacing non-ASCII with '?'.
				// TODO: support non-ASCII.
				for (j = 0; j < len; j++) {
					buf[j] = s[2 * j];
					if (s[2 * j + 1])
						buf[j] = '?';
					if (!buf[j])
						break;
				}
			} else
				sprintf(buf, "%.*s", len, s);
			store_tag("LABEL", buf, info);
		}
	}

	len = fstypes[i].uuid_off;
	if (len) {
		int uoff = len - off;

		// Assemble UUID with whatever size and set of dashes this filesystem uses
		s = buf;
		if (!strcmp(type, "ntfs")) {
			for (j = 7; j >= 0; --j)
				s += sprintf(s, "%02X", toybuf[uoff + j]);
		} else if (!strcmp(type, "vfat")) {
			s += sprintf(s, "%02X%02X-%02X%02X", toybuf[uoff + 3],
				     toybuf[uoff + 2], toybuf[uoff + 1],
				     toybuf[uoff]);
		} else {
			for (j = 0; j < 16; j++)
				s += sprintf(s, "-%02x" + !(0x550 & (1 << j)),
					     toybuf[uoff + j]);
		}
		store_tag("UUID", buf, info);
	}

	if ((!strcmp(type, "ext3") || !strcmp(type, "ext4")) &&
	    !(toybuf[1120] & ~0x12))
		store_tag("SEC_TYPE", "ext2", info);

	store_tag("TYPE", type, info);
}

static int get_ubifs_vol_count(const char *path)
{
	char volume_path[PATH_MAX] = { 0 };
	pv_fs_path_concat(volume_path, 2, path, "volumes_count");

	// maximum number of volumes allowed is 128 (UBI_MAX_VOLUMES)
	// drivers/mtd/ubi/ubi-media.h on the kernel repo
	char buf[4] = { 0 };
	ssize_t read = pv_fs_file_read_to_buf(volume_path, buf, 8);

	if (read < 1)
		return read;

	return strtol(buf, NULL, 10);
}

static char *get_ubifs_dev_path(const char *dev, const char *vol,
				const char *ubi_sys_path, int vol_count)
{
	char ubi_sys_attr[PATH_MAX] = { 0 };

	// maximum length of ubifs volume name is
	// 127 + 1 (UBI_VOL_NAME_MAX + '\0')
	// drivers/mtd/ubi/ubi-media.h on the kernel repo
	char vol_name[128] = { 0 };
	char ubi_dev[NAME_MAX] = { 0 };

	ssize_t read = 0;

	for (int i = 0; i < vol_count; ++i) {
		snprintf(ubi_dev, NAME_MAX, "%s_%d", dev, i);
		pv_fs_path_concat(ubi_sys_attr, 3, ubi_sys_path, ubi_dev,
				  "name");

		read = pv_fs_file_read_to_buf(ubi_sys_attr, vol_name, 128);

		if (read < 1)
			continue;

		if (!strncmp(vol, vol_name, strlen(vol))) {
			char buf[PATH_MAX] = { 0 };
			pv_fs_path_concat(buf, 2, "/dev", ubi_dev);
			return strdup(buf);
		}
		memset(ubi_sys_attr, 0, PATH_MAX);
	}

	return NULL;
}

static int get_blkid_ubifs(struct blkid_info *info, const char *key)
{
	int ret = 0;
	char *sep = strchr(key, ':');
	if (!sep)
		return -1;

	char dev[NAME_MAX] = { 0 };
	char vol[NAME_MAX] = { 0 };
	int dev_sz = sep - key;

	memcpy(dev, key, dev_sz);
	memcpy(vol, key + dev_sz + 1, strlen(key) - dev_sz);

	char path[PATH_MAX] = { 0 };
	pv_fs_path_concat(path, 2, "/sys/devices/virtual/ubi", dev);

	int vol_count = get_ubifs_vol_count(path);
	if (vol_count < 1)
		return -2;

	info->device = get_ubifs_dev_path(dev, vol, path, vol_count);
	info->fstype = strdup("ubifs");
	info->label = strdup(vol);

	return ret;
}

/*
 * Get block device from UUID or LABEL.
 * The key should be of the form UUID=XXXX... or
 * LABEL=XXXXX.....
 * */
int get_blkid(struct blkid_info *info, const char *key)
{
	if (!strncmp(pv_config_get_storage_fstype(), "ubifs", strlen("ubifs")))
		return get_blkid_ubifs(info, key);

	unsigned int ma, mi, sz;
	int fd;
	char *name = toybuf, *buffer = toybuf + 1024, device[32];
	FILE *fp = fopen("/proc/partitions", "r");
	char *id_or_label = NULL;
	int i = 0;
	struct type_store {
		char *key;
		char **store;
	};
	struct type_store key_store[] = {
		{ .key = "LABEL=", .store = &info->label },
		{ .key = "UUID=", .store = &info->uuid }
	};

	for (i = 0; i < ARRAY_LEN(key_store); i++) {
		size_t kl = strlen(key);
		size_t sl = strlen(key_store[i].key);
		if (kl < sl)
			continue;
		if (strncmp(key, key_store[i].key, sl) == 0) {
			id_or_label = pv_str_skip_prefix((char *)key,
							 key_store[i].key);
			break;
		}
	}

	/*
     * if we don't have a LABEL= or UUID= then assume that it's
     * the device and return that in device info.
     * */
	if (!id_or_label) {
		info->device = strdup(key);
		goto out;
	}

	if (fp) {
		while (fgets(buffer, 1024, fp)) {
			bool found = false;
			*name = 0;
			if (sscanf(buffer, " %u %u %u %[^\n ]", &ma, &mi, &sz,
				   name) != 4)
				continue;
			sprintf(device, "/dev/%.20s", name);
			if (-1 == (fd = open(device, O_RDONLY))) {
				pv_log(WARN, "failed Device: %s", device);
				if (errno != ENOMEDIUM)
					pv_log(WARN,
					       "unable to open device file %s",
					       device);
				continue;
			} else {
				do_blkid(fd, device, info);
				close(fd);
			}
			for (i = 0; i < ARRAY_LEN(key_store); i++) {
				char *to_compare = *(key_store[i].store);
				if (to_compare &&
				    (strcmp(to_compare, id_or_label) == 0)) {
					info->device = strdup(device);
					found = true;
					break;
				}
			}
			if (found)
				break;
			/*
		     * If we reach here then free the resources allocated
		     * in blkid_info.
		     * */
			free_blkid_info(info);
		}
	}
out:
	if (fp)
		fclose(fp);
	return 0;
}
