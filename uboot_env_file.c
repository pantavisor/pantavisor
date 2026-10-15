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
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/limits.h>

#include "uboot_env_file.h"
#include "blkid.h"
#include "config.h"
#include "paths.h"
#include "utils/str.h"
#include "utils/fs.h"

#define MODULE_NAME "uboot-env-file"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define ENV_FILE_DEFAULT "/pv.env"

// what U-Boot's text "env export" leaves for pv_trying cleared: just the NUL
static const char cleared_env[] = "";

struct env_file {
	char device[PATH_MAX]; // empty when the file is on the storage mount
	char path[PATH_MAX]; // path inside the filesystem
};

// get_blkid dereferences the storage fstype, which is unset in appengine
static int lookup_device(const char *key, char *dev, size_t size)
{
	struct blkid_info info;
	int ret = -1;

	if (!key || !pv_config_get_str(PV_STORAGE_FSTYPE))
		return -1;

	blkid_init(&info);
	if (!get_blkid(&info, key) && info.device) {
		SNPRINTF_WTRUNC(dev, size, "%s", info.device);
		ret = 0;
	}
	free_blkid_info(&info);

	return ret;
}

static int storage_device(char *dev, size_t size)
{
	return lookup_device(pv_config_get_str(PV_STORAGE_DEVICE), dev, size);
}

// e.g. /dev/mmcblk0p2 -> mmcblk0, /dev/sda2 -> sda
static int disk_of(const char *dev, char *disk, size_t size)
{
	char link[PATH_MAX], real[PATH_MAX], parent[PATH_MAX];
	const char *name = strrchr(dev, '/');

	name = name ? name + 1 : dev;
	SNPRINTF_WTRUNC(link, sizeof(link), "/sys/class/block/%s/partition",
			name);
	if (access(link, F_OK))
		return -1;

	SNPRINTF_WTRUNC(link, sizeof(link), "/sys/class/block/%s", name);
	if (!realpath(link, real))
		return -1;

	pv_fs_dirname(real, parent);
	pv_fs_basename(parent, disk);

	return *disk ? 0 : -1;
}

static int partition_number(const char *disk, const char *entry)
{
	char path[PATH_MAX], buf[16] = { 0 };

	if (strncmp(entry, disk, strlen(disk)))
		return -1;

	SNPRINTF_WTRUNC(path, sizeof(path), "/sys/class/block/%s/%s/partition",
			disk, entry);
	if (pv_fs_file_read_to_buf(path, buf, sizeof(buf) - 1) <= 0)
		return -1;

	return atoi(buf);
}

// U-Boot prints partition numbers in hex, the kernel counts in decimal
static int disk_partition_device(const char *disk, unsigned long number,
				 char *dev, size_t size)
{
	char path[PATH_MAX];
	struct dirent *de;
	int ret = -1;
	DIR *d;

	SNPRINTF_WTRUNC(path, sizeof(path), "/sys/class/block/%s", disk);
	d = opendir(path);
	if (!d)
		return -1;

	while (ret && (de = readdir(d))) {
		if (partition_number(disk, de->d_name) == (int)number) {
			SNPRINTF_WTRUNC(dev, size, "/dev/%s", de->d_name);
			ret = 0;
		}
	}
	closedir(d);

	return ret;
}

static void set_target(struct env_file *ef, const char *device,
		       const char *path, const char *storage_dev)
{
	// the storage partition is already mounted, use that mount
	if (storage_dev && !strcmp(device, storage_dev))
		device = "";

	SNPRINTF_WTRUNC(ef->device, sizeof(ef->device), "%s", device);
	SNPRINTF_WTRUNC(ef->path, sizeof(ef->path), "%s", path);
}

static int resolve_part(struct env_file *ef, const char *spec)
{
	char storage_dev[PATH_MAX], disk[NAME_MAX], dev[PATH_MAX];
	const char *sep = strchr(spec, ':');
	char *end;
	unsigned long number = strtoul(spec, &end, 16);

	if (!sep || end != sep || sep == spec || sep[1] != '/')
		return -1;
	if (storage_device(storage_dev, sizeof(storage_dev)) ||
	    disk_of(storage_dev, disk, sizeof(disk)) ||
	    disk_partition_device(disk, number, dev, sizeof(dev)))
		return -1;

	set_target(ef, dev, sep + 1, storage_dev);
	return 0;
}

static int resolve_blkid(struct env_file *ef, const char *spec)
{
	char key[PATH_MAX], storage_dev[PATH_MAX] = { 0 };
	const char *sep = strstr(spec, ":/");
	char dev[PATH_MAX];

	if (!sep)
		return -1;

	SNPRINTF_WTRUNC(key, sizeof(key), "%.*s", (int)(sep - spec), spec);
	if (lookup_device(key, dev, sizeof(dev)))
		return -1;

	storage_device(storage_dev, sizeof(storage_dev));
	set_target(ef, dev, sep + 1, storage_dev);
	return 0;
}

static int resolve(struct env_file *ef, const char *spec)
{
	memset(ef, 0, sizeof(*ef));

	if (!strncmp(spec, "part:", 5))
		return resolve_part(ef, spec + 5);
	if (!strncmp(spec, "ubi::", 5)) {
		if (spec[5] != '/')
			return -1;
		set_target(ef, "", spec + 5, NULL);
		return 0;
	}
	if (!strncmp(spec, "LABEL=", 6) || !strncmp(spec, "UUID=", 5))
		return resolve_blkid(ef, spec);

	return -1;
}

static int overwrite(const char *path)
{
	struct stat st;
	int fd, ret = -1;

	// only touch a pv.env the boot script created
	if (stat(path, &st) || !S_ISREG(st.st_mode)) {
		pv_log(INFO, "no %s, nothing to rewrite", path);
		return 1;
	}

	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd < 0) {
		pv_log(WARN, "cannot open %s: %s", path, strerror(errno));
		return -1;
	}

	if (pv_fs_file_write_nointr(fd, cleared_env, sizeof(cleared_env)) ==
		    (ssize_t)sizeof(cleared_env) &&
	    !fsync(fd))
		ret = 0;
	else
		pv_log(WARN, "cannot write %s: %s", path, strerror(errno));
	close(fd);

	return ret;
}

static int mount_any(const char *dev, const char *mnt)
{
	static const char *const fstypes[] = { "vfat", "ext4" };

	for (size_t i = 0; i < sizeof(fstypes) / sizeof(*fstypes); i++)
		if (!mount(dev, mnt, fstypes[i], MS_NOATIME, NULL))
			return 0;

	pv_log(WARN, "cannot mount %s as vfat or ext4: %s", dev,
	       strerror(errno));
	return -1;
}

static int overwrite_on_device(const struct env_file *ef)
{
	char mnt[PATH_MAX], file[PATH_MAX];
	int ret;

	pv_paths_pv_file(mnt, sizeof(mnt), "bootenv-mnt");
	pv_fs_mkdir_p(mnt, 0700);
	if (mount_any(ef->device, mnt))
		return -1;

	SNPRINTF_WTRUNC(file, sizeof(file), "%s%s", mnt, ef->path);
	ret = overwrite(file);
	sync();
	if (umount(mnt))
		pv_log(WARN, "cannot unmount %s: %s", mnt, strerror(errno));
	rmdir(mnt);

	return ret;
}

// returns 0 on rewrite, 1 when there is no file, -1 on failure
static int rewrite(const struct env_file *ef)
{
	char file[PATH_MAX], storage[PATH_MAX];
	int ret;

	if (*ef->device)
		ret = overwrite_on_device(ef);
	else {
		pv_paths_storage(storage, sizeof(storage));
		SNPRINTF_WTRUNC(file, sizeof(file), "%s%s", storage, ef->path);
		ret = overwrite(file);
	}

	if (!ret)
		pv_log(INFO, "cleared pv_trying in %s%s%s", ef->device,
		       *ef->device ? ":" : "storage", ef->path);
	return ret;
}

static int rewrite_probed(void)
{
	static const char *const specs[] = { "LABEL=boot:" ENV_FILE_DEFAULT,
					     "ubi::" ENV_FILE_DEFAULT };
	struct env_file ef;
	int ret;

	for (size_t i = 0; i < sizeof(specs) / sizeof(*specs); i++) {
		if (resolve(&ef, specs[i]))
			continue;
		ret = rewrite(&ef);
		if (ret <= 0)
			return ret;
	}

	pv_log(INFO, "no pv.env found on the boot partition or storage");
	return 0;
}

int pv_uboot_env_file_clear_trying(void)
{
	const char *spec = pv_config_get_str(PV_BOOTLOADER_TRYING_ENV);
	struct env_file ef;

	if (!spec || !*spec)
		return rewrite_probed();

	if (resolve(&ef, spec)) {
		pv_log(WARN, "cannot resolve PV_BOOTLOADER_TRYING_ENV '%s'",
		       spec);
		return -1;
	}

	return rewrite(&ef) < 0 ? -1 : 0;
}
