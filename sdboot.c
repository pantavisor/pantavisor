/*
 * Copyright (c) 2026 Pantacor Ltd.
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
 * systemd-boot backend.
 *
 * Every revision boots its own unified kernel image, copied from the trail
 * (bsp/run.json "uki", linked as .pv/pv-uki.efi) to EFI/Linux/pv-<rev>.efi on
 * the ESP, where systemd-boot lists it without any entry file. Revisions are
 * selected through systemd-boot's EFI variables (Boot Loader Interface):
 *
 *   install  LoaderEntryDefault = pv-<done>.efi, LoaderEntryOneShot = pv-<rev>.efi
 *   commit   LoaderEntryDefault = pv-<rev>.efi, other pv-*.efi removed
 *   boot     the booted revision is read back from LoaderEntrySelected
 *
 * The one-shot is consumed by systemd-boot whether or not the tried revision
 * comes up, so any reboot after the try lands on the default. A revision that
 * fails without having been rebooted into (non-reboot transition) has its
 * one-shot removed along with pv_try. The UKI cmdline is fixed at build time and the same image can
 * serve several revisions, so its pv_rev is ignored when LoaderEntrySelected
 * is available.
 *
 * pv_rev/pv_try are kept in uboot.txt through the plain uboot backend.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "bootloader.h"
#include "blkid.h"
#include "config.h"
#include "paths.h"
#include "utils/fs.h"
#include "utils/str.h"

#define MODULE_NAME "sdboot"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define EFIVARS_DIR "/sys/firmware/efi/efivars"
#define EFIVARFS_MAGIC_NUM 0xde5e81e4
#define LOADER_GUID "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

#define EFI_VARIABLE_NON_VOLATILE 0x1
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x2
#define EFI_VARIABLE_RUNTIME_ACCESS 0x4

#define ESP_FSTYPE "vfat"
#define ESP_UKI_DIR "EFI/Linux"
#define UKI_PREFIX "pv-"
#define UKI_SUFFIX ".efi"
#define TRAIL_UKI_FNAME "pv-uki.efi"

#define ENTRY_MAX 256

extern const struct bl_ops uboot_ops;

static char esp_mnt[PATH_MAX];

static int sdboot_mount_efivarfs(void)
{
	struct statfs sfs;

	if (!statfs(EFIVARS_DIR, &sfs) && sfs.f_type == EFIVARFS_MAGIC_NUM)
		return 0;

	if (mount("efivarfs", EFIVARS_DIR, "efivarfs", 0, NULL) &&
	    errno != EBUSY) {
		pv_log(ERROR, "cannot mount efivarfs: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static void sdboot_efivar_path(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, EFIVARS_DIR "/%s-" LOADER_GUID, name);
}

// efivarfs marks variables immutable; they must be made mutable to be
// rewritten or removed
static void sdboot_efivar_mutable(const char *path)
{
	int fd, flags;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	if (!ioctl(fd, FS_IOC_GETFLAGS, &flags) && (flags & FS_IMMUTABLE_FL)) {
		flags &= ~FS_IMMUTABLE_FL;
		ioctl(fd, FS_IOC_SETFLAGS, &flags);
	}

	close(fd);
}

/*
 * Loader variables are NUL-terminated UTF-16LE strings. Entry ids are file
 * names we chose, so anything outside ASCII is rejected rather than converted.
 */
static char *sdboot_efivar_read_str(const char *name)
{
	char path[PATH_MAX];
	uint8_t buf[4 + 2 * ENTRY_MAX];
	char *str;
	ssize_t n;
	int fd, len = 0;

	sdboot_efivar_path(path, sizeof(path), name);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	n = read(fd, buf, sizeof(buf));
	close(fd);

	// 4 bytes of attributes, then the data
	if (n < 6)
		return NULL;

	str = calloc(ENTRY_MAX + 1, sizeof(char));
	if (!str)
		return NULL;

	for (ssize_t i = 4; i + 1 < n && len < ENTRY_MAX; i += 2) {
		uint16_t c = buf[i] | (buf[i + 1] << 8);
		if (!c)
			break;
		if (c > 0x7f) {
			pv_log(WARN, "%s holds a non-ASCII entry id", name);
			free(str);
			return NULL;
		}
		str[len++] = (char)c;
	}

	return str;
}

static int sdboot_efivar_write_str(const char *name, const char *value)
{
	char path[PATH_MAX];
	uint8_t buf[4 + 2 * (ENTRY_MAX + 1)] = { 0 };
	uint32_t attrs = EFI_VARIABLE_NON_VOLATILE |
			 EFI_VARIABLE_BOOTSERVICE_ACCESS |
			 EFI_VARIABLE_RUNTIME_ACCESS;
	size_t len = strlen(value), size;
	int fd;
	ssize_t n;

	if (len > ENTRY_MAX)
		return -1;

	memcpy(buf, &attrs, sizeof(attrs));
	for (size_t i = 0; i < len; i++)
		buf[4 + 2 * i] = (uint8_t)value[i];
	size = 4 + 2 * (len + 1);

	sdboot_efivar_path(path, sizeof(path), name);
	sdboot_efivar_mutable(path);

	// efivarfs takes attributes and data in a single write()
	fd = open(path, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		pv_log(ERROR, "cannot open %s: %s", path, strerror(errno));
		return -1;
	}

	n = write(fd, buf, size);
	close(fd);

	if (n != (ssize_t)size) {
		pv_log(ERROR, "cannot write %s=%s: %s", name, value,
		       strerror(errno));
		return -1;
	}

	pv_log(DEBUG, "set %s=%s", name, value);

	return 0;
}

static int sdboot_efivar_delete(const char *name)
{
	char path[PATH_MAX];

	sdboot_efivar_path(path, sizeof(path), name);
	sdboot_efivar_mutable(path);

	if (unlink(path) && errno != ENOENT) {
		pv_log(ERROR, "cannot delete %s: %s", name, strerror(errno));
		return -1;
	}

	pv_log(DEBUG, "deleted %s", name);

	return 0;
}

static void sdboot_entry_name(char *buf, size_t size, const char *rev)
{
	SNPRINTF_WTRUNC(buf, size, UKI_PREFIX "%s" UKI_SUFFIX, rev);
}

// pv-<rev>.efi -> <rev>; NULL for any other entry
static char *sdboot_entry_rev(const char *entry)
{
	size_t len = strlen(entry);
	size_t plen = strlen(UKI_PREFIX), slen = strlen(UKI_SUFFIX);

	if (len <= plen + slen || strncmp(entry, UKI_PREFIX, plen) ||
	    strcmp(entry + len - slen, UKI_SUFFIX))
		return NULL;

	return strndup(entry + plen, len - plen - slen);
}

static int sdboot_esp_mount(void)
{
	struct blkid_info info;
	const char *esp = pv_config_get_str(PV_BOOTLOADER_SDBOOT_ESP);
	int ret = -1;

	blkid_init(&info);
	if (get_blkid(&info, esp) || !info.device) {
		pv_log(ERROR, "cannot find ESP '%s'", esp);
		goto out;
	}

	pv_fs_mkdir_p(esp_mnt, 0755);
	if (mount(info.device, esp_mnt, ESP_FSTYPE, MS_NOATIME, NULL)) {
		pv_log(ERROR, "cannot mount ESP %s: %s", info.device,
		       strerror(errno));
		goto out;
	}

	ret = 0;
out:
	free_blkid_info(&info);
	return ret;
}

static void sdboot_esp_umount(void)
{
	sync();
	if (umount(esp_mnt))
		pv_log(WARN, "cannot unmount ESP: %s", strerror(errno));
}

static void sdboot_esp_uki_path(char *buf, size_t size, const char *rev)
{
	char entry[ENTRY_MAX];

	sdboot_entry_name(entry, sizeof(entry), rev);
	SNPRINTF_WTRUNC(buf, size, "%s/" ESP_UKI_DIR "/%s", esp_mnt, entry);
}

static int sdboot_esp_install_uki(const char *rev)
{
	char src[PATH_MAX], dst[PATH_MAX];

	pv_paths_storage_trail_pv_file(src, sizeof(src), rev, TRAIL_UKI_FNAME);
	if (!pv_fs_path_exist(src)) {
		pv_log(ERROR, "revision %s has no UKI (bsp/run.json \"uki\")",
		       rev);
		return -1;
	}

	sdboot_esp_uki_path(dst, sizeof(dst), rev);
	pv_fs_mkbasedir_p(dst, 0755);

	if (pv_fs_file_copy(src, dst, 0644)) {
		pv_log(ERROR, "cannot copy %s to %s", src, dst);
		return -1;
	}

	pv_log(INFO, "installed %s", dst);

	return 0;
}

// remove every pv-<rev>.efi whose rev is neither keep_a nor keep_b
static void sdboot_esp_prune(const char *keep_a, const char *keep_b)
{
	char dir[PATH_MAX], path[PATH_MAX];
	struct dirent *de;
	DIR *d;

	SNPRINTF_WTRUNC(dir, sizeof(dir), "%s/" ESP_UKI_DIR, esp_mnt);
	d = opendir(dir);
	if (!d)
		return;

	while ((de = readdir(d))) {
		char *rev = sdboot_entry_rev(de->d_name);
		if (!rev)
			continue;

		if ((!keep_a || strcmp(rev, keep_a)) &&
		    (!keep_b || strcmp(rev, keep_b))) {
			SNPRINTF_WTRUNC(path, sizeof(path), "%s/%s", dir,
					de->d_name);
			pv_log(INFO, "removing %s", path);
			pv_fs_path_remove(path, false);
		}
		free(rev);
	}

	closedir(d);
}

static void sdboot_free(void)
{
	if (uboot_ops.free)
		uboot_ops.free();
}

static int sdboot_init(void)
{
	pv_paths_pv_file(esp_mnt, sizeof(esp_mnt), "esp");

	if (sdboot_mount_efivarfs())
		return -1;

	return uboot_ops.init();
}

static int sdboot_set_env_key(char *key, char *value)
{
	return uboot_ops.set_env_key(key, value);
}

/*
 * LoaderEntryOneShot is the firmware's copy of pv_try. A revision that fails
 * during a non-reboot transition never consumed it, so without this the
 * rollback reboot would start the failed revision with pv_try already gone.
 */
static int sdboot_unset_env_key(char *key)
{
	if (!strcmp(key, "pv_try") &&
	    sdboot_efivar_delete("LoaderEntryOneShot"))
		return -1;

	return uboot_ops.unset_env_key(key);
}

static char *sdboot_get_env_key(char *key)
{
	return uboot_ops.get_env_key(key);
}

static int sdboot_flush_env(void)
{
	return uboot_ops.flush_env();
}

static int sdboot_install_update(char *rev)
{
	const char *done = pv_bootloader_get_done();
	char entry[ENTRY_MAX];
	int ret;

	if (sdboot_esp_mount())
		return -1;

	ret = sdboot_esp_install_uki(rev);
	if (!ret)
		sdboot_esp_prune(done, rev);

	sdboot_esp_umount();

	if (ret)
		return -1;

	/*
	 * With no LoaderEntryDefault, loader.conf's default glob picks among
	 * all pv-*.efi, possibly the one being tried; pin the fallback first.
	 */
	sdboot_entry_name(entry, sizeof(entry), done);
	if (sdboot_efivar_write_str("LoaderEntryDefault", entry))
		return -1;

	sdboot_entry_name(entry, sizeof(entry), rev);
	if (sdboot_efivar_write_str("LoaderEntryOneShot", entry))
		return -1;

	return 0;
}

static int sdboot_commit_update(void)
{
	const char *rev = pv_bootloader_get_done();
	char entry[ENTRY_MAX], uki[PATH_MAX];
	int ret = -1;

	if (sdboot_esp_mount())
		return -1;

	// never make an entry the default before it is on the ESP
	sdboot_esp_uki_path(uki, sizeof(uki), rev);
	if (!pv_fs_path_exist(uki) && sdboot_esp_install_uki(rev))
		goto out;

	sdboot_entry_name(entry, sizeof(entry), rev);
	if (sdboot_efivar_write_str("LoaderEntryDefault", entry))
		goto out;

	sdboot_esp_prune(rev, NULL);
	ret = 0;
out:
	sdboot_esp_umount();
	return ret;
}

static int sdboot_validate_state(const char *pv_try, const char *pv_done,
				 char **pv_rev_out)
{
	char *entry, *rev;

	entry = sdboot_efivar_read_str("LoaderEntrySelected");
	if (!entry) {
		pv_log(WARN,
		       "LoaderEntrySelected not set, not booted by systemd-boot? using cmdline pv_rev");
		return 0;
	}

	rev = sdboot_entry_rev(entry);
	if (!rev) {
		pv_log(WARN,
		       "booted entry '%s' is not a pantavisor UKI, using cmdline pv_rev",
		       entry);
		free(entry);
		return 0;
	}

	pv_log(INFO, "booted entry %s: revision %s (try=%s done=%s)", entry,
	       rev, pv_try ? pv_try : "", pv_done ? pv_done : "");
	free(entry);

	*pv_rev_out = rev;

	return 0;
}

const struct bl_ops sdboot_ops = {
	.free = sdboot_free,
	.init = sdboot_init,
	.set_env_key = sdboot_set_env_key,
	.unset_env_key = sdboot_unset_env_key,
	.get_env_key = sdboot_get_env_key,
	.flush_env = sdboot_flush_env,
	.install_update = sdboot_install_update,
	.commit_update = sdboot_commit_update,
	.fail_update = NULL,
	.validate_state = sdboot_validate_state,
};
