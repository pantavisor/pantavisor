/*
 * Copyright (c) 2025-2026 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "disk_impl.h"
#include "disk.h"
#include "config.h"
#include "paths.h"
#include "utils/fs.h"
#include "utils/str.h"

#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define MODULE_NAME "disk-dual"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static void dual_init_done_path(struct pv_disk *disk, char *buf, size_t size)
{
	const char *disksdir = pv_config_get_str(PV_SYSTEM_DISKSDIR);
	if (disk->dual_disks_count >= 2)
		SNPRINTF_WTRUNC(buf, size, "%s/dual_%s_%s.init_done",
				disksdir, disk->dual_disks[0],
				disk->dual_disks[1]);
	else
		SNPRINTF_WTRUNC(buf, size, "%s/dual_%s.init_done", disksdir,
				disk->name);
}

static struct pv_disk *resolve_subdisk(struct pv_disk *dual, int index)
{
	if (index >= dual->dual_disks_count)
		return NULL;
	return pv_disk_find(dual->disk_list, dual->dual_disks[index]);
}

static int bind_mount_to_dual(struct pv_disk *dual, struct pv_disk *sub)
{
	char src[PATH_MAX], dst[PATH_MAX];

	pv_paths_storage_mounted_disk_path(src, PATH_MAX, "dmcrypt",
					   sub->name);
	pv_paths_storage_mounted_disk_path(dst, PATH_MAX, "dmcrypt",
					   dual->name);

	pv_fs_mkdir_p(dst, 0755);

	if (mount(src, dst, NULL, MS_BIND, NULL) != 0) {
		pv_log(ERROR, "dual: bind mount '%s' -> '%s' failed: %s",
		       src, dst, strerror(errno));
		return -1;
	}

	pv_log(INFO, "dual: bind mounted '%s' -> '%s'", src, dst);
	return 0;
}

static int unbind_dual(struct pv_disk *dual)
{
	char dst[PATH_MAX];
	pv_paths_storage_mounted_disk_path(dst, PATH_MAX, "dmcrypt",
					   dual->name);

	if (umount(dst) != 0) {
		if (errno == EINVAL || errno == ENOENT) {
			pv_log(DEBUG, "dual: '%s' not mounted", dst);
			return 0;
		}
		pv_log(ERROR, "dual: unbind '%s' failed: %s", dst,
		       strerror(errno));
		return -1;
	}

	pv_fs_path_remove(dst, true);
	pv_log(INFO, "dual: unbound '%s'", dst);
	return 0;
}

/*
 * Mount a sub-disk under its own name, then bind-mount to the dual path.
 * If !allow_create, set no_create on the sub-disk so the crypt script
 * won't create the image/key if they don't exist.
 */
static int try_mount_subdisk(struct pv_disk *dual, struct pv_disk *sub,
			     bool allow_create)
{
	if (!sub)
		return -1;

	bool orig_no_create = sub->no_create;
	sub->no_create = !allow_create;

	int ret = pv_disk_mount(sub);

	sub->no_create = orig_no_create;

	if (ret != 0)
		return -1;

	ret = bind_mount_to_dual(dual, sub);
	if (ret != 0) {
		pv_disk_umount(sub);
		return -1;
	}

	dual->mounted = true;
	pv_log(INFO, "dual: mounted sub-disk '%s' for '%s'", sub->name,
	       dual->name);
	return 0;
}

static int do_copy_verify(const char *src_dir, const char *dst_dir)
{
	DIR *dir = opendir(src_dir);
	if (!dir) {
		pv_log(ERROR, "dual: cannot open source dir '%s': %s",
		       src_dir, strerror(errno));
		return -1;
	}

	int ret = 0;
	struct dirent *ent;
	while ((ent = readdir(dir)) != NULL) {
		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
			continue;
		if (!strcmp(ent->d_name, "lost+found"))
			continue;

		char src_path[PATH_MAX], dst_path[PATH_MAX];
		SNPRINTF_WTRUNC(src_path, sizeof(src_path), "%s/%s", src_dir,
				ent->d_name);
		SNPRINTF_WTRUNC(dst_path, sizeof(dst_path), "%s/%s", dst_dir,
				ent->d_name);

		struct stat st;
		if (stat(src_path, &st) < 0) {
			pv_log(ERROR, "dual: cannot stat '%s': %s", src_path,
			       strerror(errno));
			ret = -1;
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			pv_fs_mkdir_p(dst_path, st.st_mode & 07777);
			if (do_copy_verify(src_path, dst_path) < 0) {
				ret = -1;
				break;
			}
		} else if (S_ISREG(st.st_mode)) {
			if (pv_fs_file_copy(src_path, dst_path,
					    st.st_mode & 07777) < 0) {
				pv_log(ERROR, "dual: copy failed '%s' -> '%s'",
				       src_path, dst_path);
				ret = -1;
				break;
			}
			if (!pv_fs_file_is_same(src_path, dst_path)) {
				pv_log(ERROR,
				       "dual: verify failed '%s' != '%s'",
				       src_path, dst_path);
				ret = -1;
				break;
			}
		}
	}

	closedir(dir);
	return ret;
}

static int do_copy_once_to_primary(struct pv_disk *dual)
{
	char init_done[PATH_MAX];
	dual_init_done_path(dual, init_done, sizeof(init_done));

	if (pv_fs_path_exist(init_done)) {
		pv_log(INFO, "dual: copy-once-to-primary: already done");
		return 1; /* signal: step done, continue to next */
	}

	struct pv_disk *primary = resolve_subdisk(dual, 0);
	struct pv_disk *secondary = resolve_subdisk(dual, 1);
	if (!primary || !secondary) {
		pv_log(WARN, "dual: need both sub-disks for copy");
		return -1;
	}

	/* mount secondary read-only under its own name */
	bool orig_ro = secondary->read_only;
	bool orig_nc = secondary->no_create;
	secondary->read_only = true;
	secondary->no_create = true;
	int ret = pv_disk_mount(secondary);
	secondary->read_only = orig_ro;
	secondary->no_create = orig_nc;

	if (ret != 0) {
		pv_log(WARN, "dual: secondary not available for copy");
		return -1;
	}

	/* create + mount primary under its own name */
	ret = pv_disk_mount(primary);
	if (ret != 0) {
		pv_log(ERROR, "dual: primary creation for copy failed");
		pv_disk_umount(secondary);
		return -1;
	}

	/* copy from secondary to primary */
	char sec_path[PATH_MAX], pri_path[PATH_MAX];
	pv_paths_storage_mounted_disk_path(sec_path, PATH_MAX, "dmcrypt",
					   secondary->name);
	pv_paths_storage_mounted_disk_path(pri_path, PATH_MAX, "dmcrypt",
					   primary->name);

	ret = do_copy_verify(sec_path, pri_path);

	/* umount secondary — no longer needed */
	pv_disk_umount(secondary);

	if (ret != 0) {
		pv_log(ERROR, "dual: copy verification failed");
		pv_disk_umount(primary);
		return -1;
	}

	/* primary stays mounted, bind-mount to dual path */
	ret = bind_mount_to_dual(dual, primary);
	if (ret != 0) {
		pv_disk_umount(primary);
		return -1;
	}

	dual->mounted = true;
	pv_fs_file_save(init_done, "", 0644);
	pv_log(INFO, "dual: copied secondary to primary");
	return 0;
}

static int pv_disk_dual_init(struct pv_disk *disk)
{
	if (disk->type != DISK_DUAL) {
		pv_log(ERROR, "disk %s is not dual type", disk->name);
		return -1;
	}
	if (disk->dual_disks_count < 1) {
		pv_log(ERROR, "dual disk %s has no sub-disks", disk->name);
		return -1;
	}
	if (disk->init_order_count < 1) {
		pv_log(ERROR, "dual disk %s has no init_order", disk->name);
		return -1;
	}

	for (int i = 0; i < disk->dual_disks_count; i++) {
		if (!pv_disk_find(disk->disk_list, disk->dual_disks[i])) {
			pv_log(ERROR, "dual disk %s: sub-disk '%s' not found",
			       disk->name, disk->dual_disks[i]);
			return -1;
		}
	}

	return 0;
}

static pv_disk_status_t pv_disk_dual_status(struct pv_disk *disk)
{
	char path[PATH_MAX] = { 0 };
	pv_paths_storage_mounted_disk_path(path, PATH_MAX, "dmcrypt",
					   disk->name);

	if (!access(path, F_OK)) {
		pv_log(DEBUG, "dual disk %s already mounted", disk->name);
		return DISK_STATUS_MOUNTED;
	}

	return DISK_STATUS_NOT_MOUNTED;
}

static int pv_disk_dual_format(struct pv_disk *disk)
{
	return 0;
}

static int pv_disk_dual_mount(struct pv_disk *disk)
{
	struct pv_disk *primary = resolve_subdisk(disk, 0);
	struct pv_disk *secondary = resolve_subdisk(disk, 1);

	for (int i = 0; i < disk->init_order_count; i++) {
		const char *step = disk->init_order[i];

		if (!strcmp(step, "primary")) {
			pv_log(INFO, "dual: trying primary '%s'...",
			       disk->dual_disks[0]);
			if (try_mount_subdisk(disk, primary, false) == 0)
				goto done;
			pv_log(INFO, "dual: primary not available");

		} else if (!strcmp(step, "secondary")) {
			pv_log(INFO, "dual: trying secondary '%s'...",
			       secondary ? disk->dual_disks[1] : "(null)");
			if (try_mount_subdisk(disk, secondary, false) == 0)
				goto done;
			pv_log(INFO, "dual: secondary not available");

		} else if (!strcmp(step, "create-primary")) {
			pv_log(INFO, "dual: creating primary '%s'...",
			       disk->dual_disks[0]);
			if (try_mount_subdisk(disk, primary, true) == 0)
				goto done;
			pv_log(WARN, "dual: primary creation failed");

		} else if (!strcmp(step, "create-secondary")) {
			pv_log(INFO, "dual: creating secondary '%s'...",
			       secondary ? disk->dual_disks[1] : "(null)");
			if (try_mount_subdisk(disk, secondary, true) == 0)
				goto done;
			pv_log(WARN, "dual: secondary creation failed");

		} else if (!strcmp(step, "copy-once-to-primary")) {
			int ret = do_copy_once_to_primary(disk);
			if (ret == 0)
				goto done;
			if (ret == 1)
				continue; /* already done, try next step */
			pv_log(WARN, "dual: copy-once-to-primary failed");

		} else {
			pv_log(WARN, "dual: unknown init_order step: %s",
			       step);
		}
	}

	pv_log(ERROR, "dual: all init_order steps failed for %s", disk->name);
	return -1;

done:
	{
		char init_done[PATH_MAX];
		dual_init_done_path(disk, init_done, sizeof(init_done));
		pv_fs_file_save(init_done, "", 0644);
	}
	return 0;
}

static int pv_disk_dual_umount(struct pv_disk *disk)
{
	/* unbind the dual mount point first */
	unbind_dual(disk);
	disk->mounted = false;

	/* then umount whichever sub-disk is mounted */
	for (int i = 0; i < disk->dual_disks_count; i++) {
		struct pv_disk *sub = resolve_subdisk(disk, i);
		if (!sub)
			continue;

		if (sub->mounted)
			pv_disk_umount(sub);
	}

	return 0;
}

struct pv_disk_impl dual_impl = {
	.init = pv_disk_dual_init,
	.status = pv_disk_dual_status,
	.format = pv_disk_dual_format,
	.mount = pv_disk_dual_mount,
	.umount = pv_disk_dual_umount,
};
