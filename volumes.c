/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <libgen.h>

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "loop.h"

#include "paths.h"
#include "pantavisor.h"
#include "volumes.h"
#include "parser/parser.h"
#include "platforms.h"
#include "state.h"
#include "tsh.h"
#include "init.h"
#include "utils/fs.h"
#include "utils/str.h"
#include "utils/tsh.h"

#define MODULE_NAME "volumes"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

#define FW_PATH "/lib/firmware"

static const char *pv_volume_type_str(pv_volume_t vt)
{
	switch (vt) {
	case VOL_LOOPIMG:
		return "LOOP_IMG";
	case VOL_PERMANENT:
		return "PERMANENT";
	case VOL_REVISION:
		return "REVISION";
	case VOL_BOOT:
		return "TMPFS";
	default:
		return "UNKNOWN";
	}

	return "UNKNOWN";
}

static void pv_disk_free(struct pv_disk *d)
{
	if (d->name)
		free(d->name);
	if (d->path)
		free(d->path);
	if (d->uuid)
		free(d->uuid);
	if (d->options)
		free(d->options);

	free(d);
}

void pv_disks_empty(struct pv_state *s)
{
	int num_disk = 0;
	struct pv_disk *d, *tmp;
	struct dl_list *disks = &s->disks;

	// Iterate over all disks from state
	dl_list_for_each_safe(d, tmp, disks, struct pv_disk, list)
	{
		pv_log(DEBUG, "removing disk %s", d->name);
		dl_list_del(&d->list);
		pv_disk_free(d);
		num_disk++;
	}

	pv_log(INFO, "removed %d disks", num_disk);
}

void pv_volume_free(struct pv_volume *v)
{
	if (v->name)
		free(v->name);
	if (v->mode)
		free(v->mode);
	if (v->src)
		free(v->src);
	if (v->dest)
		free(v->dest);
	if (v->umount_cmd)
		free(v->umount_cmd);

	free(v);
}

void pv_volumes_empty(struct pv_state *s)
{
	int num_vol = 0;
	struct pv_volume *v, *tmp;
	struct dl_list *volumes = &s->volumes;

	// Iterate over all volumes from state
	dl_list_for_each_safe(v, tmp, volumes, struct pv_volume, list)
	{
		pv_log(DEBUG, "removing volume %s", v->name);
		dl_list_del(&v->list);
		pv_volume_free(v);
		num_vol++;
	}

	pv_log(INFO, "removed %d volumes", num_vol);
}

struct pv_volume *pv_volume_add_with_disk(struct pv_state *s, char *name,
					  char *disk)
{
	struct pv_volume *v = calloc(1, sizeof(struct pv_volume));
	struct pv_disk *d, *tmp;
	struct dl_list *disks = NULL;

	if (v) {
		v->name = strdup(name);
		dl_list_init(&v->list);
		dl_list_add_tail(&s->volumes, &v->list);
		disks = &s->disks;

		if (disk) {
			dl_list_for_each_safe(d, tmp, disks, struct pv_disk,
					      list)
			{
				if (!strcmp(d->name, disk)) {
					v->disk = d;
					break;
				}
			}
		} else {
			dl_list_for_each_safe(d, tmp, disks, struct pv_disk,
					      list)
			{
				if (d->def) {
					v->disk = d;
					break;
				}
			}
		}
	}

	return v;
}

struct pv_volume *pv_volume_add(struct pv_state *s, char *name)
{
	return pv_volume_add_with_disk(s, name, NULL);
}

struct pv_disk *pv_disk_add(struct pv_state *s)
{
	struct pv_disk *d = calloc(1, sizeof(struct pv_disk));

	if (d) {
		dl_list_init(&d->list);
		dl_list_add_tail(&s->disks, &d->list);
	}

	return d;
}

static int pv_volume_mount_handler(struct pv_volume *v, char *action)
{
	struct pv_disk *d = v->disk;
	char path[PATH_MAX];
	char *command = NULL;
	char *crypt_type;
	int ret;
	int wstatus;

	pv_paths_storage_mounted_disk_path(path, PATH_MAX, "dmcrypt", d->name);
	if (!access(path, F_OK)) {
		pv_log(DEBUG, "disk %s already mounted", path);
		return 0;
	}

	switch (d->type) {
	case DISK_DM_CRYPT_CAAM:
		crypt_type = "caam";
		break;
	case DISK_DM_CRYPT_DCP:
		crypt_type = "dcp";
		break;
	case DISK_DM_CRYPT_VERSATILE:
		crypt_type = "versatile";
		break;
	case DISK_DIR:
	case DISK_UNKNOWN:
	default:
		return -ENOTSUP;
	}

	command = malloc(sizeof(char) *
			 (strlen("/lib/pv/volmount/crypt/crypt %s %s %s %s") +
			  strlen(action) + strlen(crypt_type) +
			  strlen(d->path) + strlen(path) + 1));
	if (!command)
		return -ENOMEM;

	sprintf(command, "/lib/pv/volmount/crypt/crypt %s %s %s %s", action,
		crypt_type, d->path, path);
	pv_log(INFO, "command: %s", command);

	tsh_run(command, 1, &wstatus);
	if (!WIFEXITED(wstatus)) {
		pv_log(ERROR, "command did not terminate normally");
		ret = -1;
	} else if (WEXITSTATUS(wstatus) != 0) {
		pv_log(ERROR, "command returned exit code %d",
		       WEXITSTATUS(wstatus));
		ret = -1;
	} else
		ret = 0;

	if (command)
		free(command);

	return ret;
}
int pv_volume_mount(struct pv_volume *v)
{
	int ret = -1;
	int loop_fd = -1, file_fd = -1;
	struct pantavisor *pv = pv_get_instance();
	struct pv_state *s = pv->state;
	struct pv_disk *d = v->disk;
	char path[PATH_MAX], mntpoint[PATH_MAX];
	char *fstype;
	char *umount_cmd = NULL;
	char *handlercut = NULL;
	char *handler = NULL;
	char *name = NULL;
	const char *partname = NULL;
	struct stat buf;
	int wstatus;
	char *command;
	char *disk_name = NULL;

	if (v->disk && !v->disk->def) {
		ret = pv_volume_mount_handler(v, "mount");
		if (ret < 0)
			return ret;

		disk_name = d->name;
	}

	handlercut = strchr(v->name, ':');
	if (handlercut) {
		*handlercut = 0;
		handler = strdup(v->name);
		*handlercut = ':';
		name = handlercut + 1;
	} else {
		name = v->name;
	}

	switch (pv_state_spec(s)) {
	case SPEC_SYSTEM1:
		if (v->plat) {
			partname = v->plat->name;
		} else {
			partname = "bsp";
		}
		pv_paths_storage_trail_plat_file(path, PATH_MAX, s->rev,
						 partname, name);
		pv_paths_volumes_plat_file(mntpoint, PATH_MAX, partname, name);
		break;
	case SPEC_MULTI1:
		pv_paths_storage_trail_file(path, PATH_MAX, s->rev, name);
		pv_paths_volumes_file(mntpoint, PATH_MAX, name);
		break;
	default:
		pv_log(WARN, "cannot mount volumes for unknown state spec");
		goto out;
	}

	pv_log(DEBUG, "mounting '%s' from platform '%s'", v->name, partname);

	switch (v->type) {
	case VOL_LOOPIMG:
		fstype = strrchr(v->name, '.');
		fstype++;
		if (strcmp(fstype, "bind") == 0) {
			if (stat(mntpoint, &buf) != 0) {
				if (pv_fs_file_save(mntpoint, "", 0644) < 0)
					pv_log(WARN,
					       "could not save file %s: %s",
					       mntpoint, strerror(errno));
			}
			ret = mount(path, mntpoint, NULL, MS_BIND, NULL);
		} else if (strcmp(fstype, "data") == 0) {
			pv_log(INFO, "mounting proper .data dir");

			pv_fs_mkdir_p(mntpoint, 0755);
			ret = mount(path, mntpoint, NULL, MS_BIND | MS_REC,
				    NULL);
		} else if (handler) {
			pv_log(INFO, "with '%s' handler", handler);
			command = malloc(
				sizeof(char) *
				(strlen(handler) + strlen(partname) +
				 strlen(path) + strlen(name) +
				 strlen("/lib/pv/volmount/verity/%s mount %s %s %s") +
				 1));
			umount_cmd = malloc(
				sizeof(char) *
				(strlen(handler) + strlen(partname) +
				 strlen(path) + strlen(name) +
				 strlen("/lib/pv/volmount/verity/%s umount %s %s %s") +
				 1));
			sprintf(command,
				"/lib/pv/volmount/verity/%s mount %s %s %s",
				handler, path, partname, name);
			sprintf(umount_cmd,
				"/lib/pv/volmount/verity/%s umount %s %s %s",
				handler, path, partname, name);
			tsh_run(command, 1, &wstatus);
			if (!WIFEXITED(wstatus))
				ret = -1;
			else if (WEXITSTATUS(wstatus) != 0)
				ret = -1 * WEXITSTATUS(wstatus);
			else
				ret = 0;
			free(command);
		} else {
			ret = mount_loop(path, mntpoint, fstype, &loop_fd,
					 &file_fd);
		}
		break;
	case VOL_PERMANENT:
		if (disk_name)
			pv_paths_crypt_disks_perm_file(path, PATH_MAX,
						       "dmcrypt", disk_name,
						       v->plat->name, v->name);
		else
			pv_paths_storage_disks_perm_file(
				path, PATH_MAX, v->plat->name, v->name);

		pv_fs_mkdir_p(path, 0755);
		pv_fs_mkdir_p(mntpoint, 0755);
		ret = mount(path, mntpoint, "none", MS_BIND, "rw");
		break;
	case VOL_REVISION:
		if (disk_name)
			pv_paths_crypt_disks_rev_file(path, PATH_MAX, "dmcrypt",
						      disk_name, s->rev,
						      v->plat->name, v->name);
		else
			pv_paths_storage_disks_rev_file(path, PATH_MAX, s->rev,
							v->plat->name, v->name);

		pv_fs_mkdir_p(path, 0755);
		pv_fs_mkdir_p(mntpoint, 0755);
		ret = mount(path, mntpoint, "none", MS_BIND, "rw");
		break;
	case VOL_BOOT:
		if (disk_name) {
			char *base_path = NULL;

			pv_paths_crypt_disks_boot_file(path, PATH_MAX,
						       "dmcrypt", disk_name,
						       v->plat->name, v->name);
			base_path = strdup(path);

			char full_path[PATH_MAX];
			pv_fs_path_concat(full_path, 2, dirname(base_path),
					  v->name);
			pv_fs_path_remove(full_path, true);

			free(base_path);

			pv_fs_mkdir_p(path, 0755);
			pv_fs_mkdir_p(mntpoint, 0755);
			ret = mount(path, mntpoint, "none", MS_BIND, "rw");
			break;
		}

		pv_fs_mkdir_p(mntpoint, 0755);
		ret = mount("none", mntpoint, "tmpfs", 0, NULL);
		break;
	default:
		pv_log(WARN, "unknown volume type %d", v->type);
		break;
	}

	if (ret < 0) {
		pv_log(ERROR, "error mounting '%s' (%s) at '%s' -> %s", path,
		       pv_volume_type_str(v->type), mntpoint, strerror(errno));
		goto out;
	}

	pv_log(DEBUG, "mounted '%s' (%s) at '%s'", path,
	       pv_volume_type_str(v->type), mntpoint);
	// register mount state
	v->src = strdup(path);
	v->dest = strdup(mntpoint);
	v->loop_fd = loop_fd;
	v->file_fd = file_fd;
	v->umount_cmd = umount_cmd;

out:
	if (handler)
		free(handler);
	return ret;
}

int pv_volume_unmount(struct pv_volume *v)
{
	int ret = 0;

	pv_log(DEBUG, "unmounting '%s'...", v->dest);

	if (v->umount_cmd != NULL) {
		pv_log(DEBUG, "using handler...");
		int wstatus;
		tsh_run(v->umount_cmd, 1, &wstatus);
		if (!WIFEXITED(wstatus))
			ret = -1;
		else if (WEXITSTATUS(wstatus) != 0)
			ret = -1;
		else
			ret = 0;
	} else if (v->loop_fd == -1) {
		pv_log(DEBUG, "using umount...");
		ret = umount(v->dest);
	} else {
		pv_log(DEBUG, "using umount loop...");
		ret = unmount_loop(v->dest, v->loop_fd, v->file_fd);
	}

	if (ret < 0)
		pv_log(ERROR, "error unmounting volume") else pv_log(
			DEBUG, "unmounted successfully");

	return ret;
}

int pv_volumes_mount_firmware_modules()
{
	int ret = 0;
	struct stat st;
	char path_volumes[PATH_MAX];
	char path_lib[PATH_MAX];
	struct utsname uts;
	struct pantavisor *pv = pv_get_instance();

	char *firmware = pv->state->bsp.firmware;
	char *modules = pv->state->bsp.modules;

	if (!firmware)
		goto modules;

	if ((stat(FW_PATH, &st) < 0) && errno == ENOENT)
		pv_fs_mkdir_p(FW_PATH, 0755);

	if (strchr(firmware, '/')) {
		pv_paths_root_file(path_volumes, PATH_MAX,
				   pv->state->bsp.firmware);
	} else if (strchr(firmware, ':')) {
		pv_paths_volumes_plat_file(path_volumes, PATH_MAX, "bsp",
					   strchr(firmware, ':') + 1);
	} else {
		pv_paths_volumes_plat_file(path_volumes, PATH_MAX, "bsp",
					   pv->state->bsp.firmware);
	}

	if (stat(path_volumes, &st)) {
		pv_log(DEBUG, "cannot mount firmware because %s does not exist",
		       path_volumes);
		goto modules;
	}

	ret = mount_bind(path_volumes, FW_PATH);

	if (ret < 0)
		goto out;

	pv_log(DEBUG, "bind mounted %s firmware to %s", path_volumes, FW_PATH);

modules:

	if (!modules)
		goto out;

	if (strchr(pv->state->bsp.modules, '/')) {
		pv_paths_root_file(path_volumes, PATH_MAX, modules);
		SNPRINTF_WTRUNC(path_volumes, sizeof(path_volumes), "%s",
				modules);
	} else if (strchr(modules, ':')) {
		pv_paths_volumes_plat_file(path_volumes, PATH_MAX, "bsp",
					   strchr(modules, ':') + 1);
	} else {
		pv_paths_volumes_plat_file(path_volumes, PATH_MAX, "bsp",
					   modules);
	}

	if (!uname(&uts) && (stat(path_volumes, &st) == 0)) {
		pv_paths_lib_modules(path_lib, PATH_MAX, uts.release);
		pv_fs_mkdir_p(path_lib, 0755);
		ret = mount_bind(path_volumes, path_lib);
		pv_log(DEBUG, "bind mounted %s modules to %s", path_volumes,
		       path_lib);
	} else
		pv_log(DEBUG, "cannot mount modules because %s does not exist",
		       path_volumes);

out:
	return ret;
}

static int pv_volume_early_init(struct pv_init *this)
{
	char path[PATH_MAX];

	pv_paths_volumes_file(path, PATH_MAX, "");
	mkdir(path, 0755);

	pv_paths_storage_disks(path, PATH_MAX);
	pv_fs_mkdir_p(path, 0755);

	return 0;
}

struct pv_init pv_init_volume = {
	.init_fn = pv_volume_early_init,
	.flags = 0,
};
