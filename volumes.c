/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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
#include "logserver/logserver.h"
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

	if (!v)
		return NULL;

	v->name = strdup(name);
	dl_list_init(&v->list);
	dl_list_add_tail(&s->volumes, &v->list);
	disks = &s->disks;

	dl_list_for_each_safe(d, tmp, disks, struct pv_disk, list)
	{
		// if no disk name requested: use the default
		if ((!disk && d->def) || (disk && !strcmp(d->name, disk))) {
			v->disk = d;
			break;
		}
	}

	return v;
}

struct pv_volume *pv_volume_add(struct pv_state *s, char *name)
{
	return pv_volume_add_with_disk(s, name, NULL);
}

int pv_volume_mount(struct pv_volume *v)
{
	int ret = -1;
	int loop_fd = -1, file_fd = -1;
	struct pantavisor *pv = pv_get_instance();
	struct pv_state *s = pv->state;
	char path[PATH_MAX], mntpoint[PATH_MAX], script[PATH_MAX];
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
	char *verity_options = NULL;

	if (v->disk) {
		disk_name = v->disk->name;
	}

	if (v->disk && !v->disk->def && !v->disk->mounted) {
		ret = pv_disk_mount(v->disk);
		if (ret != 0) {
			pv_log(ERROR, "disk %s mount failed", disk_name);
			return ret;
		}

		v->disk->mounted = 1;
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
		} else if (handler &&
			   (!getenv("pv_verityoff") &&
			    pv_config_get_bool(PV_SECUREBOOT_HANDLERS))) {
			pv_log(INFO, "with '%s' handler", handler);

			if (!partname) {
				pv_log(DEBUG, "No partname == null, aborting");
				goto out;
			}

			pv_paths_lib_volmount(script, PATH_MAX, "verity",
					      handler);

			if (pv_config_get_str(PV_VOLMOUNT_DM_EXTRA_ARGS) !=
			    NULL)
				verity_options = pv_config_get_str(
					PV_VOLMOUNT_DM_EXTRA_ARGS);

			pv_log(INFO, "PV_VOLMOUNT_DM_EXTRA_ARGS: %s",
			       verity_options);

			ret = asprintf(&command, "%s mount %s %s %s %s", script,
				       path, partname, name,
				       verity_options ? verity_options : "");

			if (ret < 0) {
				pv_log(ERROR,
				       " cannot allocate memory for volume mount");
				goto out;
			}

			ret = asprintf(&umount_cmd, "%s umount %s %s %s",
				       script, path, partname, name);

			if (ret < 0) {
				pv_log(ERROR,
				       " cannot allocate memory for volume umount");
				goto out;
			}

			pv_log(INFO, "command: %s", command);
			tsh_run_logserver(command, &wstatus, "volume-mount-out",
					  "volume-mount-err");
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
						       partname, v->name);
		else
			pv_paths_storage_disks_perm_file(path, PATH_MAX,
							 partname, v->name);

		pv_fs_mkdir_p(path, 0755);
		pv_fs_mkdir_p(mntpoint, 0755);
		ret = mount(path, mntpoint, "none", MS_BIND, "rw");
		break;
	case VOL_REVISION:
		if (disk_name)
			pv_paths_crypt_disks_rev_file(path, PATH_MAX, "dmcrypt",
						      disk_name, s->rev,
						      partname, v->name);
		else
			pv_paths_storage_disks_rev_file(path, PATH_MAX, s->rev,
							partname, v->name);

		pv_fs_mkdir_p(path, 0755);
		pv_fs_mkdir_p(mntpoint, 0755);
		ret = mount(path, mntpoint, "none", MS_BIND, "rw");
		break;
	case VOL_BOOT:
		if (disk_name) {
			char *base_path = NULL;

			pv_paths_crypt_disks_boot_file(path, PATH_MAX,
						       "dmcrypt", disk_name,
						       partname, v->name);
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
	if (umount_cmd)
		v->umount_cmd = strdup(umount_cmd);

out:
	if (umount_cmd)
		free(umount_cmd);

	if (handler)
		free(handler);
	return ret;
}

int pv_volume_unmount(struct pv_volume *v)
{
	int ret = 0;

	if (!v->dest)
		return ret;

	if (v->umount_cmd != NULL) {
		pv_log(DEBUG, "umounting with handler...");
		pv_log(INFO, "umount_cmd: %s", v->umount_cmd);
		int wstatus;
		tsh_run_logserver(v->umount_cmd, &wstatus, "volume-umount-out",
				  "volume-umount-err");
		if (!WIFEXITED(wstatus))
			ret = -1;
		else if (WEXITSTATUS(wstatus) != 0)
			ret = -1;
		else
			ret = 0;
	} else if (v->loop_fd == -1) {
		pv_log(DEBUG, "umounting '%s'...", v->dest);
		ret = umount(v->dest);
	} else {
		pv_log(DEBUG, "loop umounting '%s'...", v->dest);
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

	if (pv_fs_path_remove(FW_PATH, true) != 0)
		pv_log(WARN, "couldn't remove initial firmware");

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
		if (pv_fs_path_remove(path_lib, true) != 0)
			pv_log(WARN, "couldn't remove initial modules");

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

int pv_volumes_umount_firmware_modules()
{
	int ret = 0;
	struct utsname uts;
	char path_lib[PATH_MAX];
	struct pantavisor *pv = pv_get_instance();

	if (!pv || !pv->state)
		return ret;

	if (!pv->state->bsp.firmware)
		goto modules;

	ret = umount(FW_PATH);
	if (ret < 0)
		pv_log(WARN, "cannot umount firmware path %s", FW_PATH);

modules:
	if (!pv->state->bsp.modules)
		goto out;

	if (!uname(&uts)) {
		pv_paths_lib_modules(path_lib, PATH_MAX, uts.release);
		ret = umount(path_lib);
		if (ret < 0)
			pv_log(WARN, "cannot umount modules %s: %s", path_lib,
			       strerror(errno));
	} else {
		pv_log(WARN, "cannot get utsinfo %s", strerror(errno));
	}

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
