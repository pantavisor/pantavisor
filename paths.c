/*
 * Copyright (c) 2022-2024 Pantacor Ltd.
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
#include <stddef.h>

#include "config.h"
#include "paths.h"

#include "utils/str.h"

#define MODULE_NAME "paths"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define PV_PATH "%s"
#define PV_PATHF PV_PATH "/%s"

void pv_paths_pv_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_PATHF,
			pv_config_get_str(PV_SYSTEM_RUNDIR), name);
}

#define PV_USRMETA_PATHF PV_PATH "/" USRMETA_DNAME "/%s"
#define PV_USRMETA_PLAT_PATHF PV_PATH "/user-meta.%s/%s"

void pv_paths_pv_usrmeta_key(char *buf, size_t size, const char *key)
{
	SNPRINTF_WTRUNC(buf, size, PV_USRMETA_PATHF,
			pv_config_get_str(PV_SYSTEM_RUNDIR), key);
}

void pv_paths_pv_usrmeta_plat_key(char *buf, size_t size, const char *plat,
				  const char *key)
{
	SNPRINTF_WTRUNC(buf, size, PV_USRMETA_PLAT_PATHF,
			pv_config_get_str(PV_SYSTEM_RUNDIR), plat, key);
}

#define PV_DEVMETA_PATHF PV_PATH "/" DEVMETA_DNAME "/%s"
#define PV_DEVMETA_PLAT_PATHF PV_PATH "/device-meta.%s/%s"

void pv_paths_pv_devmeta_key(char *buf, size_t size, const char *key)
{
	SNPRINTF_WTRUNC(buf, size, PV_DEVMETA_PATHF,
			pv_config_get_str(PV_SYSTEM_RUNDIR), key);
}

void pv_paths_pv_devmeta_plat_key(char *buf, size_t size, const char *plat,
				  const char *key)
{
	SNPRINTF_WTRUNC(buf, size, PV_DEVMETA_PLAT_PATHF,
			pv_config_get_str(PV_SYSTEM_RUNDIR), plat, key);
}

#define PV_LOGS_PATHF PV_PATH "/" LOGS_DNAME "/%s"
#define PV_LOGS_PLAT_PATHF PV_LOGS_PATHF "/%s"
#define PV_LOGS_FILE_PATHF PV_LOGS_PLAT_PATHF "/%s"

void pv_paths_pv_log(char *buf, size_t size, const char *rev)
{
	SNPRINTF_WTRUNC(buf, size, PV_LOGS_PATHF,
			pv_config_get_str(PV_SYSTEM_RUNDIR), rev);
}

void pv_paths_pv_log_plat(char *buf, size_t size, const char *rev,
			  const char *plat)
{
	SNPRINTF_WTRUNC(buf, size, PV_LOGS_PLAT_PATHF,
			pv_config_get_str(PV_SYSTEM_RUNDIR), rev, plat);
}

void pv_paths_pv_log_file(char *buf, size_t size, const char *rev,
			  const char *plat, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LOGS_FILE_PATHF,
			pv_config_get_str(PV_SYSTEM_RUNDIR), rev, plat, name);
}

#define PV_STORAGE_PATHF "%s"

void pv_paths_storage(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT));
}

void pv_paths_storage_log(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF,
			pv_config_get_str(PV_LOG_DIR));
}

void pv_paths_storage_usrmeta(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF,
			pv_config_get_str(PV_CACHE_USRMETADIR));
}

void pv_paths_storage_devmeta(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF,
			pv_config_get_str(PV_CACHE_DEVMETADIR));
}

void pv_paths_storage_dropbear(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF,
			pv_config_get_str(PV_DROPBEAR_CACHE_DIR));
}

#define PV_STORAGE_FILE_PATHF "%s/%s"

void pv_paths_storage_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_FILE_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), name);
}

#define PV_OBJECT_PATHF "%s/objects/%s"
#define PV_OBJECT_TMP_PATHF "%s/objects/%s.tmp"

void pv_paths_storage_object(char *buf, size_t size, const char *sha)
{
	SNPRINTF_WTRUNC(buf, size, PV_OBJECT_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), sha);
}

void pv_paths_storage_object_tmp(char *buf, size_t size, const char *id)
{
	SNPRINTF_WTRUNC(buf, size, PV_OBJECT_TMP_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), id);
}

#define PV_TRAILS_PATHF "%s/trails/%s"
#define PV_TRAILS_FILE_PATHF PV_TRAILS_PATHF "/%s"
#define PV_TRAILS_PLAT_FILE_PATHF PV_TRAILS_PATHF "/%s/%s"
#define PV_TRAILS_CONFIG_PATHF PV_TRAILS_PATHF "/_config/%s"
#define PV_TRAILS_PV_PATHF PV_TRAILS_PATHF "/.pv/%s"
#define PV_TRAILS_PVR_PATHF PV_TRAILS_PATHF "/.pvr/%s"

void pv_paths_storage_trail(char *buf, size_t size, const char *rev)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), rev);
}

void pv_paths_storage_trail_file(char *buf, size_t size, const char *rev,
				 const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_FILE_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), rev, name);
}

void pv_paths_storage_trail_plat_file(char *buf, size_t size, const char *rev,
				      const char *plat, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_PLAT_FILE_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), rev, plat,
			name);
}

void pv_paths_storage_trail_config_file(char *buf, size_t size, const char *rev,
					const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_CONFIG_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), rev, name);
}

void pv_paths_storage_trail_pv_file(char *buf, size_t size, const char *rev,
				    const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_PV_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), rev, name);
}

void pv_paths_storage_trail_pvr_file(char *buf, size_t size, const char *rev,
				     const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_PVR_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), rev, name);
}

#define PV_CONFIG_PATHF "%s/config/%s"

void pv_paths_storage_config_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_CONFIG_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), name);
}

#define PV_BOOT_PATHF "%s/boot/%s"

void pv_paths_storage_boot_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_BOOT_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), name);
}

#define PV_STORAGE_DISKS_PATHF "%s/disks/"
#define PV_STORAGE_DISKS_REV_PATHF "%s/disks/rev/%s"
#define PV_STORAGE_DISKS_PERM_FILE_PATHF "%s/disks/perm/%s/%s"
#define PV_STORAGE_DISKS_REV_FILE_PATHF "%s/disks/rev/%s/%s/%s"

void pv_paths_storage_disks(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_DISKS_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT));
}

void pv_paths_storage_disks_rev(char *buf, size_t size, const char *rev)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_DISKS_REV_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), rev);
}

void pv_paths_storage_disks_rev_file(char *buf, size_t size, const char *rev,
				     const char *plat, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_DISKS_REV_FILE_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), rev, plat,
			name);
}

void pv_paths_storage_disks_perm_file(char *buf, size_t size, const char *plat,
				      const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_DISKS_PERM_FILE_PATHF,
			pv_config_get_str(PV_STORAGE_MNTPOINT), plat, name);
}

#define PV_STORAGE_CRYPT_PATHF "%s/pv/%s/%s"
#define PV_CRYPT_DISKS_PERM_FILE_PATHF PV_STORAGE_CRYPT_PATHF "/perm/%s/%s"
#define PV_CRYPT_DISKS_REV_FILE_PATHF PV_STORAGE_CRYPT_PATHF "/rev/%s/%s/%s"
#define PV_CRYPT_DISKS_BOOT_FILE_PATHF PV_STORAGE_CRYPT_PATHF "/boot/%s/%s"

void pv_paths_storage_mounted_disk_path(char *buf, size_t size,
					const char *type, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_CRYPT_PATHF,
			pv_config_get_str(PV_SYSTEM_MEDIADIR), type, name);
}

void pv_paths_crypt_disks_rev_file(char *buf, size_t size, const char *type,
				   const char *dname, const char *rev,
				   const char *plat, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_CRYPT_DISKS_REV_FILE_PATHF,
			pv_config_get_str(PV_SYSTEM_MEDIADIR), type, dname, rev,
			plat, name);
}

void pv_paths_crypt_disks_perm_file(char *buf, size_t size, const char *type,
				    const char *dname, const char *plat,
				    const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_CRYPT_DISKS_PERM_FILE_PATHF,
			pv_config_get_str(PV_SYSTEM_MEDIADIR), type, dname,
			plat, name);
}

void pv_paths_crypt_disks_boot_file(char *buf, size_t size, const char *type,
				    const char *dname, const char *plat,
				    const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_CRYPT_DISKS_BOOT_FILE_PATHF,
			pv_config_get_str(PV_SYSTEM_MEDIADIR), type, dname,
			plat, name);
}

#define PV_ROOT_PATHF "%s"
#define PV_VOLUMES_PATHF "%s/%s"
#define PV_VOLUMES_PLAT_PATHF PV_VOLUMES_PATHF "/%s"

void pv_paths_root_file(char *buf, size_t size, const char *path)
{
	SNPRINTF_WTRUNC(buf, size, PV_ROOT_PATHF, path);
}

void pv_paths_volumes_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_VOLUMES_PATHF,
			pv_config_get_str(PV_DISK_VOLDIR), name);
}

void pv_paths_volumes_plat_file(char *buf, size_t size, const char *plat,
				const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_VOLUMES_PLAT_PATHF,
			pv_config_get_str(PV_DISK_VOLDIR), plat, name);
}

void pv_paths_exports(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_ROOT_PATHF,
			pv_config_get_str(PV_DISK_EXPORTSDIR));
}

void pv_paths_writable(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_ROOT_PATHF,
			pv_config_get_str(PV_DISK_WRITABLEDIR));
}

#define PV_LIB_PLUGIN_PATHF "%s/pv_%s.so"
#define PV_LIB_MODULES_PATHF "%s/modules/%s"
#define PV_LIB_CRYPT_PATHF "%s/pv/volmount/crypt/%s"
#define PV_LIB_VOLMOUNT_PATHF "%s/pv/volmount/%s/%s"
#define PV_LIB_HOOK_PATHF "%s/pv/hooks_lxc-mount.d/%s"
#define PV_LIB_HOOKS_EARLY_SPAWN_PATHF "%s/pv/hooks_early.spawn/%s"
#define PV_LIB_LXC_ROOTFS_MOUNT_PATHF "%s/lib/lxc/rootfs"
#define PV_LIB_LXC_LXCPATH_PATHF "%s/var/lib/lxc"

void pv_paths_lib_plugin(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_PLUGIN_PATHF,
			pv_config_get_str(PV_SYSTEM_LIBDIR), name);
}

void pv_paths_lib_modules(char *buf, size_t size, const char *release)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_MODULES_PATHF,
			pv_config_get_str(PV_SYSTEM_LIBDIR), release);
}

void pv_paths_lib_crypt(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_CRYPT_PATHF,
			pv_config_get_str(PV_SYSTEM_LIBDIR), name);
}

void pv_paths_lib_volmount(char *buf, size_t size, const char *type,
			   const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_VOLMOUNT_PATHF,
			pv_config_get_str(PV_SYSTEM_LIBDIR), type, name);
}

void pv_paths_lib_hook(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_HOOK_PATHF,
			pv_config_get_str(PV_SYSTEM_LIBDIR), name);
}

void pv_paths_lib_hooks_early_spawn(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_HOOKS_EARLY_SPAWN_PATHF,
			pv_config_get_str(PV_SYSTEM_LIBDIR), name);
}

void pv_paths_lib_lxc_rootfs_mount(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_LXC_ROOTFS_MOUNT_PATHF,
			pv_config_get_str(PV_SYSTEM_USRDIR));
}

void pv_paths_lib_lxc_lxcpath(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_LXC_LXCPATH_PATHF,
			pv_config_get_str(PV_SYSTEM_USRDIR));
}

#define PV_ETC_PATHF "%s/%s"
void pv_paths_etc_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_ETC_PATHF,
			pv_config_get_str(PV_SYSTEM_ETCDIR), name);
}

#define PV_ETC_POLICY_PATHF "%s/policies/%s.config"
void pv_paths_etc_policy_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_ETC_POLICY_PATHF,
			pv_config_get_str(PV_SYSTEM_ETCPANTAVISORDIR), name);
}

#define PV_ETC_SSH_PATHF "%s/ssh/%s"
void pv_paths_etc_ssh_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_ETC_SSH_PATHF,
			pv_config_get_str(PV_SYSTEM_ETCPANTAVISORDIR), name);
}

#define PV_CONFIGS_PATHF "%s/%s"

void pv_paths_configs_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_CONFIGS_PATHF,
			pv_config_get_str(PV_SYSTEM_CONFDIR), name);
}

#define PV_CERT_PATHF "%s/%s"

void pv_paths_cert(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_CERT_PATHF,
			pv_config_get_str(PV_LIBTHTTP_CERTSDIR), name);
}

#define PV_TRUST_CERTS_PATHF "%s/%s/%s.crt"

void pv_paths_secureboot_trust_crts(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRUST_CERTS_PATHF,
			pv_config_get_str(PV_SYSTEM_ETCDIR), PVS_TRUST_DNAME,
			name);
}

#define PV_TMP_PATHF "%s.tmp"

void pv_paths_tmp(char *buf, size_t size, const char *path)
{
	SNPRINTF_WTRUNC(buf, size, PV_TMP_PATHF, path);
}
