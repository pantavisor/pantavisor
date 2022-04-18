/*
 * Copyright (c) 2022 Pantacor Ltd.
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

#include "paths.h"
#include "utils/str.h"

#define MODULE_NAME             "paths"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define PV_PATH  "/pv"
#define PV_PATHF PV_PATH"/%s"

void pv_paths_pv_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_PATHF, name);
}

#define PV_USRMETA_PATHF      PV_PATH"/"USRMETA_DNAME"/%s"
#define PV_USRMETA_PLAT_PATHF PV_PATH"/user-meta.%s/%s"

void pv_paths_pv_usrmeta_key(char *buf, size_t size, const char *key)
{
	SNPRINTF_WTRUNC(buf, size, PV_USRMETA_PATHF, key);
}

void pv_paths_pv_usrmeta_plat_key(char *buf, size_t size, const char *plat, const char *key)
{
	SNPRINTF_WTRUNC(buf, size, PV_USRMETA_PLAT_PATHF, plat, key);
}

#define PV_LOGS_PATHF      PV_PATH"/"LOGS_DNAME"/%s"
#define PV_LOGS_PLAT_PATHF PV_LOGS_PATHF"/%s"
#define PV_LOGS_FILE_PATHF PV_LOGS_PLAT_PATHF"/%s"

void pv_paths_pv_log(char *buf, size_t size, const char *rev)
{
	SNPRINTF_WTRUNC(buf, size, PV_LOGS_PATHF, rev);
}

void pv_paths_pv_log_plat(char *buf, size_t size, const char *rev, const char *plat)
{
	SNPRINTF_WTRUNC(buf, size, PV_LOGS_PLAT_PATHF, rev, plat);
}

void pv_paths_pv_log_file(char *buf, size_t size, const char *rev, const char *plat, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LOGS_FILE_PATHF, rev, plat, name);
}

#define PV_STORAGE_PATHF "%s"

void pv_paths_storage(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF, pv_config_get_storage_mntpoint());
}

void pv_paths_storage_log(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF, pv_config_get_log_logdir());
}

void pv_paths_storage_meta(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF, pv_config_get_cache_metacachedir());
}

void pv_paths_storage_dropbear(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_PATHF, pv_config_get_cache_dropbearcachedir());
}

#define PV_OBJECT_PATHF     "%s/objects/%s"
#define PV_OBJECT_TMP_PATHF PV_OBJECT_PATHF".tmp"

void pv_paths_storage_object(char *buf, size_t size, const char *sha)
{
	SNPRINTF_WTRUNC(buf, size, PV_OBJECT_PATHF, pv_config_get_storage_mntpoint(), sha);
}

void pv_paths_storage_object_tmp(char *buf, size_t size, const char *sha)
{
	SNPRINTF_WTRUNC(buf, size, PV_OBJECT_TMP_PATHF, pv_config_get_storage_mntpoint(), sha);
}

#define PV_TRAILS_PATHF           "%s/trails/%s/"
#define PV_TRAILS_FILE_PATHF      PV_TRAILS_PATHF"%s"
#define PV_TRAILS_PLAT_FILE_PATHF PV_TRAILS_PATHF"%s/%s"
#define PV_TRAILS_CONFIG_PATHF    PV_TRAILS_PATHF"_config/"
#define PV_TRAILS_PV_PATHF        PV_TRAILS_PATHF".pv/%s"
#define PV_TRAILS_PVR_PATHF       PV_TRAILS_PATHF".pvr/%s"

void pv_paths_storage_trail(char *buf, size_t size, const char *rev)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_PATHF, pv_config_get_storage_mntpoint(), rev);
}

void pv_paths_storage_trail_file(char *buf, size_t size, const char *rev, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_FILE_PATHF, pv_config_get_storage_mntpoint(), rev, name);
}

void pv_paths_storage_trail_plat_file(char *buf, size_t size, const char *rev, const char *plat, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_PLAT_FILE_PATHF, pv_config_get_storage_mntpoint(), rev, plat, name);
}

void pv_paths_storage_trail_config(char *buf, size_t size, const char *rev)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_CONFIG_PATHF, pv_config_get_storage_mntpoint(), rev);
}

void pv_paths_storage_trail_pv_file(char *buf, size_t size, const char *rev, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_PV_PATHF, pv_config_get_storage_mntpoint(), rev, name);
}

void pv_paths_storage_trail_pvr_file(char *buf, size_t size, const char *rev, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_TRAILS_PVR_PATHF, pv_config_get_storage_mntpoint(), rev, name);
}

#define PV_CONFIG_PATHF "%s/config/%s"

void pv_paths_storage_config_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_CONFIG_PATHF, pv_config_get_storage_mntpoint(), name);
}

#define PV_BOOT_PATHF "%s/boot/%s"

void pv_paths_storage_boot_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_BOOT_PATHF, pv_config_get_storage_mntpoint(), name);
}

#define PV_STORAGE_FACTORY_META_PATHF "%s/factory/meta/%s"

void pv_paths_storage_factory_meta_key(char *buf, size_t size, const char *key)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_FACTORY_META_PATHF, pv_config_get_storage_mntpoint(), key);
}

#define PV_STORAGE_DISKS_PATHF           "%s/disks/"
#define PV_STORAGE_DISKS_REV_PATHF       "%s/disks/rev"
#define PV_STORAGE_DISKS_PERM_FILE_PATHF "%s/disks/perm/%s/%s"
#define PV_STORAGE_DISKS_REV_FILE_PATHF  "%s/disks/rev/%s/%s/%s"

void pv_paths_storage_disks(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_DISKS_PATHF, pv_config_get_storage_mntpoint());
}

void pv_paths_storage_disks_rev(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_DISKS_REV_PATHF, pv_config_get_storage_mntpoint());
}

void pv_paths_storage_disks_rev_file(char *buf, size_t size, const char *rev, const char *plat, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_DISKS_REV_FILE_PATHF, pv_config_get_storage_mntpoint(), rev, plat, name);
}

void pv_paths_storage_disks_perm_file(char *buf, size_t size, const char *plat, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_STORAGE_DISKS_PERM_FILE_PATHF, pv_config_get_storage_mntpoint(), plat, name);
}

#define PV_ROOT_PATHF         "%s"
#define PV_VOLUMES_PATHF      "/volumes/%s"
#define PV_VOLUMES_PLAT_PATHF PV_VOLUMES_PATHF"/%s"

void pv_paths_root_file(char *buf, size_t size, const char *path)
{
	SNPRINTF_WTRUNC(buf, size, PV_ROOT_PATHF, path);
}

void pv_paths_volumes_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_VOLUMES_PATHF, name);
}

void pv_paths_volumes_plat_file(char *buf, size_t size, const char *plat, const char *name){
	SNPRINTF_WTRUNC(buf, size, PV_VOLUMES_PLAT_PATHF, plat, name);
}

#define PV_LIB_PLUGIN_PATHF   "/lib/pv_%s.so"
#define PV_LIB_MODULES_PATHF  "/lib/modules/%s"
#define PV_LIB_VOLMOUNT_PATHF "/lib/pv/volmount/%s"
#define PV_LIB_HOOK_PATHF     "/lib/pv/hooks_lxc-mount.d/%s"

void pv_paths_lib_plugin(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_PLUGIN_PATHF, name);
}

void pv_paths_lib_modules(char *buf, size_t size, const char *release)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_MODULES_PATHF, release);
}

void pv_paths_lib_volmount(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_VOLMOUNT_PATHF, name);
}

void pv_paths_lib_hook(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_LIB_HOOK_PATHF, name);
}

#define PV_CONFIG_PANTAVISOR_PATHF "/etc/pantavisor.config"

void pv_paths_etc_pantavisor(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_CONFIG_PANTAVISOR_PATHF);
}

#define PV_ETC_PATHF "/etc/%s"

void pv_paths_etc_file(char *buf, size_t size, const char *name)
{
	SNPRINTF_WTRUNC(buf, size, PV_ETC_PATHF, name);
}

#define PV_CONFIGS_PATHF "/configs/"

void pv_paths_configs(char *buf, size_t size)
{
	SNPRINTF_WTRUNC(buf, size, PV_CONFIGS_PATHF);
}

#define PV_CERT_PATHF "/certs/%s"

void pv_paths_cert(char *buf, size_t size, const char* name)
{
	SNPRINTF_WTRUNC(buf, size, PV_CERT_PATHF, name);
}
