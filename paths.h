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
#ifndef PV_PATHS_H
#define PV_PATHS_H

#include <stddef.h>

#define ONLINE_FNAME "online"
#define DEVICE_ID_FNAME "device-id"
#define CHALLENGE_FNAME "challenge"
#define PHHOST_FNAME "pantahub-host"
#define PVCTRL_FNAME "pv-ctrl"
#define LOGCTRL_FNAME "pv-ctrl-log"
#define LOGFD_FNAME "pv-fd-log"
#define LOGPUSH_FNAME "pv-push-log"

void pv_paths_pv_file(char *buf, size_t size, const char *name);

#define USRMETA_DNAME "user-meta"
#define SSH_KEY_FNAME "pvr-sdk.authorized_keys"

void pv_paths_pv_usrmeta_key(char *buf, size_t size, const char *key);
void pv_paths_pv_usrmeta_plat_key(char *buf, size_t size, const char *plat,
				  const char *key);

#define DEVMETA_DNAME "device-meta"

void pv_paths_pv_devmeta_key(char *buf, size_t size, const char *key);
void pv_paths_pv_devmeta_plat_key(char *buf, size_t size, const char *plat,
				  const char *key);

#define LOGS_DNAME "logs"
#define LOGS_ERROR_DNAME "error"
#define LXC_LOG_SUBDIR "lxc"
#define LOGS_PV_DNAME "pantavisor"
#define LOGS_PV_FNAME "pantavisor.log"

void pv_paths_pv_log(char *buf, size_t size, const char *rev);
void pv_paths_pv_log_plat(char *buf, size_t size, const char *rev,
			  const char *plat);
void pv_paths_pv_log_file(char *buf, size_t size, const char *rev,
			  const char *plat, const char *name);

void pv_paths_storage(char *buf, size_t size);
void pv_paths_storage_log(char *buf, size_t size);
void pv_paths_storage_usrmeta(char *buf, size_t size);
void pv_paths_storage_devmeta(char *buf, size_t size);
void pv_paths_storage_dropbear(char *buf, size_t size);

#define COREPV_FNAME "corepv"
#define PVMOUNTED_FNAME ".pvmounted"

void pv_paths_storage_file(char *buf, size_t size, const char *name);
void pv_paths_storage_object(char *buf, size_t size, const char *sha);

#define DONE_FNAME "done"
#define PROGRESS_FNAME "progress"
#define COMMITMSG_FNAME "commitmsg"
#define JSON_FNAME "json"
#define CONFIG_FNAME "config"
#define LOGS_FNAME "logs"
#define LOGS_TMP_FNAME "logs.tmp"

void pv_paths_storage_trail(char *buf, size_t size, const char *rev);
void pv_paths_storage_trail_file(char *buf, size_t size, const char *rev,
				 const char *name);
void pv_paths_storage_trail_plat_file(char *buf, size_t size, const char *rev,
				      const char *plat, const char *name);
void pv_paths_storage_trail_config_file(char *buf, size_t size, const char *rev,
					const char *name);
void pv_paths_storage_trail_pv_file(char *buf, size_t size, const char *rev,
				    const char *name);
void pv_paths_storage_trail_pvr_file(char *buf, size_t size, const char *rev,
				     const char *name);

#define UNCLAIMED_FNAME "unclaimed.config"
#define PANTAHUB_FNAME "pantahub.config"

void pv_paths_storage_config_file(char *buf, size_t size, const char *name);

#define GRUBENV_FNAME "grubenv"
#define UBOOTTXT_FNAME "uboot.txt"
#define RPIABTXT_FNAME "rpiab.txt"

void pv_paths_storage_boot_file(char *buf, size_t size, const char *name);

void pv_paths_storage_factory_meta_key(char *buf, size_t size, const char *key);

void pv_paths_storage_disks(char *buf, size_t size);
void pv_paths_storage_disks_rev(char *buf, size_t size, const char *rev);
void pv_paths_storage_disks_rev_file(char *buf, size_t size, const char *rev,
				     const char *plat, const char *name);
void pv_paths_storage_disks_perm_file(char *buf, size_t size, const char *plat,
				      const char *name);
void pv_paths_storage_mounted_disk_path(char *buf, size_t size,
					const char *type, const char *name);
void pv_paths_crypt_disks_rev_file(char *buf, size_t size, const char *type,
				   const char *dname, const char *rev,
				   const char *plat, const char *name);
void pv_paths_crypt_disks_perm_file(char *buf, size_t size, const char *type,
				    const char *dname, const char *plat,
				    const char *name);
void pv_paths_crypt_disks_boot_file(char *buf, size_t size, const char *type,
				    const char *dname, const char *plat,
				    const char *name);

void pv_paths_lib_plugin(char *buf, size_t size, const char *name);
void pv_paths_lib_modules(char *buf, size_t size, const char *release);
void pv_paths_lib_crypt(char *buf, size_t size, const char *name);
void pv_paths_lib_volmount(char *buf, size_t size, const char *type,
			   const char *name);
void pv_paths_lib_hook(char *buf, size_t size, const char *name);
void pv_paths_lib_hooks_early_spawn(char *buf, size_t size, const char *name);
void pv_paths_lib_lxc_rootfs_mount(char *buf, size_t size);
void pv_paths_lib_lxc_lxcpath(char *buf, size_t size);

#define BSP_DNAME "bsp"
#define USRMETAVOL_DNAME "pv--usrmeta"
#define DEVMETAVOL_DNAME "pv--devmeta"

void pv_paths_root_file(char *buf, size_t size, const char *path);
void pv_paths_volumes_file(char *buf, size_t size, const char *name);
void pv_paths_volumes_plat_file(char *buf, size_t size, const char *plat,
				const char *name);
void pv_paths_exports(char *buf, size_t size);
void pv_paths_writable(char *buf, size_t size);

#define PV_PANTAVISOR_CONFIG_PATH "/etc/pantavisor.config"

#define DROPBEAR_DNAME "dropbear"
#define PV_DNAME "pantavisor"
#define PV_DEFAULTS_GROUPS PV_DNAME "/defaults/groups.json"
#define PVS_TRUST_DNAME PV_DNAME "/pvs/trust"
#define PVS_PK_FNAME PVS_TRUST_DNAME "/pub.pem"
#define PVS_CERT_DEFAULT_OEM_STORE "ca-oem-certificates"
#define PVS_CERT_DEFAULT_STORE "ca-certificates"

void pv_paths_etc_file(char *buf, size_t size, const char *name);
void pv_paths_etc_policy_file(char *buf, size_t size, const char *name);
void pv_paths_etc_ssh_file(char *buf, size_t size, const char *name);

void pv_paths_configs_file(char *buf, size_t size, const char *name);

void pv_paths_cert(char *buf, size_t size, const char *name);

void pv_paths_secureboot_trust_crts(char *buf, size_t size, const char *name);

void pv_paths_tmp(char *buf, size_t size, const char *path);

#define PLATFORM_PV_PATH "/pantavisor"
#define PLATFORM_LOGS_PATH PLATFORM_PV_PATH "/" LOGS_DNAME
#define PLATFORM_PVCTRL_SOCKET_PATH PLATFORM_PV_PATH "/" PVCTRL_FNAME
#define PLATFORM_LOG_CTRL_PATH PLATFORM_PV_PATH "/" LOGCTRL_FNAME
#define PLATFORM_USER_META_PATH PLATFORM_PV_PATH "/" USRMETA_DNAME
#define PLATFORM_DEVICE_META_PATH PLATFORM_PV_PATH "/" DEVMETA_DNAME

#endif /* PATHS_H */
