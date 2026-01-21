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

#ifndef PV_CONFIG_H
#define PV_CONFIG_H

#include <stdbool.h>

#include "utils/list.h"

// GENERIC

typedef enum {
	PH_CREDS_HOST,
	PH_CREDS_ID,
	PH_CREDS_PORT,
	PH_CREDS_PROXY_HOST,
	PH_CREDS_PROXY_NOPROXYCONNECT,
	PH_CREDS_PROXY_PORT,
	PH_CREDS_PRN,
	PH_CREDS_SECRET,
	PH_CREDS_TYPE,
	PH_FACTORY_AUTOTOK,
	PH_LIBEVENT_HTTP_TIMEOUT,
	PH_LIBEVENT_HTTP_RETRIES,
	PH_METADATA_DEVMETA_INTERVAL,
	PH_METADATA_USRMETA_INTERVAL,
	PH_ONLINE_REQUEST_THRESHOLD,
	PH_UPDATER_INTERVAL,
	PH_UPDATER_NETWORK_TIMEOUT,
	PH_UPDATER_TRANSFER_MAX_COUNT,
	PV_BOOTLOADER_FITCONFIG,
	PV_BOOTLOADER_MTD_ENV,
	PV_BOOTLOADER_MTD_ONLY,
	PV_BOOTLOADER_TYPE,
	PV_BOOTLOADER_UBOOTAB_A_NAME,
	PV_BOOTLOADER_UBOOTAB_B_NAME,
	PV_BOOTLOADER_UBOOTAB_ENV_NAME,
	PV_BOOTLOADER_UBOOTAB_ENV_BAK_NAME,
	PV_BOOTLOADER_UBOOTAB_ENV_OFFSET,
	PV_BOOTLOADER_UBOOTAB_ENV_SIZE,
	PV_CACHE_DEVMETADIR,
	PV_CACHE_USRMETADIR,
	PV_CONTROL_REMOTE,
	PV_CONTROL_REMOTE_ALWAYS,
	PV_DEBUG_SHELL,
	PV_DEBUG_SHELL_AUTOLOGIN,
	PV_DEBUG_SHELL_TIMEOUT,
	PV_DEBUG_SSH,
	PV_DEBUG_SSH_AUTHORIZED_KEYS,
	PV_DISK_EXPORTSDIR,
	PV_DISK_VOLDIR,
	PV_DISK_WRITABLEDIR,
	PV_DROPBEAR_CACHE_DIR,
	PV_LIBEVENT_DEBUG_MODE,
	PV_LIBTHTTP_CERTSDIR,
	PV_LIBTHTTP_LOG_LEVEL,
	PV_LOG_CAPTURE,
	PV_LOG_CAPTURE_DMESG,
	PV_LOG_BUF_NITEMS,
	PV_LOG_DIR,
	PV_LOG_FILETREE_TIMESTAMP_FORMAT,
	PV_LOG_LEVEL,
	PV_LOG_LOGGERS,
	PV_LOG_MAXSIZE,
	PV_LOG_PUSH,
	PV_LOG_SERVER_OUTPUTS,
	PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT,
	PV_LOG_STDOUT_TIMESTAMP_FORMAT,
	PV_LXC_LOG_LEVEL,
	PV_NET_BRADDRESS4,
	PV_NET_BRDEV,
	PV_NET_BRMASK4,
	PV_OEM_NAME,
	PV_POLICY,
	PV_REVISION_RETRIES,
	PV_SECUREBOOT_CHECKSUM,
	PV_SECUREBOOT_HANDLERS,
	PV_SECUREBOOT_MODE,
	PV_SECUREBOOT_OEM_TRUSTSTORE,
	PV_SECUREBOOT_TRUSTSTORE,
	PV_STORAGE_DEVICE,
	PV_STORAGE_FSTYPE,
	PV_STORAGE_GC_KEEP_FACTORY,
	PV_STORAGE_GC_RESERVED,
	PV_STORAGE_GC_THRESHOLD_DEFERTIME,
	PV_STORAGE_GC_THRESHOLD,
	PV_STORAGE_LOGTEMPSIZE,
	PV_STORAGE_MNTPOINT,
	PV_STORAGE_MNTTYPE,
	PV_STORAGE_PHCONFIG_VOL,
	PV_STORAGE_WAIT,
	PV_SYSTEM_APPARMOR_PROFILES,
	PV_SYSTEM_CONFDIR,
	PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO,
	PV_SYSTEM_ETCDIR,
	PV_SYSTEM_ETCPANTAVISORDIR,
	PV_SYSTEM_INIT_MODE,
	PV_SYSTEM_LIBDIR,
	PV_SYSTEM_MEDIADIR,
	PV_SYSTEM_MOUNT_SECURITYFS,
	PV_SYSTEM_RUNDIR,
	PV_SYSTEM_USRDIR,
	PV_UPDATER_COMMIT_DELAY,
	PV_UPDATER_GOALS_TIMEOUT,
	PV_UPDATER_USE_TMP_OBJECTS,
	PV_VOLMOUNT_DM_EXTRA_ARGS,
	PV_WDT_MODE,
	PV_WDT_TIMEOUT,
	PV_MAX
} config_index_t;

bool pv_config_get_bool(config_index_t ci);
int pv_config_get_int(config_index_t ci);
char *pv_config_get_str(config_index_t ci);

// BOOTLOADER TYPE

typedef enum {
	BL_UBOOT_PLAIN = 0,
	BL_UBOOT_PVK,
	BL_GRUB,
	BL_RPIAB,
	BL_UBOOT_AB
} bootloader_t;

bootloader_t pv_config_get_bootloader_type(void);
char *pv_config_get_bootloader_type_str(void);

// CREDS

void pv_config_set_creds_id(char *id);
void pv_config_set_creds_prn(char *prn);
void pv_config_set_creds_secret(char *secret);

// DEBUG

void pv_config_set_debug_shell(bool shell);
void pv_config_set_debug_shell_autologin(bool autologin);
void pv_config_set_debug_ssh(bool ssh);

// LOG SERVER OUTPUTS

typedef enum {
	LOG_SERVER_OUTPUT_NULL_SINK = 1 << 0,
	LOG_SERVER_OUTPUT_SINGLE_FILE = 1 << 1,
	LOG_SERVER_OUTPUT_FILE_TREE = 1 << 2,
	LOG_SERVER_OUTPUT_STDOUT = 1 << 3,
	LOG_SERVER_OUTPUT_STDOUT_CONTAINERS = 1 << 4,
	LOG_SERVER_OUTPUT_STDOUT_PANTAVISOR = 1 << 5,
	LOG_SERVER_OUTPUT_STDOUT_DIRECT = 1 << 6,
	LOG_SERVER_OUTPUT_UPDATE = 1 << 7,
} log_server_output_mask_t;

log_server_output_mask_t pv_config_get_log_server_outputs(void);

// SECUREBOOT MODE

typedef enum {
	SB_DISABLED,
	SB_AUDIT,
	SB_LENIENT,
	SB_STRICT,
} secureboot_mode_t;

secureboot_mode_t pv_config_get_secureboot_mode(void);
char *pv_config_get_secureboot_mode_str(void);

// SYSTEM INIT MODE

typedef enum { IM_EMBEDDED, IM_STANDALONE, IM_APPENGINE } init_mode_t;

init_mode_t pv_config_get_system_init_mode(void);
char *pv_config_get_system_init_mode_str(void);
void pv_config_set_system_init_mode(init_mode_t mode);

// WATCHDOG MODE

typedef enum {
	WDT_DISABLED,
	WDT_SHUTDOWN,
	WDT_STARTUP,
	WDT_ALWAYS,
} wdt_mode_t;

wdt_mode_t pv_config_get_wdt_mode(void);
char *pv_config_get_wdt_mode_str(void);

// MAIN FUNCTIONS

int pv_config_init(char *path);

void pv_config_save_devmeta(void);

int pv_config_load_update(const char *rev, const char *trail_config);

int pv_config_load_creds(void);
int pv_config_load_unclaimed_creds(void);
int pv_config_save_creds(void);
int pv_config_unload_creds(void);

void pv_config_override_value(const char *key, const char *value);

void pv_config_free(void);

char *pv_config_get_legacy_json(void);
char *pv_config_get_complete_json(void);
void pv_config_print(void);

#endif
