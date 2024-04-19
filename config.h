/*
 * Copyright (c) 2017-2024 Pantacor Ltd.
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
	CI_BOOTLOADER_FITCONFIG,
	CI_BOOTLOADER_MTD_ENV,
	CI_BOOTLOADER_MTD_ONLY,
	CI_BOOTLOADER_TYPE,
	CI_CACHE_DEVMETADIR,
	CI_CACHE_USRMETADIR,
	CI_CONTROL_REMOTE,
	CI_CONTROL_REMOTE_ALWAYS,
	CI_CREDS_HOST,
	CI_CREDS_ID,
	CI_CREDS_PORT,
	CI_CREDS_PROXY_HOST,
	CI_CREDS_PROXY_NOPROXYCONNECT,
	CI_CREDS_PROXY_PORT,
	CI_CREDS_PRN,
	CI_CREDS_SECRET,
	CI_CREDS_TPM_CERT,
	CI_CREDS_TPM_KEY,
	CI_CREDS_TYPE,
	CI_DEBUG_SHELL,
	CI_DEBUG_SHELL_AUTOLOGIN,
	CI_DEBUG_SSH,
	CI_DEBUG_SSH_AUTHORIZED_KEYS,
	CI_DISK_EXPORTSDIR,
	CI_DISK_VOLDIR,
	CI_DISK_WRITABLEDIR,
	CI_DROPBEAR_CACHE_DIR,
	CI_FACTORY_AUTOTOK,
	CI_LIBTHTTP_CERTDIR,
	CI_LIBTHTTP_LOG_LEVEL,
	CI_LOG_CAPTURE,
	CI_LOG_CAPTURE_DMESG,
	CI_LOG_BUF_NITEMS,
	CI_LOG_DIR,
	CI_LOG_FILETREE_TS_FMT,
	CI_LOG_LEVEL,
	CI_LOG_LOGGERS,
	CI_LOG_MAXSIZE,
	CI_LOG_PUSH,
	CI_LOG_SERVER_OUTPUTS,
	CI_LOG_SINGLEFILE_TS_FMT,
	CI_LOG_STDOUT,
	CI_LOG_STDOUT_TS_FMT,
	CI_LXC_LOG_LEVEL,
	CI_METADATA_DEVMETA_INTERVAL,
	CI_METADATA_USRMETA_INTERVAL,
	CI_NET_BRADDRESS4,
	CI_NET_BRDEV,
	CI_NET_BRMASK4,
	CI_POLICY,
	CI_REVISION_RETRIES,
	CI_REVISION_RETRIES_TIMEOUT,
	CI_SECUREBOOT_CHECKSUM,
	CI_SECUREBOOT_HANDLERS,
	CI_SECUREBOOT_MODE,
	CI_SECUREBOOT_TRUSTSTORE,
	CI_STORAGE_DEVICE,
	CI_STORAGE_FSTYPE,
	CI_STORAGE_GC_KEEP_FACTORY,
	CI_STORAGE_GC_RESERVED,
	CI_STORAGE_GC_THRESHOLD_DEFERTIME,
	CI_STORAGE_GC_THRESHOLD,
	CI_STORAGE_LOGTEMPSIZE,
	CI_STORAGE_MNTPOINT,
	CI_STORAGE_MNTTYPE,
	CI_STORAGE_OPTS,
	CI_STORAGE_WAIT,
	CI_SYSTEM_APPARMOR_PROFILES,
	CI_SYSTEM_CONFDIR,
	CI_SYSTEM_DRIVERS_LOAD_EARLY_AUTO,
	CI_SYSTEM_ETCDIR,
	CI_SYSTEM_INIT_MODE,
	CI_SYSTEM_LIBDIR,
	CI_SYSTEM_MEDIADIR,
	CI_SYSTEM_MOUNT_SECURITYFS,
	CI_SYSTEM_RUNDIR,
	CI_SYSTEM_USRDIR,
	CI_UPDATER_COMMIT_DELAY,
	CI_UPDATER_GOALS_TIMEOUT,
	CI_UPDATER_INTERVAL,
	CI_UPDATER_NETWORK_TIMEOUT,
	CI_UPDATER_USE_TMP_OBJECTS,
	CI_WDT_ENABLED,
	CI_WDT_MODE,
	CI_WDT_TIMEOUT,
	CI_MAX
} config_index_t;

bool pv_config_get_bool(config_index_t ci);
int pv_config_get_int(config_index_t ci);
char *pv_config_get_str(config_index_t ci);

// BOOTLOADER TYPE

typedef enum {
	BL_UBOOT_PLAIN = 0,
	BL_UBOOT_PVK,
	BL_GRUB,
	BL_RPIAB
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

int pv_config_load_unclaimed_creds(void);
int pv_config_save_creds(void);

void pv_config_override_value(const char *key, const char *value);

void pv_config_free(void);

char *pv_config_get_json(void);
void pv_config_print(void);

#endif
