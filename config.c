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

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <sys/stat.h>

#include <linux/limits.h>

#include "config.h"
#include "init.h"
#include "config_parser.h"
#include "bootloader.h"
#include "state.h"
#include "storage.h"
#include "paths.h"
#include "parser/parser.h"
#include "utils/fs.h"
#include "utils/str.h"
#include "utils/math.h"
#include "utils/json.h"

#define MODULE_NAME "config"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

typedef enum {
	BOOL,
	BOOTLOADER,
	INIT_MODE,
	INT,
	LOG_SERVER_OUTPUT_UPDATE_MASK,
	SB_MODE,
	STR,
	WDT_MODE
} type_t;

typedef enum {
	DEFAULT = 0,
	ARGS = 1 << 0,
	PV_CONF = 1 << 1,
	PH_CONF = 1 << 2,
	PH_CLIENT = 1 << 3,
	POLICY = 1 << 4,
	PV_CMDLINE = 1 << 5,
	PH_CMDLINE = 1 << 6,
	ENV = 1 << 7,
	OEM = 1 << 8,
	META = 1 << 9,
	CMD = 1 << 10
} level_t;

#define PV PV_CONF | POLICY | PV_CMDLINE | ENV
#define PH PH_CONF | POLICY | PH_CMDLINE | ENV
#define RUN META | CMD

#define LEVEL_SYSCTL PV | OEM

// default list
#define CACHE_DEVMETADIR_DEF "/storage/cache/devmeta"
#define CACHE_USRMETADIR_DEF "/storage/cache/meta"
#define CREDS_HOST_DEF "192.168.53.1"
#define CREDS_TYPE_DEF "builtin"
#define DISK_EXPORTSDIR_DEF "/exports"
#define DISK_VOLDIR_DEF "/volumes"
#define DISK_WRITABLEDIR_DEF "/writable"
#define DROPBEAR_CACHE_DIR_DEF "/storage/cache/dropbear"
#define LIBTHTTP_CERTSDIR_DEF "/certs"
#define LOG_DIR_DEF "/storage/logs/"
#define LOG_MAXSIZE_DEF (1 << 21) // 2MiB
#define LOG_SERVER_OUTPUTS_DEF "filetree"
#define NET_BRADDRESS4_DEF "10.0.3.1"
#define NET_BRDEV_DEF "lxcbr0"
#define NET_BRMASK4_DEF "255.255.255.0"
#define SECUREBOOT_OEM_TRUSTSTORE_DEF PVS_CERT_DEFAULT_OEM_STORE
#define SECUREBOOT_TRUSTSTORE_DEF PVS_CERT_DEFAULT_STORE
#define SYSTEM_CONFDIR_DEF "/configs"
#define SYSTEM_ETCDIR_DEF "/etc"
#define SYSTEM_LIBDIR_DEF "/lib"
#define SYSTEM_MEDIADIR_DEF "/media"
#define SYSTEM_RUNDIR_DEF "/pv"
#define SYSTEM_USRDIR_DEF "/usr"

struct pv_config_entry {
	type_t type;
	const char *key;
	level_t allowed;
	level_t modified;
	struct {
		bool b;
		int i;
		char *s;
	} value;
};

// configuration lookup table
static struct pv_config_entry entries[] = {
	{ STR, "PH_CREDS_HOST", PH | OEM, 0, .value.s = CREDS_HOST_DEF },
	{ STR, "PH_CREDS_ID", PH | OEM, 0, .value.s = NULL },
	{ INT, "PH_CREDS_PORT", PH | OEM, 0, .value.i = 12365 },
	{ STR, "PH_CREDS_PROXY_HOST", PH | OEM, 0, .value.s = NULL },
	{ INT, "PH_CREDS_PROXY_NOPROXYCONNECT", PH | OEM, 0, .value.i = 0 },
	{ INT, "PH_CREDS_PROXY_PORT", PH | OEM, 0, .value.i = 3218 },
	{ STR, "PH_CREDS_PRN", PH | OEM, 0, .value.s = NULL },
	{ STR, "PH_CREDS_SECRET", PH | OEM, 0, .value.s = NULL },
	{ STR, "PH_CREDS_TYPE", PH | OEM, 0, .value.s = CREDS_TYPE_DEF },
	{ STR, "PH_FACTORY_AUTOTOK", PH | OEM, 0, .value.s = NULL },
	{ INT, "PH_METADATA_DEVMETA_INTERVAL", PH | OEM | RUN, 0,
	  .value.i = 10 },
	{ INT, "PH_METADATA_USRMETA_INTERVAL", PH | OEM | RUN, 0,
	  .value.i = 5 },
	{ INT, "PH_UPDATER_INTERVAL", PH | OEM | RUN, 0, .value.i = 60 },
	{ INT, "PH_UPDATER_NETWORK_TIMEOUT", PH | OEM | RUN, 0,
	  .value.i = 120 },
	{ STR, "PV_BOOTLOADER_FITCONFIG", PV, 0, .value.s = NULL },
	{ STR, "PV_BOOTLOADER_MTD_ENV", PV, 0, .value.s = NULL },
	{ BOOL, "PV_BOOTLOADER_MTD_ONLY", PV, 0, .value.b = false },
	{ BOOTLOADER, "PV_BOOTLOADER_TYPE", PV, 0, .value.i = BL_UBOOT_PLAIN },
	{ STR, "PV_CACHE_DEVMETADIR", PV, 0, .value.s = CACHE_DEVMETADIR_DEF },
	{ STR, "PV_CACHE_USRMETADIR", PV, 0, .value.s = CACHE_USRMETADIR_DEF },
	{ BOOL, "PV_CONTROL_REMOTE", PV | OEM, 0, .value.b = true },
	{ BOOL, "PV_CONTROL_REMOTE_ALWAYS", PV | OEM, 0, .value.b = false },
	{ BOOL, "PV_DEBUG_SHELL", PV, 0, .value.b = true },
	{ BOOL, "PV_DEBUG_SHELL_AUTOLOGIN", PV, 0, .value.b = false },
	{ BOOL, "PV_DEBUG_SSH", PV | OEM | RUN, 0, .value.b = true },
	{ STR, "PV_DEBUG_SSH_AUTHORIZED_KEYS", PV | OEM | RUN, 0,
	  .value.s = NULL },
	{ STR, "PV_DISK_EXPORTSDIR", PV, 0, .value.s = DISK_EXPORTSDIR_DEF },
	{ STR, "PV_DISK_VOLDIR", PV, 0, .value.s = DISK_VOLDIR_DEF },
	{ STR, "PV_DISK_WRITABLEDIR", PV, 0, .value.s = DISK_WRITABLEDIR_DEF },
	{ STR, "PV_DROPBEAR_CACHE_DIR", PV, 0,
	  .value.s = DROPBEAR_CACHE_DIR_DEF },
	{ STR, "PV_LIBTHTTP_CERTSDIR", PV, 0,
	  .value.s = LIBTHTTP_CERTSDIR_DEF },
	{ INT, "PV_LIBTHTTP_LOG_LEVEL", PV | OEM | RUN, 0, .value.i = 3 },
	{ BOOL, "PV_LOG_CAPTURE", PV | OEM, 0, .value.b = true },
	{ BOOL, "PV_LOG_CAPTURE_DMESG", PV | OEM, 0, .value.b = true },
	{ INT, "PV_LOG_BUF_NITEMS", PV | OEM, 0, .value.i = 128 },
	{ STR, "PV_LOG_DIR", PV, 0, .value.s = LOG_DIR_DEF },
	{ STR, "PV_LOG_FILETREE_TIMESTAMP_FORMAT", PV | OEM | RUN, 0,
	  .value.s = NULL },
	{ INT, "PV_LOG_LEVEL", PV | OEM | RUN, 0, .value.i = 0 },
	{ BOOL, "PV_LOG_LOGGERS", PV | OEM, 0, .value.b = true },
	{ INT, "PV_LOG_MAXSIZE", PV | OEM | RUN, 0,
	  .value.i = LOG_MAXSIZE_DEF },
	{ BOOL, "PV_LOG_PUSH", PV | OEM | RUN, 0, .value.b = true },
	{ LOG_SERVER_OUTPUT_UPDATE_MASK, "PV_LOG_SERVER_OUTPUTS",
	  PV | OEM | RUN, 0,
	  .value.i = LOG_SERVER_OUTPUT_FILE_TREE | LOG_SERVER_OUTPUT_UPDATE },
	{ STR, "PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT", PV | OEM | RUN, 0,
	  .value.s = NULL },
	{ STR, "PV_LOG_STDOUT_TIMESTAMP_FORMAT", PV | OEM | RUN, 0,
	  .value.s = NULL },
	{ INT, "PV_LXC_LOG_LEVEL", PV | OEM, 0, .value.i = 2 },
	{ STR, "PV_NET_BRADDRESS4", PV | OEM, 0,
	  .value.s = NET_BRADDRESS4_DEF },
	{ STR, "PV_NET_BRDEV", PV | OEM, 0, .value.s = NET_BRDEV_DEF },
	{ STR, "PV_NET_BRMASK4", PV | OEM, 0, .value.s = NET_BRMASK4_DEF },
	{ STR, "PV_OEM_NAME", PV, 0, .value.s = NULL },
	{ STR, "PV_POLICY", PV, 0, .value.s = NULL },
	{ INT, "PV_REVISION_RETRIES", PV | OEM | RUN, 0, .value.i = 10 },
	{ BOOL, "PV_SECUREBOOT_CHECKSUM", PV, 0, .value.b = true },
	{ BOOL, "PV_SECUREBOOT_HANDLERS", PV, 0, .value.b = true },
	{ SB_MODE, "PV_SECUREBOOT_MODE", PV, 0, .value.i = SB_LENIENT },
	{ STR, "PV_SECUREBOOT_OEM_TRUSTORE", PV, 0,
	  .value.s = SECUREBOOT_OEM_TRUSTSTORE_DEF },
	{ STR, "PV_SECUREBOOT_TRUSTSTORE", PV, 0,
	  .value.s = SECUREBOOT_TRUSTSTORE_DEF },
	{ STR, "PV_STORAGE_DEVICE", PV, 0, .value.s = NULL },
	{ STR, "PV_STORAGE_FSTYPE", PV, 0, .value.s = NULL },
	{ BOOL, "PV_STORAGE_GC_KEEP_FACTORY", PV | OEM | RUN, 0,
	  .value.b = false },
	{ INT, "PV_STORAGE_GC_RESERVED", PV | OEM | RUN, 0, .value.i = 5 },
	{ INT, "PV_STORAGE_GC_THRESHOLD_DEFERTIME", PV | OEM | RUN, 0,
	  .value.i = 600 },
	{ INT, "PV_STORAGE_GC_THRESHOLD", PV | OEM | RUN, 0, .value.i = 0 },
	{ STR, "PV_STORAGE_LOGTEMPSIZE", PV, 0, .value.s = NULL },
	{ STR, "PV_STORAGE_MNTPOINT", PV, 0, .value.s = NULL },
	{ STR, "PV_STORAGE_MNTTYPE", PV, 0, .value.s = NULL },
	{ INT, "PV_STORAGE_WAIT", PV, 0, .value.i = 5 },
	{ STR, "PV_SYSTEM_APPARMOR_PROFILES", PV, 0, .value.s = NULL },
	{ STR, "PV_SYSTEM_CONFDIR", PV, 0, .value.s = SYSTEM_CONFDIR_DEF },
	{ BOOL, "PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO", PV, 0, .value.b = false },
	{ STR, "PV_SYSTEM_ETCDIR", PV, 0, .value.s = SYSTEM_ETCDIR_DEF },
	{ INIT_MODE, "PV_SYSTEM_INIT_MODE", PV, 0, .value.i = IM_EMBEDDED },
	{ STR, "PV_SYSTEM_LIBDIR", PV, 0, .value.s = SYSTEM_LIBDIR_DEF },
	{ STR, "PV_SYSTEM_MEDIADIR", PV, 0, .value.s = SYSTEM_MEDIADIR_DEF },
	{ BOOL, "PV_SYSTEM_MOUNT_SECURITYFS", PV, 0, .value.b = false },
	{ STR, "PV_SYSTEM_RUNDIR", PV, 0, .value.s = SYSTEM_RUNDIR_DEF },
	{ STR, "PV_SYSTEM_USRDIR", PV, 0, .value.s = SYSTEM_USRDIR_DEF },
	{ INT, "PV_UPDATER_COMMIT_DELAY", PV | OEM | RUN, 0, .value.i = 25 },
	{ INT, "PV_UPDATER_GOALS_TIMEOUT", PV | OEM | RUN, 0, .value.i = 120 },
	{ BOOL, "PV_UPDATER_USE_TMP_OBJECTS", PV | OEM | RUN, 0,
	  .value.b = false },
	{ WDT_MODE, "PV_WDT_MODE", PV, 0, .value.i = WDT_SHUTDOWN },
	{ INT, "PV_WDT_TIMEOUT", PV, 0, .value.i = 15 }
};

struct pv_config_alias {
	char *alias;
	char *key;
};

static struct pv_config_alias aliases[] = {
	// LEGACY CONFIG KEY
	{ "creds.host", "PH_CREDS_HOST" },
	{ "creds.id", "PH_CREDS_ID" },
	{ "creds.port", "PH_CREDS_PORT" },
	{ "creds.proxy.host", "PH_CREDS_PROXY_HOST" },
	{ "creds.proxy.noproxyconnect", "PH_CREDS_PROXY_NOPROXYCONNECT" },
	{ "creds.proxy.port", "PH_CREDS_PROXY_PORT" },
	{ "creds.prn", "PH_CREDS_PRN" },
	{ "creds.secret", "PH_CREDS_SECRET" },
	{ "creds.type", "PH_CREDS_TYPE" },
	{ "factory.autotok", "PH_FACTORY_AUTOTOK" },
	{ "metadata.devmeta.interval", "PH_METADATA_DEVMETA_INTERVAL" },
	{ "metadata.usrmeta.interval", "PH_METADATA_USRMETA_INTERVAL" },
	{ "updater.interval", "PH_UPDATER_INTERVAL" },
	{ "updater.network_timeout", "PH_UPDATER_NETWORK_TIMEOUT" },
	{ "bootloader.fitconfig", "PV_BOOTLOADER_FITCONFIG" },
	{ "bootloader.mtd_env", "PV_BOOTLOADER_MTD_ENV" },
	{ "bootloader.mtd_only", "PV_BOOTLOADER_MTD_ONLY" },
	{ "bootloader.type", "PV_BOOTLOADER_TYPE" },
	{ "cache.devmetadir", "PV_CACHE_DEVMETADIR" },
	{ "cache.usrmetadir", "PV_CACHE_USRMETADIR" },
	{ "control.remote", "PV_CONTROL_REMOTE" },
	{ "control.remote.always", "PV_CONTROL_REMOTE_ALWAYS" },
	{ "debug.shell", "PV_DEBUG_SHELL" },
	{ "debug.shell.autologin", "PV_DEBUG_SHELL_AUTOLOGIN" },
	{ "debug.ssh", "PV_DEBUG_SSH" },
	{ "debug.ssh_authorized_keys", "PV_DEBUG_SSH_AUTHORIZED_KEYS" },
	{ "disk.exportsdir", "PV_DISK_EXPORTSDIR" },
	{ "disk.voldir", "PV_DISK_VOLDIR" },
	{ "disk.writabledir", "PV_DISK_WRITABLEDIR" },
	{ "dropbear.cache.dir", "PV_DROPBEAR_CACHE_DIR" },
	{ "libthttp.certdir", "PV_LIBTHTTP_CERTSDIR" },
	{ "libthttp.log.level", "PV_LIBTHTTP_LOG_LEVEL" },
	{ "log.capture", "PV_LOG_CAPTURE" },
	{ "log.capture.dmesg", "PV_LOG_CAPTURE_DMESG" },
	{ "log.buf_nitems", "PV_LOG_BUF_NITEMS" },
	{ "log.dir", "PV_LOG_DIR" },
	{ "log.filetree.timestamp.format", "PV_LOG_FILETREE_TIMESTAMP_FORMAT" },
	{ "log.level", "PV_LOG_LEVEL" },
	{ "log.loggers", "PV_LOG_LOGGERS" },
	{ "log.maxsize", "PV_LOG_MAXSIZE" },
	{ "log.push", "PV_LOG_PUSH" },
	{ "log.server.outputs", "PV_LOG_SERVER_OUTPUTS" },
	{ "log.singlefile.timestamp.format",
	  "PV_LOG_SINGLEFILE_TIMESTAMP_FORMAT" },
	{ "log.stdout.timestamp.format", "PV_LOG_STDOUT_TIMESTAMP_FORMAT" },
	{ "lxc.log.level", "PV_LXC_LOG_LEVEL" },
	{ "net.braddress4", "PV_NET_BRADDRESS4" },
	{ "net.brdev", "PV_NET_BRDEV" },
	{ "net.brmask4", "PV_NET_BRMASK4" },
	{ "policy", "PV_POLICY" },
	{ "revision.retries", "PV_REVISION_RETRIES" },
	{ "secureboot.checksum", "PV_SECUREBOOT_CHECKSUM" },
	{ "secureboot.handlers", "PV_SECUREBOOT_HANDLERS" },
	{ "secureboot.mode", "PV_SECUREBOOT_MODE" },
	{ "secureboot.truststore", "PV_SECUREBOOT_TRUSTSTORE" },
	{ "storage.device", "PV_STORAGE_DEVICE" },
	{ "storage.fstype", "PV_STORAGE_FSTYPE" },
	{ "storage.gc.keep_factory", "PV_STORAGE_GC_KEEP_FACTORY" },
	{ "storage.gc.reserved", "PV_STORAGE_GC_RESERVED" },
	{ "storage.gc.threshold.defertime",
	  "PV_STORAGE_GC_THRESHOLD_DEFERTIME" },
	{ "storage.gc.threshold", "PV_STORAGE_GC_THRESHOLD" },
	{ "storage.logtempsize", "PV_STORAGE_LOGTEMPSIZE" },
	{ "storage.mntpoint", "PV_STORAGE_MNTPOINT" },
	{ "storage.mnttype", "PV_STORAGE_MNTTYPE" },
	{ "storage.wait", "PV_STORAGE_WAIT" },
	{ "system.apparmor.profiles", "PV_SYSTEM_APPARMOR_PROFILES" },
	{ "system.confdir", "PV_SYSTEM_CONFDIR" },
	{ "system.drivers.load_early.auto",
	  "PV_SYSTEM_DRIVERS_LOAD_EARLY_AUTO" },
	{ "system.etcdir", "PV_SYSTEM_ETCDIR" },
	{ "system.init.mode", "PV_SYSTEM_INIT_MODE" },
	{ "system.libdir", "PV_SYSTEM_LIBDIR" },
	{ "system.mediadir", "PV_SYSTEM_MEDIADIR" },
	{ "system.mount.securityfs", "PV_SYSTEM_MOUNT_SECURITYFS" },
	{ "system.rundir", "PV_SYSTEM_RUNDIR" },
	{ "system.usrdir", "PV_SYSTEM_USRDIR" },
	{ "updater.commit.delay", "PV_UPDATER_COMMIT_DELAY" },
	{ "updater.goals.timeout", "PV_UPDATER_GOALS_TIMEOUT" },
	{ "updater.use_tmp_objects", "PV_UPDATER_USE_TMP_OBJECTS" },
	{ "wdt.mode", "PV_WDT_MODE" },
	{ "wdt.timeout", "PV_WDT_TIMEOUT" },
	// OTHER COMPATIBLE KEYS
	{ "meta.cache.dir", "PV_CACHE_USRMETADIR" },
	{ "pantahub.log.push", "PV_LOG_PUSH" },
	{ "updater.keep_factory", "PV_STORAGE_GC_KEEP_FACTORY" }
};

bool pv_config_get_bool(config_index_t ci)
{
	return entries[ci].value.b;
}

static void _set_config_by_entry_bool(struct pv_config_entry *entry, bool value)
{
	if (!entry)
		return;

	entry->value.b = value;
}

static void _set_config_by_index_bool(config_index_t ci, bool value,
				      level_t modified)
{
	entries[ci].modified = modified;
	_set_config_by_entry_bool(&entries[ci], value);
}

int pv_config_get_int(config_index_t ci)
{
	return entries[ci].value.i;
}

static void _set_config_by_entry_int(struct pv_config_entry *entry, int value)
{
	if (!entry)
		return;

	entry->value.i = value;
}

char *pv_config_get_str(config_index_t ci)
{
	return entries[ci].value.s;
}

static void _set_config_by_entry_str(struct pv_config_entry *entry,
				     const char *value)
{
	if (!entry)
		return;

	if (entry->value.s)
		free(entry->value.s);
	entry->value.s = strdup(value);
}

static void _set_config_by_index_str(config_index_t ci, const char *value,
				     level_t modified)
{
	entries[ci].modified = modified;
	_set_config_by_entry_str(&entries[ci], value);
}

bootloader_t pv_config_get_bootloader_type()
{
	return pv_config_get_int(PV_BOOTLOADER_TYPE);
}

static char *_get_bootloader_type_str(bootloader_t type)
{
	switch (type) {
	case BL_UBOOT_PLAIN:
		return "uboot";
	case BL_UBOOT_PVK:
		return "uboot-pvk";
	case BL_GRUB:
		return "grub";
	case BL_RPIAB:
		return "rpiab";
	default:
		return "unknown";
	}
}

char *pv_config_get_bootloader_type_str(void)
{
	return _get_bootloader_type_str(pv_config_get_bootloader_type());
}

static void _set_config_by_entry_bootloader_type(struct pv_config_entry *entry,
						 const char *value)
{
	if (!entry)
		return;

	if (pv_str_matches(value, strlen(value), "uboot", strlen("uboot")))
		entry->value.i = BL_UBOOT_PLAIN;
	else if (pv_str_matches(value, strlen(value), "uboot-pvk",
				strlen("uboot-pvk")))
		entry->value.i = BL_UBOOT_PVK;
	else if (pv_str_matches(value, strlen(value), "grub", strlen("grub")))
		entry->value.i = BL_GRUB;
	else if (pv_str_matches(value, strlen(value), "rpiab", strlen("rpiab")))
		entry->value.i = BL_RPIAB;
	else
		pv_log(WARN, "unknown bootloader type '%s'", value);
}

void pv_config_set_creds_id(char *id)
{
	_set_config_by_index_str(PH_CREDS_ID, id, PH_CLIENT);
}
void pv_config_set_creds_prn(char *prn)
{
	_set_config_by_index_str(PH_CREDS_PRN, prn, PH_CLIENT);
}
void pv_config_set_creds_secret(char *secret)
{
	_set_config_by_index_str(PH_CREDS_SECRET, secret, PH_CLIENT);
}

void pv_config_set_debug_shell(bool shell)
{
	_set_config_by_index_bool(PV_DEBUG_SHELL, shell, ARGS);
}
void pv_config_set_debug_shell_autologin(bool shell)
{
	_set_config_by_index_bool(PV_DEBUG_SHELL_AUTOLOGIN, shell, ARGS);
}
void pv_config_set_debug_ssh(bool ssh)
{
	_set_config_by_index_bool(PV_DEBUG_SSH, ssh, ARGS);
}

log_server_output_mask_t pv_config_get_log_server_outputs()
{
	return pv_config_get_int(PV_LOG_SERVER_OUTPUTS);
}

static void
_set_config_by_entry_log_server_outputs(struct pv_config_entry *entry,
					const char *value)
{
	if (!entry)
		return;

	char *token, *tmp;
	int server_outputs = 0;

	char *val = strdup(value);

	for (token = strtok_r(val, ",", &tmp); token;
	     token = strtok_r(NULL, ",", &tmp)) {
		if (pv_str_matches(token, strlen(token), "singlefile",
				   strlen("singlefile")))
			server_outputs |= LOG_SERVER_OUTPUT_SINGLE_FILE;
		else if (pv_str_matches(token, strlen(token), "filetree",
					strlen("filetree")))
			server_outputs |= LOG_SERVER_OUTPUT_FILE_TREE;
		else if (pv_str_matches(token, strlen(token), "nullsink",
					strlen("nullsink")))
			server_outputs |= LOG_SERVER_OUTPUT_NULL_SINK;
		else if (pv_str_matches(token, strlen(token), "stdout_direct",
					strlen("stdout_direct")))
			server_outputs |= LOG_SERVER_OUTPUT_STDOUT_DIRECT;
		else if (pv_str_matches(token, strlen(token),
					"stdout.containers",
					strlen("stdout.containers")))
			server_outputs |= LOG_SERVER_OUTPUT_STDOUT_CONTAINERS;
		else if (pv_str_matches(token, strlen(token),
					"stdout.pantavisor",
					strlen("stdout.pantavisor")))
			server_outputs |= LOG_SERVER_OUTPUT_STDOUT_PANTAVISOR;
		else if (pv_str_matches(token, strlen(token), "stdout",
					strlen("stdout")))
			server_outputs |= LOG_SERVER_OUTPUT_STDOUT;
		else
			pv_log(WARN, "unknown log server output '%s'", token);
	}

	free(val);

	server_outputs |= LOG_SERVER_OUTPUT_UPDATE;
	entry->value.i = server_outputs;
}

secureboot_mode_t pv_config_get_secureboot_mode()
{
	return pv_config_get_int(PV_SECUREBOOT_MODE);
}

static char *_get_secureboot_mode_str(secureboot_mode_t mode)
{
	switch (mode) {
	case SB_DISABLED:
		return "disabled";
	case SB_AUDIT:
		return "audit";
	case SB_LENIENT:
		return "lenient";
	case SB_STRICT:
		return "strict";
	default:
		return "unknown";
	}
}

char *pv_config_get_secureboot_mode_str(void)
{
	return _get_secureboot_mode_str(pv_config_get_secureboot_mode());
}

static void _set_config_by_entry_secureboot_mode(struct pv_config_entry *entry,
						 const char *value)
{
	if (!entry)
		return;

	if (pv_str_matches(value, strlen(value), "disabled",
			   strlen("disabled")))
		entry->value.i = SB_DISABLED;
	else if (pv_str_matches(value, strlen(value), "audit", strlen("audit")))
		entry->value.i = SB_AUDIT;
	else if (pv_str_matches(value, strlen(value), "lenient",
				strlen("lenient")))
		entry->value.i = SB_LENIENT;
	else if (pv_str_matches(value, strlen(value), "strict",
				strlen("strict")))
		entry->value.i = SB_STRICT;
	else
		pv_log(WARN, "unknown secureboot mode '%s'", value);
}

init_mode_t pv_config_get_system_init_mode()
{
	return pv_config_get_int(PV_SYSTEM_INIT_MODE);
}

static char *_get_system_init_mode_str(init_mode_t mode)
{
	switch (mode) {
	case IM_EMBEDDED:
		return "embedded";
	case IM_STANDALONE:
		return "standalone";
	case IM_APPENGINE:
		return "appengine";
	default:
		return "unknown";
	}
}

char *pv_config_get_system_init_mode_str(void)
{
	return _get_system_init_mode_str(pv_config_get_system_init_mode());
}

static void _set_config_by_entry_init_mode(struct pv_config_entry *entry,
					   const char *value)
{
	if (!entry)
		return;

	if (pv_str_matches(value, strlen(value), "embedded",
			   strlen("embedded")))
		entry->value.i = IM_EMBEDDED;
	else if (pv_str_matches(value, strlen(value), "standalone",
				strlen("standalone")))
		entry->value.i = IM_STANDALONE;
	else if (pv_str_matches(value, strlen(value), "appengine",
				strlen("appengine")))
		entry->value.i = IM_APPENGINE;
	else
		pv_log(WARN, "unknown system init mode '%s'", value);
}

void pv_config_set_system_init_mode(init_mode_t mode)
{
	entries[PV_SYSTEM_INIT_MODE].value.i = mode;
	entries[PV_SYSTEM_INIT_MODE].modified = ARGS;
}

wdt_mode_t pv_config_get_wdt_mode()
{
	return pv_config_get_int(PV_WDT_MODE);
}

static char *_get_wdt_mode_str(wdt_mode_t mode)
{
	switch (mode) {
	case WDT_DISABLED:
		return "disabled";
	case WDT_SHUTDOWN:
		return "shutdown";
	case WDT_STARTUP:
		return "startup";
	case WDT_ALWAYS:
		return "always";
	default:
		return "unknown";
	}
}

char *pv_config_get_wdt_mode_str(void)
{
	return _get_wdt_mode_str(pv_config_get_wdt_mode());
}

static void _set_config_by_entry_wdt_mode(struct pv_config_entry *entry,
					  const char *value)
{
	if (!entry)
		return;

	if (pv_str_matches(value, strlen(value), "disabled",
			   strlen("disabled")))
		entry->value.i = WDT_DISABLED;
	else if (pv_str_matches(value, strlen(value), "shutdown",
				strlen("shutdown")))
		entry->value.i = WDT_SHUTDOWN;
	else if (pv_str_matches(value, strlen(value), "startup",
				strlen("startup")))
		entry->value.i = WDT_STARTUP;
	else if (pv_str_matches(value, strlen(value), "always",
				strlen("always")))
		entry->value.i = WDT_ALWAYS;
	else
		pv_log(WARN, "unknown wdt mode '%s'", value);
}

static char *_get_value_policy(struct dl_list *config_list)
{
	char *item = config_get_value(config_list, "PV_POLICY");
	if (!item)
		item = config_get_value(config_list, "policy");

	if (!item || !strlen(item))
		return NULL;

	// policy does not allow paths
	if (strchr(item, '/'))
		return NULL;

	return strdup(item);
}

static int _set_config_sysctl_by_key(const char *key, const char *value)
{
	char *path = pv_config_parser_sysctl_key(key);
	if (!path)
		return 0;

	int fd = open(path, O_WRONLY | O_SYNC);
	if (fd < 0) {
		pv_log(WARN, "cannot open '%s': %s", path, strerror(errno));
		free(path);
		return -1;
	}

	write(fd, value, strlen(value) + 1);
	close(fd);
	free(path);

	return 1;
}

static int pv_config_load_policy(const char *policy,
				 struct dl_list *config_list)
{
	char path[PATH_MAX];

	if (!policy) {
		pv_log(DEBUG, "policy not set");
		return 0;
	}

	pv_paths_etc_policy_file(path, PATH_MAX, policy);
	if (load_key_value_file(path, config_list) < 0) {
		pv_log(FATAL, "unable to parse '%s'\n", path);
		return -1;
	}

	return 0;
}

static struct pv_config_entry *_search_config_entry_by_key(const char *key)
{
	struct pv_config_entry *entry = NULL;
	const char *k;

	for (config_index_t ci = 0; ci < PV_MAX; ci++) {
		k = entries[ci].key;
		if (pv_str_matches_case(k, strlen(k), key, strlen(key))) {
			entry = &entries[ci];
			break;
		}
	}

	return entry;
}

static char *_get_mod_level_str(level_t ml)
{
	switch (ml) {
	case DEFAULT:
		return "default";
	case ARGS:
		return "args";
	case PV_CONF:
		return "pv conf file";
	case PH_CONF:
		return "ph conf file";
	case POLICY:
		return "policy";
	case PV_CMDLINE:
		return "pv cmdline";
	case PH_CMDLINE:
		return "ph cmdline";
	case ENV:
		return "env";
	case OEM:
		return "oem config";
	case META:
		return "metadata";
	case CMD:
		return "command";
	default:
		return "unknown";
	}
}

static int _set_config_by_entry(struct pv_config_entry *entry,
				const char *value, level_t modified)
{
	if (!entry)
		return -1;

	if (!(entry->allowed & modified)) {
		pv_log(WARN, "key '%s' not allowed in %s level", entry->key,
		       _get_mod_level_str(modified));
		return -1;
	}

	long value_int = 0;
	if ((entry->type == BOOL) || (entry->type == INT)) {
		char *endptr;
		value_int = strtol(value, &endptr, 10);

		if (*endptr != '\0') {
			pv_log(WARN, "invalid number format '%s' for key '%s'",
			       value, entry->key);
			return -1;
		}
	}

	entry->modified = modified;

	switch (entry->type) {
	case BOOL:
		_set_config_by_entry_bool(entry, value_int);
		break;
	case BOOTLOADER:
		_set_config_by_entry_bootloader_type(entry, value);
		break;
	case INIT_MODE:
		_set_config_by_entry_init_mode(entry, value);
		break;
	case INT:
		_set_config_by_entry_int(entry, value_int);
		break;
	case LOG_SERVER_OUTPUT_UPDATE_MASK:
		_set_config_by_entry_log_server_outputs(entry, value);
		break;
	case SB_MODE:
		_set_config_by_entry_secureboot_mode(entry, value);
		break;
	case STR:
		_set_config_by_entry_str(entry, value);
		break;
	case WDT_MODE:
		_set_config_by_entry_wdt_mode(entry, value);
		break;
	default:
		pv_log(WARN, "unknown config type %d for key '%s'", entry->type,
		       entry->key);
		return -1;
	}

	return 0;
}

static struct pv_config_entry *_search_config_entry_by_alias(const char *alias)
{
	size_t alias_number = sizeof(aliases) / sizeof(struct pv_config_alias);
	char *a;

	for (size_t ai = 0; ai < alias_number; ai++) {
		a = aliases[ai].alias;
		if (pv_str_matches(a, strlen(a), alias, strlen(alias)))
			return _search_config_entry_by_key(aliases[ai].key);
	}

	return NULL;
}

static int _set_config_by_key(const char *key, const char *value, void *opaque)
{
	level_t *level = (level_t *)opaque;
	pv_log(DEBUG, "setting '%s' with value '%s' on level '%s'", key, value,
	       _get_mod_level_str(*level));

	if (*level & LEVEL_SYSCTL) {
		if (_set_config_sysctl_by_key(key, value))
			return 0;
	}

	struct pv_config_entry *entry;
	entry = _search_config_entry_by_key(key);
	if (!entry) {
		entry = _search_config_entry_by_alias(key);
		if (entry) {
			pv_log(WARN, "translating legacy key '%s' as '%s'", key,
			       entry->key);
		}
	}
	if (!entry) {
		pv_log(WARN, "key '%s' unknown", key);
		return 0;
	}

	if (_set_config_by_entry(entry, value, *level)) {
		pv_log(WARN, "cannot set key '%s' in config", key);
		return 0;
	}

	return 0;
}

static void _iterate_config_items(struct dl_list *items, level_t level)
{
	level_t l = level;
	config_iterate_items(items, _set_config_by_key, (void *)&l);
}

static int pv_config_load_file(char *path)
{
	int ret = -1;
	char *policy = NULL;

	DEFINE_DL_LIST(cmdline_list);
	DEFINE_DL_LIST(env_list);
	DEFINE_DL_LIST(pv_conf_list);
	DEFINE_DL_LIST(policy_list);

	config_parse_cmdline(&cmdline_list, "pv_");

	config_parse_env(&env_list);

	if (load_key_value_file(path, &pv_conf_list) < 0) {
		pv_log(ERROR, "cannot load config from '%s'", path);
		goto out;
	}

	policy = _get_value_policy(&cmdline_list);
	if (!policy)
		policy = _get_value_policy(&env_list);
	if (!policy)
		policy = _get_value_policy(&pv_conf_list);

	_iterate_config_items(&pv_conf_list, PV_CONF);

	// we do this here because we need the paths from pantavisor.config
	if (pv_config_load_policy(policy, &policy_list)) {
		pv_log(ERROR, "cannot load config from policy '%s'", policy);
		goto out;
	}

	_iterate_config_items(&policy_list, POLICY);
	_iterate_config_items(&cmdline_list, PV_CMDLINE);
	_iterate_config_items(&env_list, ENV);

	ret = 0;

out:
	if (policy)
		free(policy);

	config_clear_items(&policy_list);
	config_clear_items(&pv_conf_list);
	config_clear_items(&env_list);
	config_clear_items(&cmdline_list);

	return ret;
}

static int pv_config_load_creds_from_file(char *path)
{
	DEFINE_DL_LIST(ph_conf_list);
	if (load_key_value_file(path, &ph_conf_list) < 0) {
		pv_log(ERROR, "cannot load config from '%s'", path);
		return -1;
	}
	level_t level = PH_CONF;
	config_iterate_items(&ph_conf_list, _set_config_by_key, (void *)&level);
	config_clear_items(&ph_conf_list);

	DEFINE_DL_LIST(cmdline_list);
	config_parse_cmdline(&cmdline_list, "ph_");
	level = PH_CMDLINE;
	config_iterate_items(&cmdline_list, _set_config_by_key, (void *)&level);
	config_clear_items(&cmdline_list);

	return 0;
}

static int pv_config_override_config_from_file(char *path, level_t level)
{
	DEFINE_DL_LIST(oem_config_list);

	if (load_key_value_file(path, &oem_config_list) < 0) {
		pv_log(WARN, "could not load config file from '%s'", path);
		return -1;
	}

	config_iterate_items(&oem_config_list, _set_config_by_key,
			     (void *)&level);

	config_clear_items(&oem_config_list);

	return 0;
}

static void pv_config_load_bsp(const char *rev, const char *trail_config)
{
	if (trail_config)
		pv_log(WARN,
		       "ignoring not supported BSP config file set in bsp/src.json");
}

static int pv_config_load_oem(const char *rev)
{
	const char *oem_name = pv_config_get_str(PV_OEM_NAME);
	if (!oem_name)
		return 0;

	char *policy = "default";
	if (pv_config_get_str(PV_POLICY))
		policy = pv_config_get_str(PV_POLICY);

	char file_name[256];
	snprintf(file_name, 256, "%s.config", policy);

	char path[PATH_MAX];
	pv_paths_storage_trail_plat_file(path, PATH_MAX, rev, oem_name,
					 file_name);
	if (pv_config_override_config_from_file(path, OEM)) {
		pv_log(WARN, "could not load OEM config file");
		return -1;
	}

	return 0;
}

int pv_config_load_update(const char *rev, const char *trail_config)
{
	pv_config_load_bsp(rev, trail_config);

	if (pv_config_load_oem(rev)) {
		pv_log(WARN, "could not load OEM config");
		return -1;
	}

	return 0;
}

static int write_config_tuple_string(int fd, const char *key, const char *value)
{
	if (!key || !value)
		return 0;

	if (write(fd, key, strlen(key)) < 0)
		return -1;
	if (write(fd, "=", 1) < 0)
		return -1;
	if (write(fd, value, strlen(value)) < 0)
		return -1;
	if (write(fd, "\n", 1) < 0)
		return -1;

	return 1;
}

static int write_config_tuple_int(int fd, const char *key, int value)
{
	char buf[MAX_DEC_STRING_SIZE_OF_TYPE(int)];

	SNPRINTF_WTRUNC(buf, sizeof(buf), "%d", value);

	return write_config_tuple_string(fd, key, buf);
}

static int pv_config_save_creds_to_file(char *path)
{
	int fd;
	char tmp_path[PATH_MAX];

	pv_paths_tmp(tmp_path, PATH_MAX, path);
	fd = open(tmp_path, O_RDWR | O_SYNC | O_CREAT | O_TRUNC, 644);
	if (fd < 0) {
		pv_log(ERROR, "unable to open temporary credentials config: %s",
		       strerror(errno));
		return -1;
	}

	for (config_index_t ci = 0; ci < PV_MAX; ci++) {
		struct pv_config_entry *entry = &entries[ci];
		if (!(entry->allowed & PH_CONF))
			continue;

		switch (entry->type) {
		case INT:
			write_config_tuple_int(fd, entry->key, entry->value.i);
			break;
		case STR:
			if (!entry->value.s)
				continue;

			write_config_tuple_string(fd, entry->key,
						  entry->value.s);
			break;
		default:
			pv_log(WARN, "unknown type for config entry %s",
			       entry->key);
		}
	}

	close(fd);
	if (pv_fs_path_rename(tmp_path, path) < 0) {
		pv_log(ERROR, "could not rename: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int pv_config_load_unclaimed_creds()
{
	char path[PATH_MAX];
	struct stat st;

	pv_paths_storage_config_file(path, PATH_MAX, UNCLAIMED_FNAME);

	if (stat(path, &st))
		return 0;

	if (pv_config_load_creds_from_file(path)) {
		pv_log(WARN, "cannot load creds from %s", path);
		return 0;
	}

	return 0;
}

int pv_config_save_creds()
{
	struct pantavisor *pv = pv_get_instance();
	char path[PATH_MAX];

	if (pv->unclaimed)
		pv_paths_storage_config_file(path, PATH_MAX, UNCLAIMED_FNAME);
	else
		pv_paths_storage_config_file(path, PATH_MAX, PANTAHUB_FNAME);

	if (pv_config_save_creds_to_file(path)) {
		pv_log(ERROR, "cannot save creds in %s", path);
		return -1;
	}

	return 0;
}

void pv_config_override_value(const char *key, const char *value)
{
	level_t level = META;
	_set_config_by_key(key, value, (void *)&level);
}

void pv_config_free()
{
	for (config_index_t ci = 0; ci < PV_MAX; ci++) {
		if (entries[ci].type == STR)
			free(entries[ci].value.s);
	}
}

static char *_search_config_alias_by_key(const char *key)
{
	size_t alias_number = sizeof(aliases) / sizeof(struct pv_config_alias);
	char *k = NULL;

	for (size_t ai = 0; ai < alias_number; ai++) {
		k = aliases[ai].key;
		if (pv_str_matches_case(k, strlen(k), key, strlen(key)))
			return aliases[ai].alias;
	}

	return NULL;
}

static void _add_config_entry_json(config_index_t ci, struct pv_json_ser *js)
{
	if (ci >= PV_MAX)
		return;

	char *key = _search_config_alias_by_key(entries[ci].key);
	if (!key)
		return;
	pv_json_ser_key(js, key);

	switch (entries[ci].type) {
	case BOOL:
		pv_json_ser_bool(js, entries[ci].value.b);
		break;
	case BOOTLOADER:
	case INIT_MODE:
	case INT:
	case LOG_SERVER_OUTPUT_UPDATE_MASK:
	case SB_MODE:
	case WDT_MODE:
		pv_json_ser_number(js, entries[ci].value.i);
		break;
	case STR:
		pv_json_ser_string(js, entries[ci].value.s);
		break;
	default:
		pv_log(WARN, "unknown type for config entry %s",
		       entries[ci].key);
		pv_json_ser_string(js, NULL);
	}
}

char *pv_config_get_json()
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, 512);

	pv_json_ser_object(&js);
	{
		for (config_index_t ci = 0; ci < PV_MAX; ci++) {
			_add_config_entry_json(ci, &js);
		}

		pv_json_ser_object_pop(&js);
	}

	return pv_json_ser_str(&js);
}

static void _print_config_entry(config_index_t ci)
{
	if (ci >= PV_MAX)
		return;

	const char *key = entries[ci].key;
	level_t modified = entries[ci].modified;

	switch (entries[ci].type) {
	case BOOL:
		pv_log(INFO, "%s = %d (%s)", key, entries[ci].value.b,
		       _get_mod_level_str(modified));
		break;
	case BOOTLOADER:
		pv_log(INFO, "%s = '%s' (%s)", key,
		       _get_bootloader_type_str(entries[ci].value.i),
		       _get_mod_level_str(modified));
		break;
	case INIT_MODE:
		pv_log(INFO, "%s = '%s' (%s)", key,
		       _get_system_init_mode_str(entries[ci].value.i),
		       _get_mod_level_str(modified));
		break;
	case INT:
		pv_log(INFO, "%s = %d (%s)", key, entries[ci].value.i,
		       _get_mod_level_str(modified));
		break;
	case LOG_SERVER_OUTPUT_UPDATE_MASK:
		pv_log(INFO, "%s = %d (%s)", key, entries[ci].value.i,
		       _get_mod_level_str(modified));
		break;
	case SB_MODE:
		pv_log(INFO, "%s = '%s' (%s)", key,
		       _get_secureboot_mode_str(entries[ci].value.i),
		       _get_mod_level_str(modified));
		break;
	case STR:
		pv_log(INFO, "%s = '%s' (%s)", key, entries[ci].value.s,
		       _get_mod_level_str(modified));
		break;
	case WDT_MODE:
		pv_log(INFO, "%s = '%s' (%s)", key,
		       _get_wdt_mode_str(entries[ci].value.i),
		       _get_mod_level_str(modified));
		break;
	default:
		pv_log(WARN, "unknown type for config entry %s", key);
	}
}

void pv_config_print()
{
	for (config_index_t ci = 0; ci < PV_MAX; ci++) {
		_print_config_entry(ci);
	}
}

int pv_config_init(char *path)
{
	size_t entry_number = sizeof(entries) / sizeof(struct pv_config_entry);
	if (PV_MAX != entry_number) {
		pv_log(FATAL, "number of config_index_t is not %zu",
		       entry_number);
		return -1;
	}

	// we alloc all strings, incluiding default ones
	// this way, we can free both default and non-default the same way
	char *tmp;
	for (config_index_t ci = 0; ci < PV_MAX; ci++) {
		if ((entries[ci].type == STR) && entries[ci].value.s) {
			tmp = strdup(entries[ci].value.s);
			entries[ci].value.s = tmp;
		}
	}

	// default core_pattern, overridable by config
	_set_config_sysctl_by_key("PV_SYSCTL_KERNEL_CORE_PATTERN",
				  "|/lib/pv/pvcrash --skip");

	if (!path)
		path = PV_PANTAVISOR_CONFIG_PATH;
	pv_log(DEBUG, "loading config from %s\n", path);
	if (pv_config_load_file(path) < 0) {
		pv_log(FATAL, "unable to load '%s'\n", path);
		return -1;
	}

	return 0;
}

static int pv_config_load_creds(struct pv_init *this)
{
	char path[PATH_MAX];
	struct stat st;

	pv_paths_storage_config_file(path, PATH_MAX, PANTAHUB_FNAME);

	if (stat(path, &st)) {
		pv_log(WARN, "cannot find creds in %s", path);
		return 0;
	}

	if (pv_config_load_creds_from_file(path)) {
		pv_log(ERROR, "cannot load creds from %s", path);
		return -1;
	}

	return 0;
}

struct pv_init pv_init_creds = {
	.init_fn = pv_config_load_creds,
	.flags = 0,
};
