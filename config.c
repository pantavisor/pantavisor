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
	TRAIL = 1 << 7,
	META = 1 << 8,
	CMD = 1 << 9
} level_t;

#define PV_ENTRY PV_CONF | PV_CMDLINE
#define PH_ENTRY PH_CONF | PH_CMDLINE
#define UPDATE_TIME POLICY | TRAIL
#define RUN_TIME UPDATE_TIME | META | CMD

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
	{ STR, "bootloader.fitconfig", PV_ENTRY | POLICY, 0, .value.s = NULL },
	{ STR, "bootloader.mtd_env", PV_ENTRY | POLICY, 0, .value.s = NULL },
	{ BOOL, "bootloader.mtd_only", PV_ENTRY | POLICY, 0, .value.b = false },
	{ BOOTLOADER, "bootloader.type", PV_ENTRY | POLICY, 0,
	  .value.i = BL_UBOOT_PLAIN },
	{ STR, "cache.devmetadir", PV_ENTRY | POLICY, 0,
	  .value.s = CACHE_DEVMETADIR_DEF },
	{ STR, "cache.usrmetadir", PV_ENTRY | POLICY, 0,
	  .value.s = CACHE_USRMETADIR_DEF },
	{ BOOL, "control.remote", PV_ENTRY | POLICY, 0, .value.b = true },
	{ BOOL, "control.remote.always", PV_ENTRY | POLICY, 0,
	  .value.b = false },
	{ STR, "creds.host", PH_ENTRY, 0, .value.s = CREDS_HOST_DEF },
	{ STR, "creds.id", PH_ENTRY, 0, .value.s = NULL },
	{ INT, "creds.port", PH_ENTRY, 0, .value.i = 12365 },
	{ STR, "creds.proxy.host", PH_ENTRY | UPDATE_TIME, 0, .value.s = NULL },
	{ INT, "creds.proxy.noproxyconnect", PH_ENTRY | UPDATE_TIME, 0,
	  .value.i = 0 },
	{ INT, "creds.proxy.port", PH_ENTRY | UPDATE_TIME, 0, .value.i = 3218 },
	{ STR, "creds.prn", PH_ENTRY, 0, .value.s = NULL },
	{ STR, "creds.secret", PH_ENTRY, 0, .value.s = NULL },
	{ STR, "creds.tpm.cert", PH_ENTRY, 0, .value.s = NULL },
	{ STR, "creds.tpm.key", PH_ENTRY, 0, .value.s = NULL },
	{ STR, "creds.type", PH_ENTRY, 0, .value.s = CREDS_TYPE_DEF },
	{ BOOL, "debug.shell", PV_ENTRY | POLICY, 0, .value.b = true },
	{ BOOL, "debug.shell.autologin", PV_ENTRY | POLICY, 0,
	  .value.b = false },
	{ BOOL, "debug.ssh", PV_ENTRY | RUN_TIME, 0, .value.b = true },
	{ STR, "debug.ssh_authorized_keys", PV_ENTRY | RUN_TIME, 0,
	  .value.s = NULL },
	{ STR, "disk.exportsdir", PV_ENTRY | POLICY, 0,
	  .value.s = DISK_EXPORTSDIR_DEF },
	{ STR, "disk.voldir", PV_ENTRY | POLICY, 0,
	  .value.s = DISK_VOLDIR_DEF },
	{ STR, "disk.writabledir", PV_ENTRY | POLICY, 0,
	  .value.s = DISK_WRITABLEDIR_DEF },
	{ STR, "dropbear.cache.dir", PV_ENTRY | POLICY, 0,
	  .value.s = DROPBEAR_CACHE_DIR_DEF },
	{ STR, "factory.autotok", PH_ENTRY, 0, .value.s = NULL },
	{ STR, "libthttp.certsdir", PV_ENTRY | POLICY, 0,
	  .value.s = LIBTHTTP_CERTSDIR_DEF },
	{ INT, "libthttp.log.level", PV_ENTRY | RUN_TIME, 0, .value.i = 3 },
	{ BOOL, "log.capture", PV_ENTRY | UPDATE_TIME, 0, .value.b = true },
	{ BOOL, "log.capture.dmesg", PV_ENTRY | UPDATE_TIME, 0,
	  .value.b = false },
	{ INT, "log.buf_nitems", PV_ENTRY | UPDATE_TIME, 0, .value.i = 128 },
	{ STR, "log.dir", PV_ENTRY | POLICY, 0, .value.s = LOG_DIR_DEF },
	{ STR, "log.filetree.timestamp.format", PV_ENTRY | RUN_TIME, 0,
	  .value.s = NULL },
	{ INT, "log.level", PV_ENTRY | RUN_TIME, 0, .value.i = 0 },
	{ BOOL, "log.loggers", PV_ENTRY | UPDATE_TIME, 0, .value.b = true },
	{ INT, "log.maxsize", PV_ENTRY | RUN_TIME, 0,
	  .value.i = LOG_MAXSIZE_DEF },
	{ BOOL, "log.push", PV_ENTRY | RUN_TIME, 0, .value.b = true },
	{ LOG_SERVER_OUTPUT_UPDATE_MASK, "log.server.outputs",
	  PV_ENTRY | RUN_TIME, 0,
	  .value.i = LOG_SERVER_OUTPUT_FILE_TREE | LOG_SERVER_OUTPUT_UPDATE },
	{ STR, "log.singlefile.timestamp.format", PV_ENTRY | RUN_TIME, 0,
	  .value.s = NULL },
	{ BOOL, "log.stdout", PV_ENTRY | RUN_TIME, 0, .value.b = false },
	{ STR, "log.stdout.timestamp.format", PV_ENTRY | RUN_TIME, 0,
	  .value.s = NULL },
	{ INT, "lxc.log.level", PV_ENTRY | UPDATE_TIME, 0, .value.i = 2 },
	{ INT, "metadata.devmeta.interval", PH_ENTRY | RUN_TIME, 0,
	  .value.i = 10 },
	{ INT, "metadata.usrmeta.interval", PH_ENTRY | RUN_TIME, 0,
	  .value.i = 5 },
	{ STR, "net.braddress4", PV_ENTRY | UPDATE_TIME, 0,
	  .value.s = NET_BRADDRESS4_DEF },
	{ STR, "net.brdev", PV_ENTRY | UPDATE_TIME, 0,
	  .value.s = NET_BRDEV_DEF },
	{ STR, "net.brmask4", PV_ENTRY | UPDATE_TIME, 0,
	  .value.s = NET_BRMASK4_DEF },
	{ STR, "policy", PV_ENTRY, 0, .value.s = NULL },
	{ INT, "revision.retries", PV_ENTRY | RUN_TIME, 0, .value.i = 10 },
	{ INT, "revision.retries.timeout", PV_ENTRY | RUN_TIME, 0,
	  .value.i = 120 },
	{ BOOL, "secureboot.checksum", PV_ENTRY | POLICY, 0, .value.b = true },
	{ BOOL, "secureboot.handlers", PV_ENTRY | POLICY, 0, .value.b = true },
	{ SB_MODE, "secureboot.mode", PV_ENTRY | POLICY, 0,
	  .value.i = SB_LENIENT },
	{ STR, "secureboot.truststore", PV_ENTRY | POLICY, 0,
	  .value.s = SECUREBOOT_TRUSTSTORE_DEF },
	{ STR, "storage.device", PV_ENTRY | POLICY, 0, .value.s = NULL },
	{ STR, "storage.fstype", PV_ENTRY | POLICY, 0, .value.s = NULL },
	{ BOOL, "storage.gc.keep_factory", PV_ENTRY | RUN_TIME, 0,
	  .value.b = false },
	{ INT, "storage.gc.reserved", PV_ENTRY | RUN_TIME, 0, .value.i = 5 },
	{ INT, "storage.gc.threshold.defertime", PV_ENTRY | RUN_TIME, 0,
	  .value.i = 600 },
	{ INT, "storage.gc.threshold", PV_ENTRY | RUN_TIME, 0, .value.i = 0 },
	{ STR, "storage.logtempsize", PV_ENTRY | POLICY, 0, .value.s = NULL },
	{ STR, "storage.mntpoint", PV_ENTRY | POLICY, 0, .value.s = NULL },
	{ STR, "storage.mnttype", PV_ENTRY | POLICY, 0, .value.s = NULL },
	{ STR, "storage.opts", PV_ENTRY | POLICY, 0, .value.s = NULL },
	{ INT, "storage.wait", PV_ENTRY | POLICY, 0, .value.i = 5 },
	{ STR, "system.apparmor.profiles", PV_ENTRY | POLICY, 0,
	  .value.s = NULL },
	{ STR, "system.confdir", PV_ENTRY | POLICY, 0,
	  .value.s = SYSTEM_CONFDIR_DEF },
	{ BOOL, "system.drivers.load_early.auto", PV_ENTRY | POLICY, 0,
	  .value.b = false },
	{ STR, "system.etcdir", PV_ENTRY | POLICY, 0,
	  .value.s = SYSTEM_ETCDIR_DEF },
	{ INIT_MODE, "system.init.mode", PV_ENTRY | POLICY, 0,
	  .value.i = IM_EMBEDDED },
	{ STR, "system.libdir", PV_ENTRY | POLICY, 0,
	  .value.s = SYSTEM_LIBDIR_DEF },
	{ STR, "system.mediadir", PV_ENTRY | POLICY, 0,
	  .value.s = SYSTEM_MEDIADIR_DEF },
	{ BOOL, "system.mount.securityfs", PV_ENTRY | POLICY, 0,
	  .value.b = false },
	{ STR, "system.rundir", PV_ENTRY | POLICY, 0,
	  .value.s = SYSTEM_RUNDIR_DEF },
	{ STR, "system.usrdir", PV_ENTRY | POLICY, 0,
	  .value.s = SYSTEM_USRDIR_DEF },
	{ INT, "updater.commit.delay", PV_ENTRY | RUN_TIME, 0, .value.i = 25 },
	{ INT, "updater.goals.timeout", PV_ENTRY | RUN_TIME, 0,
	  .value.i = 120 },
	{ INT, "updater.interval", PH_ENTRY | RUN_TIME, 0, .value.i = 60 },
	{ INT, "updater.network_timeout", PH_ENTRY | RUN_TIME, 0,
	  .value.i = 120 },
	{ BOOL, "updater.use_tmp_objects", PV_ENTRY | RUN_TIME, 0,
	  .value.b = false },
	{ BOOL, "wdt.enabled", PV_ENTRY | UPDATE_TIME, 0, .value.b = true },
	{ WDT_MODE, "wdt.mode", PV_ENTRY | UPDATE_TIME, 0,
	  .value.i = WDT_SHUTDOWN },
	{ INT, "wdt.timeout", PV_ENTRY | UPDATE_TIME, 0, .value.i = 15 }
};

struct pv_config_alias {
	char *alias;
	char *key;
};

static struct pv_config_alias aliases[] = {
	{ "meta.cache.dir", "cache.usrmetadir" },
	{ "pantahub.log.push", "log.push" },
	{ "updater.keep_factory", "storage.gc.keep_factory" }
};

bool pv_config_get_bool(config_index_t ci)
{
	return entries[ci].value.b;
}

static void _set_config_by_entry_bool(struct pv_config_entry *entry, bool value,
				      level_t modified)
{
	if (!entry)
		return;

	entry->value.b = value;
	entry->modified = modified;
}

static void _set_config_by_index_bool(config_index_t ci, bool value,
				      level_t modified)
{
	_set_config_by_entry_bool(&entries[ci], value, modified);
}

int pv_config_get_int(config_index_t ci)
{
	return entries[ci].value.i;
}

static void _set_config_by_entry_int(struct pv_config_entry *entry, int value,
				     level_t modified)
{
	if (!entry)
		return;

	entry->value.i = value;
	entry->modified = modified;
}

char *pv_config_get_str(config_index_t ci)
{
	return entries[ci].value.s;
}

static void _set_config_by_entry_str(struct pv_config_entry *entry,
				     const char *value, level_t modified)
{
	if (!entry)
		return;

	if (entry->value.s)
		free(entry->value.s);
	entry->value.s = strdup(value);
	entry->modified = modified;
}

static void _set_config_by_index_str(config_index_t ci, const char *value,
				     level_t modified)
{
	_set_config_by_entry_str(&entries[ci], value, modified);
}

bootloader_t pv_config_get_bootloader_type()
{
	return pv_config_get_int(CI_BOOTLOADER_TYPE);
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
						 const char *value,
						 level_t modified)
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
	_set_config_by_index_str(CI_CREDS_ID, id, PH_CLIENT);
}
void pv_config_set_creds_prn(char *prn)
{
	_set_config_by_index_str(CI_CREDS_PRN, prn, PH_CLIENT);
}
void pv_config_set_creds_secret(char *secret)
{
	_set_config_by_index_str(CI_CREDS_SECRET, secret, PH_CLIENT);
}

void pv_config_set_debug_shell(bool shell)
{
	_set_config_by_index_bool(CI_DEBUG_SHELL, shell, ARGS);
}
void pv_config_set_debug_shell_autologin(bool shell)
{
	_set_config_by_index_bool(CI_DEBUG_SHELL_AUTOLOGIN, shell, ARGS);
}
void pv_config_set_debug_ssh(bool ssh)
{
	_set_config_by_index_bool(CI_DEBUG_SSH, ssh, ARGS);
}

log_server_output_mask_t pv_config_get_log_server_outputs()
{
	return pv_config_get_int(CI_LOG_SERVER_OUTPUTS);
}

static void
_set_config_by_entry_log_server_outputs(struct pv_config_entry *entry,
					const char *value, level_t modified)
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
	return pv_config_get_int(CI_SECUREBOOT_MODE);
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
						 const char *value,
						 level_t modified)
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
	return pv_config_get_int(CI_SYSTEM_INIT_MODE);
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
					   const char *value, level_t modified)
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
	entries[CI_SYSTEM_INIT_MODE].value.i = mode;
	entries[CI_SYSTEM_INIT_MODE].modified = ARGS;
}

wdt_mode_t pv_config_get_wdt_mode()
{
	return pv_config_get_int(CI_WDT_MODE);
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
					  const char *value, level_t modified)
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

static char *config_get_value_policy(struct dl_list *config_list, char *key,
				     char *default_value)
{
	char *item = config_get_value(config_list, key);

	if (!item)
		item = default_value;

	if (!item || !strlen(item))
		return NULL;

	// policy does not allow paths
	if (strchr(item, '/'))
		return NULL;

	return strdup(item);
}

static int _apply_config_sysctl(const char *key, const char *value,
				void *opaque)
{
	const char *start = key + strlen("sysctl");
	char *path =
		calloc(strlen("/proc/sys") + strlen(start) + 1, sizeof(char));

	if (!path)
		return -1;

	sprintf(path, "%s", "/proc/sys");

	const char *next = start;
	char *p = path + strlen("/proc/sys");

	for (int i = 0; i < (int)strlen(start); ++i)
		p[i] = next[i] == '.' ? '/' : next[i];

	errno = 0;
	int fd = open(path, O_WRONLY | O_SYNC);
	if (fd < 0) {
		pv_log(ERROR, "open failed for sysctl node %s with '%s'", path,
		       strerror(errno));

		free(path);
		return -1;
	}

	write(fd, value, strlen(value));
	close(fd);
	free(path);

	return 0;
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

	for (config_index_t ci = 0; ci < CI_MAX; ci++) {
		k = entries[ci].key;
		if (pv_str_matches(k, strlen(k), key, strlen(key))) {
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
	case TRAIL:
		return "trail config";
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

	switch (entry->type) {
	case BOOL:
		_set_config_by_entry_bool(entry, value_int, modified);
		break;
	case BOOTLOADER:
		_set_config_by_entry_bootloader_type(entry, value, modified);
		break;
	case INIT_MODE:
		_set_config_by_entry_init_mode(entry, value, modified);
		break;
	case INT:
		_set_config_by_entry_int(entry, value_int, modified);
		break;
	case LOG_SERVER_OUTPUT_UPDATE_MASK:
		_set_config_by_entry_log_server_outputs(entry, value, modified);
		break;
	case SB_MODE:
		_set_config_by_entry_secureboot_mode(entry, value, modified);
		break;
	case STR:
		_set_config_by_entry_str(entry, value, modified);
		break;
	case WDT_MODE:
		_set_config_by_entry_wdt_mode(entry, value, modified);
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
	struct pv_config_entry *entry = NULL;

	for (size_t ai = 0; ai < alias_number; ai++) {
		a = aliases[ai].alias;
		if (pv_str_matches(a, strlen(a), alias, strlen(alias))) {
			entry = _search_config_entry_by_key(aliases[ai].key);
			break;
		}
	}

	return entry;
}

static int _set_config_by_key(const char *key, const char *value, void *opaque)
{
	struct pv_config_entry *entry;

	entry = _search_config_entry_by_key(key);
	if (!entry)
		entry = _search_config_entry_by_alias(key);
	if (!entry)
		return 0;

	level_t *level = (level_t *)opaque;
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
	config_iterate_items_prefix(items, _apply_config_sysctl, "sysctl.",
				    NULL);
}

static int pv_config_load_file(char *path)
{
	int ret = -1;
	char *policy = NULL;

	DEFINE_DL_LIST(cmdline_list);
	DEFINE_DL_LIST(pv_conf_list);
	DEFINE_DL_LIST(policy_list);

	config_parse_cmdline(&cmdline_list, "pv_");

	if (load_key_value_file(path, &pv_conf_list) < 0) {
		pv_log(ERROR, "cannot load config from '%s'", path);
		goto out;
	}

	policy = config_get_value_policy(&cmdline_list, "policy", NULL);
	if (!policy)
		policy = config_get_value_policy(&pv_conf_list, "policy", NULL);

	_iterate_config_items(&pv_conf_list, PV_CONF);

	// we do this here because we need the paths from pantavisor.config
	if (pv_config_load_policy(policy, &policy_list)) {
		pv_log(ERROR, "cannot load config from policy '%s'", policy);
		goto out;
	}

	_iterate_config_items(&policy_list, POLICY);
	_iterate_config_items(&cmdline_list, PV_CMDLINE);

	ret = 0;

out:
	if (policy)
		free(policy);

	config_clear_items(&policy_list);
	config_clear_items(&pv_conf_list);
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

static int pv_config_override_config_from_file(char *path)
{
	DEFINE_DL_LIST(trail_config_list);

	if (load_key_value_file(path, &trail_config_list) < 0)
		return -1;

	level_t level = TRAIL;
	config_iterate_items(&trail_config_list, _set_config_by_key,
			     (void *)&level);

	config_clear_items(&trail_config_list);

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

	for (config_index_t ci = 0; ci < CI_MAX; ci++) {
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
	for (config_index_t ci = 0; ci < CI_MAX; ci++) {
		if (entries[ci].type == STR)
			free(entries[ci].value.s);
	}
}

static void _add_config_entry_json(config_index_t ci, struct pv_json_ser *js)
{
	if (ci >= CI_MAX)
		return;

	pv_json_ser_key(js, entries[ci].key);

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
		for (config_index_t ci = 0; ci < CI_MAX; ci++) {
			_add_config_entry_json(ci, &js);
		}

		pv_json_ser_object_pop(&js);
	}

	return pv_json_ser_str(&js);
}

static void _print_config_entry(config_index_t ci)
{
	if (ci >= CI_MAX)
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
	for (config_index_t ci = 0; ci < CI_MAX; ci++) {
		_print_config_entry(ci);
	}
}

int pv_config_init(char *path)
{
	size_t entry_number = sizeof(entries) / sizeof(struct pv_config_entry);
	if (CI_MAX != entry_number) {
		pv_log(FATAL, "number of config_index_t is not %zu",
		       entry_number);
		return -1;
	}

	// we alloc all strings, incluiding default ones
	// this way, we can free both default and non-default the same way
	char *tmp;
	for (config_index_t ci = 0; ci < CI_MAX; ci++) {
		if ((entries[ci].type == STR) && entries[ci].value.s) {
			tmp = strdup(entries[ci].value.s);
			entries[ci].value.s = tmp;
		}
	}

	// default core_pattern, overridable by config
	_apply_config_sysctl("sysctl.kernel.core_pattern",
			     "|/lib/pv/pvcrash --skip", NULL);

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

	if (!pv_config_get_bool(CI_CONTROL_REMOTE))
		return 0;

	pv_paths_storage_config_file(path, PATH_MAX, PANTAHUB_FNAME);

	if (stat(path, &st)) {
		pv_log(ERROR, "cannot find creds in %s", path);
		return -1;
	}

	if (pv_config_load_creds_from_file(path)) {
		pv_log(ERROR, "cannot load creds from %s", path);
		return -1;
	}

	return 0;
}

static int pv_config_trail(struct pv_init *this)
{
	int res = -1;
	char path[PATH_MAX];
	const char *rev = pv_bootloader_get_rev();
	char *json = NULL, *config_name;

	json = pv_storage_get_state_json(rev);
	if (!json) {
		pv_log(INFO, "json state not found");
		res = 0;
		goto out;
	}

	config_name = pv_parser_get_initrd_config_name(json);
	if (!config_name) {
		pv_log(INFO, "initrd config not found");
		res = 0;
		goto out;
	}

	pv_paths_storage_trail_plat_file(path, PATH_MAX, rev, "bsp",
					 config_name);
	free(config_name);

	if (pv_config_override_config_from_file(path)) {
		pv_log(FATAL, "initrd config %s not found", path);
		goto out;
	}

	res = 0;
out:
	if (json)
		free(json);
	return res;
}

struct pv_init pv_init_creds = {
	.init_fn = pv_config_load_creds,
	.flags = 0,
};

struct pv_init pv_init_config_trail = {
	.init_fn = pv_config_trail,
	.flags = 0,
};
