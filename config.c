/*
 * Copyright (c) 2017-2022 Pantacor Ltd.
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

static bool config_has_value(struct dl_list *config_list, char *key)
{
	char *item = config_get_value(config_list, key);

	if (!item || !strlen(item))
		return false;

	return true;
}

static char *config_get_value_string(struct dl_list *config_list, char *key,
				     char *default_value)
{
	char *item = config_get_value(config_list, key);

	if (!item)
		item = default_value;

	if (!item || !strlen(item))
		return NULL;

	return strdup(item);
}

static int config_get_value_int(struct dl_list *config_list, char *key,
				int default_value)
{
	char *item = config_get_value(config_list, key);
	int value = default_value;

	if (!item)
		return value;

	value = atoi(item);

	return value;
}

static bool config_get_value_bool(struct dl_list *config_list, char *key,
				  bool default_value)
{
	char *item = config_get_value(config_list, key);
	bool value = default_value;

	if (!item)
		return value;

	value = atoi(item);

	return value;
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

static int config_get_value_init_mode(struct dl_list *config_list, char *key,
				      init_mode_t default_value)
{
	char *item = config_get_value(config_list, key);
	init_mode_t value = default_value;

	if (!item)
		return value;

	if (!strcmp(item, "embedded"))
		value = IM_EMBEDDED;
	else if (!strcmp(item, "standalone"))
		value = IM_STANDALONE;
	else if (!strcmp(item, "appengine"))
		value = IM_APPENGINE;

	return value;
}

static int config_get_value_bl_type(struct dl_list *config_list, char *key,
				    int default_value)
{
	char *item = config_get_value(config_list, key);
	int value = default_value;

	if (!item)
		return value;

	if (!strcmp(item, "uboot"))
		value = BL_UBOOT_PLAIN;
	else if (!strcmp(item, "uboot-pvk"))
		value = BL_UBOOT_PVK;
	else if (!strcmp(item, "grub"))
		value = BL_GRUB;

	return value;
}

static int config_parse_log_server_outputs(char *value)
{
	char *token, *tmp;
	int server_outputs = 0;

	for (token = strtok_r(value, ",", &tmp); token;
	     token = strtok_r(NULL, ",", &tmp)) {
		if (!strcmp(token, "singlefile"))
			server_outputs |= LOG_SERVER_OUTPUT_SINGLE_FILE;
		else if (!strcmp(token, "filetree"))
			server_outputs |= LOG_SERVER_OUTPUT_FILE_TREE;
		else if (!strcmp(token, "nullsink"))
			server_outputs |= LOG_SERVER_OUTPUT_NULL_SINK;
		else if (!strcmp(token, "stdout"))
			server_outputs |= LOG_SERVER_OUTPUT_STDOUT;
	}

	server_outputs |= LOG_SERVER_OUTPUT_UPDATE;

	return server_outputs;
}

static int config_get_value_log_server_outputs(struct dl_list *config_list,
					       char *key, int default_value)
{
	char *item = config_get_value(config_list, key);
	int server_outputs = 0;

	if (!item)
		return default_value;

	server_outputs = config_parse_log_server_outputs(item);

	return server_outputs;
}

static int config_get_value_sb_mode_type(struct dl_list *config_list, char *key,
					 secureboot_mode_t default_value)
{
	char *item = config_get_value(config_list, key);
	secureboot_mode_t value = default_value;

	if (!item)
		return value;

	if (!strcmp(item, "disabled"))
		value = SB_DISABLED;
	else if (!strcmp(item, "audit"))
		value = SB_AUDIT;
	else if (!strcmp(item, "lenient"))
		value = SB_LENIENT;
	else if (!strcmp(item, "strict"))
		value = SB_STRICT;

	return value;
}

static int config_get_value_wdt_mode_type(struct dl_list *config_list,
					  char *key, wdt_mode_t default_value)
{
	char *item = config_get_value(config_list, key);
	wdt_mode_t value = default_value;

	if (!item)
		return value;

	if (!strcmp(item, "disabled"))
		value = WDT_DISABLED;
	else if (!strcmp(item, "shutdown"))
		value = WDT_SHUTDOWN;
	else if (!strcmp(item, "startup"))
		value = WDT_STARTUP;
	else if (!strcmp(item, "always")) {
		pv_log(WARN,
		       "wdt always is experimental. Do not use in production");
		value = WDT_ALWAYS;
	}

	return value;
}

static void config_override_value_string(struct dl_list *config_list, char *key,
					 char **out)
{
	char *item = config_get_value(config_list, key);

	if (item && strlen(item) > 0) {
		if (*out)
			free(*out);
		*out = strdup(item);
	}
}

static void config_override_value_int(struct dl_list *config_list, char *key,
				      int *out)
{
	char *item = config_get_value(config_list, key);

	if (item)
		*out = atoi(item);
}

static void config_override_value_bool(struct dl_list *config_list, char *key,
				       bool *out)
{
	char *item = config_get_value(config_list, key);

	if (item)
		*out = atoi(item);
}

static void
config_override_value_log_server_outputs(struct dl_list *config_list, char *key,
					 int *out)
{
	char *item = config_get_value(config_list, key);

	if (item)
		*out = config_parse_log_server_outputs(item);
}

static int config_sysctl_apply(char *key, char *value, void *opaque)
{
	char *start = key + strlen("sysctl");
	char *path =
		calloc(strlen("/proc/sys") + strlen(start) + 1, sizeof(char));

	if (!path)
		return -1;

	sprintf(path, "%s", "/proc/sys");

	char *next = start;
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

	if (!policy)
		return 0;

	pv_paths_etc_policy_file(path, PATH_MAX, policy);
	if (load_key_value_file(path, config_list) < 0) {
		pv_log(FATAL, "unable to parse %s\n", path);
		return -1;
	}

	return 0;
}

static int pv_config_load_file(char *path, struct pantavisor_config *config)
{
	DEFINE_DL_LIST(config_list);

	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	// for overrides
	config_parse_cmdline(&config_list, "pv_");

	config->sys.init_mode = config_get_value_init_mode(
		&config_list, "system.init.mode", IM_EMBEDDED);
	config->sys.libdir =
		config_get_value_string(&config_list, "system.libdir", "/lib");
	config->sys.etcdir =
		config_get_value_string(&config_list, "system.etcdir", "/etc");
	config->sys.usrdir =
		config_get_value_string(&config_list, "system.usrdir", "/usr");
	config->sys.rundir =
		config_get_value_string(&config_list, "system.rundir", "/pv");
	config->sys.mediadir = config_get_value_string(
		&config_list, "system.mediadir", "/media");
	config->sys.confdir = config_get_value_string(
		&config_list, "system.confdir", "/configs");
	config->sys.auto_load_drivers = config_get_value_bool(
		&config_list, "system.drivers.load_early.auto", false);
	config->sys.mount_securityfs = config_get_value_bool(
		&config_list, "system.mount.securityfs", false);

	config->sys.apparmor_profiles = config_get_value_string(
		&config_list, "system.apparmor.profiles", NULL);
	config->policy = config_get_value_policy(&config_list, "policy", NULL);
	if (pv_config_load_policy(config->policy, &config_list))
		return -1;

	config_parse_cmdline(&config_list, "pv_");

	config->debug.shell =
		config_get_value_bool(&config_list, "debug.shell", true);
	config->debug.shell_autologin = config_get_value_bool(
		&config_list, "debug.shell.autologin", false);
	config->debug.ssh =
		config_get_value_bool(&config_list, "debug.ssh", true);
	config->debug.ssh_authorized_keys = config_get_value_string(
		&config_list, "debug.ssh_authorized_keys", NULL);

	config->cache.dropbearcachedir = config_get_value_string(
		&config_list, "dropbear.cache.dir", "/storage/cache/dropbear");
	config->cache.usrmetadir = config_get_value_string(
		&config_list, "cache.usrmetadir", "/storage/cache/meta");
	config_override_value_string(&config_list, "meta.cache.dir",
				     &config->cache.usrmetadir);
	config->cache.devmetadir = config_get_value_string(
		&config_list, "cache.devmetadir", "/storage/cache/devmeta");

	config->bl.type = config_get_value_bl_type(
		&config_list, "bootloader.type", BL_UBOOT_PLAIN);
	config->bl.mtd_only = config_get_value_bool(
		&config_list, "bootloader.mtd_only", false);
	config->bl.mtd_path = config_get_value_string(
		&config_list, "bootloader.mtd_env", NULL);
	config->bl.fitconfig = config_get_value_string(
		&config_list, "bootloader.fitconfig", NULL);

	config->storage.path =
		config_get_value_string(&config_list, "storage.device", NULL);
	config->storage.fstype =
		config_get_value_string(&config_list, "storage.fstype", NULL);
	config->storage.opts =
		config_get_value_string(&config_list, "storage.opts", NULL);
	config->storage.mntpoint =
		config_get_value_string(&config_list, "storage.mntpoint", NULL);
	config->storage.mnttype =
		config_get_value_string(&config_list, "storage.mnttype", NULL);
	config->storage.logtempsize = config_get_value_string(
		&config_list, "storage.logtempsize", NULL);
	config->storage.wait =
		config_get_value_int(&config_list, "storage.wait", 5);

	config->storage.gc.reserved =
		config_get_value_int(&config_list, "storage.gc.reserved", 5);
	config->storage.gc.keep_factory = config_get_value_bool(
		&config_list, "storage.gc.keep_factory", false);
	config->storage.gc.threshold =
		config_get_value_int(&config_list, "storage.gc.threshold", 0);
	config->storage.gc.threshold_defertime = config_get_value_int(
		&config_list, "storage.gc.threshold.defertime", 600);

	config->disk.voldir = config_get_value_string(
		&config_list, "disk.voldir", "/volumes");
	config->disk.exportsdir = config_get_value_string(
		&config_list, "disk.exportsdir", "/exports");
	config->disk.writabledir = config_get_value_string(
		&config_list, "disk.writabledir", "/writable");

	config->net.brdev =
		config_get_value_string(&config_list, "net.brdev", "lxcbr0");
	config->net.braddress4 = config_get_value_string(
		&config_list, "net.braddress4", "10.0.3.1");
	config->net.brmask4 = config_get_value_string(
		&config_list, "net.brmask4", "255.255.255.0");

	config->updater.commit_delay =
		config_get_value_int(&config_list, "updater.commit.delay", 25);
	config->updater.goals_timeout = config_get_value_int(
		&config_list, "updater.goals.timeout", 2 * 60);
	config->updater.use_tmp_objects = config_get_value_bool(
		&config_list, "updater.use_tmp_objects", false);

	config->updater.revision_retries =
		config_get_value_int(&config_list, "revision.retries", 10);
	config->updater.revision_retry_timeout = config_get_value_int(
		&config_list, "revision.retries.timeout", 2 * 60);

	config->wdt.enabled =
		config_get_value_bool(&config_list, "wdt.enabled", true);
	config->wdt.mode = config_get_value_wdt_mode_type(
		&config_list, "wdt.mode", WDT_SHUTDOWN);
	config->wdt.timeout =
		config_get_value_int(&config_list, "wdt.timeout", 15);

	config->log.logdir = config_get_value_string(&config_list, "log.dir",
						     "/storage/logs/");
	config->log.server.outputs = config_get_value_log_server_outputs(
		&config_list, "log.server.outputs",
		LOG_SERVER_OUTPUT_FILE_TREE);
	config->log.logmax = config_get_value_int(&config_list, "log.maxsize",
						  (1 << 21)); // 2 MiB
	config->log.loglevel =
		config_get_value_int(&config_list, "log.level", 0);
	config->log.logsize =
		config_get_value_int(&config_list, "log.buf_nitems", 128);
	config->log.capture =
		config_get_value_bool(&config_list, "log.capture", true);
	config->log.loggers =
		config_get_value_bool(&config_list, "log.loggers", true);
	config->log.std_out =
		config_get_value_bool(&config_list, "log.stdout", false);
	config_override_value_string(&config_list, "log.dir",
				     &config->log.logdir);
	config->log.dmesg =
		config_get_value_bool(&config_list, "log.capture.dmesg", false);
	config->log.ts_filetree_fmt = config_get_value_string(
		&config_list, "log.filetree.timestamp.format", NULL);
	config->log.ts_singlefile_fmt = config_get_value_string(
		&config_list, "log.singlefile.timestamp.format", NULL);
	config->log.ts_stdout_fmt = config_get_value_string(
		&config_list, "log.stdout.timestamp.format", NULL);

	config->libthttp.loglevel =
		config_get_value_int(&config_list, "libthttp.log.level", 3);

	config->libthttp.certdir = config_get_value_string(
		&config_list, "libthttp.certsdir", "/certs");

	config->lxc.log_level =
		config_get_value_int(&config_list, "lxc.log.level", 2);

	config->control.remote =
		config_get_value_bool(&config_list, "control.remote", true);

	config->secureboot.mode = config_get_value_sb_mode_type(
		&config_list, "secureboot.mode", SB_LENIENT);
	config->secureboot.truststore = config_get_value_string(
		&config_list, "secureboot.truststore", PVS_CERT_DEFAULT_STORE);
	config->secureboot.checksum = config_get_value_bool(
		&config_list, "secureboot.checksum", true);
	config->secureboot.handlers = config_get_value_bool(
		&config_list, "secureboot.handlers", true);

	config_iterate_items_prefix(&config_list, config_sysctl_apply,
				    "sysctl.", NULL);

	if (!config_has_value(&config_list, "sysctl.kernel.core_pattern")) {
		config_sysctl_apply("sysctl.kernel.core_pattern",
				    "|/lib/pv/pvcrash --skip", NULL);
	}

	config_clear_items(&config_list);

	return 0;
}

static int pv_config_load_creds_from_file(char *path,
					  struct pantavisor_config *config)
{
	DEFINE_DL_LIST(config_list);

	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	// for overrides
	config_parse_cmdline(&config_list, "ph_");

	config->creds.type =
		config_get_value_string(&config_list, "creds.type", "builtin");
	config->creds.host = config_get_value_string(&config_list, "creds.host",
						     "192.168.53.1");
	config->creds.port =
		config_get_value_int(&config_list, "creds.port", 12365);
	config->creds.host_proxy =
		config_get_value_string(&config_list, "creds.proxy.host", NULL);
	config->creds.port_proxy =
		config_get_value_int(&config_list, "creds.proxy.port", 3218);
	config->creds.noproxyconnect = config_get_value_int(
		&config_list, "creds.proxy.noproxyconnect", 0);
	config->creds.id =
		config_get_value_string(&config_list, "creds.id", NULL);
	config->creds.prn =
		config_get_value_string(&config_list, "creds.prn", NULL);
	config->creds.secret =
		config_get_value_string(&config_list, "creds.secret", NULL);

	config->creds.tpm.key =
		config_get_value_string(&config_list, "creds.tpm.key", NULL);
	config->creds.tpm.cert =
		config_get_value_string(&config_list, "creds.tpm.cert", NULL);

	config->factory.autotok =
		config_get_value_string(&config_list, "factory.autotok", NULL);

	config->updater.interval =
		config_get_value_int(&config_list, "updater.interval", 60);
	config->updater.network_timeout = config_get_value_int(
		&config_list, "updater.network_timeout", 2 * 60);

	config->log.push =
		config_get_value_bool(&config_list, "log.push", true);

	config->metadata.devmeta_interval = config_get_value_int(
		&config_list, "metadata.devmeta.interval", 10);
	config->metadata.usrmeta_interval = config_get_value_int(
		&config_list, "metadata.usrmeta.interval", 5);

	config_clear_items(&config_list);

	return 0;
}

static int pv_config_override_config_from_file(char *path,
					       struct pantavisor_config *config)
{
	DEFINE_DL_LIST(config_list);

	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	config_override_value_string(&config_list, "creds.proxy.host",
				     &config->creds.host_proxy);
	config_override_value_int(&config_list, "creds.proxy.port",
				  &config->creds.port_proxy);
	config_override_value_int(&config_list, "creds.proxy.noproxyconnect",
				  &config->creds.noproxyconnect);
	config_override_value_int(&config_list, "storage.gc.reserved",
				  &config->storage.gc.reserved);
	config_override_value_bool(&config_list, "storage.gc.keep_factory",
				   &config->storage.gc.keep_factory);
	config_override_value_int(&config_list, "storage.gc.threshold",
				  &config->storage.gc.threshold);
	config_override_value_int(&config_list,
				  "storage.gc.threshold.defertime",
				  &config->storage.gc.threshold_defertime);

	config_override_value_bool(&config_list, "updater.use_tmp_objects",
				   &config->updater.use_tmp_objects);
	config_override_value_int(&config_list, "revision.retries",
				  &config->updater.revision_retries);
	config_override_value_int(&config_list, "revision.retries.timeout",
				  &config->updater.revision_retry_timeout);
	config_override_value_bool(&config_list, "updater.keep_factory",
				   &config->storage.gc.keep_factory);
	config_override_value_int(&config_list, "updater.interval",
				  &config->updater.interval);
	config_override_value_int(&config_list, "updater.goals.timeout",
				  &config->updater.goals_timeout);
	config_override_value_int(&config_list, "updater.network_timeout",
				  &config->updater.network_timeout);
	config_override_value_int(&config_list, "updater.commit.delay",
				  &config->updater.commit_delay);

	config_override_value_int(&config_list, "log.maxsize",
				  &config->log.logmax);
	config_override_value_int(&config_list, "log.level",
				  &config->log.loglevel);
	config_override_value_int(&config_list, "log.buf_nitems",
				  &config->log.logsize);
	config_override_value_bool(&config_list, "log.push", &config->log.push);
	config_override_value_bool(&config_list, "log.capture",
				   &config->log.capture);
	config_override_value_bool(&config_list, "log.loggers",
				   &config->log.loggers);
	config_override_value_bool(&config_list, "log.stdout",
				   &config->log.std_out);
	config_override_value_log_server_outputs(&config_list,
						 "log.server.outputs",
						 &config->log.server.outputs);
	config_override_value_bool(&config_list, "log.capture.dmesg",
				   &config->log.dmesg);
	config_override_value_int(&config_list, "libthttp.log.level",
				  &config->libthttp.loglevel);
	config_override_value_int(&config_list, "metadata.devmeta.interval",
				  &config->metadata.devmeta_interval);
	config_override_value_int(&config_list, "metadata.usrmeta.interval",
				  &config->metadata.usrmeta_interval);
	config_override_value_int(&config_list, "lxc.log.level",
				  &config->lxc.log_level);

	config_clear_items(&config_list);

	return 0;
}

static int write_config_tuple_string(int fd, char *key, char *value)
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

static int write_config_tuple_int(int fd, char *key, int value)
{
	char buf[MAX_DEC_STRING_SIZE_OF_TYPE(int)];

	SNPRINTF_WTRUNC(buf, sizeof(buf), "%d", value);

	return write_config_tuple_string(fd, key, buf);
}

static int pv_config_save_creds_to_file(struct pantavisor_config *config,
					char *path)
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

	write_config_tuple_string(fd, "creds.type", config->creds.type);
	write_config_tuple_string(fd, "creds.host", config->creds.host);
	write_config_tuple_int(fd, "creds.port", config->creds.port);
	if (config->creds.host_proxy) {
		write_config_tuple_string(fd, "creds.proxy.host",
					  config->creds.host_proxy);
		write_config_tuple_int(fd, "creds.proxy.port",
				       config->creds.port_proxy);
		write_config_tuple_int(fd, "creds.proxy.noproxyconnect",
				       config->creds.noproxyconnect);
	}
	write_config_tuple_string(fd, "creds.id", config->creds.id);
	write_config_tuple_string(fd, "creds.prn", config->creds.prn);
	write_config_tuple_string(fd, "creds.secret", config->creds.secret);

	write_config_tuple_string(fd, "creds.tpm.key", config->creds.tpm.key);
	write_config_tuple_string(fd, "creds.tpm.cert", config->creds.tpm.cert);

	write_config_tuple_int(fd, "debug.ssh", config->debug.ssh);

	write_config_tuple_int(fd, "updater.interval",
			       config->updater.interval);
	write_config_tuple_int(fd, "updater.network_timeout",
			       config->updater.network_timeout);

	write_config_tuple_int(fd, "log.push", config->log.push);

	write_config_tuple_int(fd, "metadata.devmeta.interval",
			       config->metadata.devmeta_interval);
	write_config_tuple_int(fd, "metadata.usrmeta.interval",
			       config->metadata.usrmeta_interval);

	close(fd);
	if (pv_fs_path_rename(tmp_path, path) < 0) {
		pv_log(ERROR, "could not rename: %s", strerror(errno));
		return -1;
	}

	return 0;
}

int pv_config_load_unclaimed_creds()
{
	struct pantavisor *pv = pv_get_instance();
	char path[PATH_MAX];
	struct stat st;

	pv_paths_storage_config_file(path, PATH_MAX, UNCLAIMED_FNAME);

	if (stat(path, &st))
		return 0;

	if (pv_config_load_creds_from_file(path, &pv->config)) {
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

	if (pv_config_save_creds_to_file(&pv->config, path)) {
		pv_log(ERROR, "cannot save creds in %s", path);
		return -1;
	}

	return 0;
}

void pv_config_override_value(const char *key, const char *value)
{
	struct pantavisor *pv = pv_get_instance();

	if (!key || !value)
		return;

	if (!strcmp(key, "storage.gc.reserved"))
		pv->config.storage.gc.reserved = atoi(value);
	else if (!strcmp(key, "storage.gc.keep_factory"))
		pv->config.storage.gc.keep_factory = atoi(value);
	else if (!strcmp(key, "storage.gc.threshold"))
		pv->config.storage.gc.threshold = atoi(value);
	else if (!strcmp(key, "storage.gc.threshold.defertime"))
		pv->config.storage.gc.threshold_defertime = atoi(value);
	else if (!strcmp(key, "updater.interval"))
		pv->config.updater.interval = atoi(value);
	else if (!strcmp(key, "log.level"))
		pv->config.log.loglevel = atoi(value);
	else if (!strcmp(key, "pantahub.log.push") || !strcmp(key, "log.push"))
		pv->config.log.push = atoi(value);
	else if (!strcmp(key, "libthttp.log.level"))
		pv->config.libthttp.loglevel = atoi(value);
	else if (!strcmp(key, "metadata.devmeta.interval"))
		pv->config.metadata.devmeta_interval = atoi(value);
	else if (!strcmp(key, "metadata.usrmeta.interval"))
		pv->config.metadata.usrmeta_interval = atoi(value);
	else if (!strcmp(key, "debug.ssh"))
		pv->config.debug.ssh = atoi(value);
}

void pv_config_free()
{
	struct pantavisor *pv = pv_get_instance();

	if (pv->config.policy)
		free(pv->config.policy);

	if (pv->config.sys.libdir)
		free(pv->config.sys.libdir);
	if (pv->config.sys.etcdir)
		free(pv->config.sys.etcdir);
	if (pv->config.sys.usrdir)
		free(pv->config.sys.usrdir);
	if (pv->config.sys.rundir)
		free(pv->config.sys.rundir);
	if (pv->config.sys.mediadir)
		free(pv->config.sys.mediadir);
	if (pv->config.sys.confdir)
		free(pv->config.sys.confdir);
	if (pv->config.sys.apparmor_profiles)
		free(pv->config.sys.apparmor_profiles);

	if (pv->config.cache.usrmetadir)
		free(pv->config.cache.usrmetadir);
	if (pv->config.cache.devmetadir)
		free(pv->config.cache.devmetadir);
	if (pv->config.cache.dropbearcachedir)
		free(pv->config.cache.dropbearcachedir);

	if (pv->config.debug.ssh_authorized_keys)
		free(pv->config.debug.ssh_authorized_keys);

	if (pv->config.libthttp.certdir)
		free(pv->config.libthttp.certdir);

	if (pv->config.log.logdir)
		free(pv->config.log.logdir);

	if (pv->config.log.ts_filetree_fmt)
		free(pv->config.log.ts_filetree_fmt);
	if (pv->config.log.ts_singlefile_fmt)
		free(pv->config.log.ts_singlefile_fmt);
	if (pv->config.log.ts_stdout_fmt)
		free(pv->config.log.ts_stdout_fmt);

	if (pv->config.net.brdev)
		free(pv->config.net.brdev);
	if (pv->config.net.braddress4)
		free(pv->config.net.braddress4);
	if (pv->config.net.brmask4)
		free(pv->config.net.brmask4);

	if (pv->config.bl.mtd_path)
		free(pv->config.bl.mtd_path);

	if (pv->config.storage.path)
		free(pv->config.storage.path);
	if (pv->config.storage.fstype)
		free(pv->config.storage.fstype);
	if (pv->config.storage.opts)
		free(pv->config.storage.opts);
	if (pv->config.storage.mntpoint)
		free(pv->config.storage.mntpoint);
	if (pv->config.storage.mnttype)
		free(pv->config.storage.mnttype);
	if (pv->config.storage.logtempsize)
		free(pv->config.storage.logtempsize);

	if (pv->config.disk.voldir)
		free(pv->config.disk.voldir);
	if (pv->config.disk.exportsdir)
		free(pv->config.disk.exportsdir);
	if (pv->config.disk.writabledir)
		free(pv->config.disk.writabledir);

	if (pv->config.creds.type)
		free(pv->config.creds.type);
	if (pv->config.creds.host)
		free(pv->config.creds.host);
	if (pv->config.creds.host_proxy)
		free(pv->config.creds.host_proxy);
	if (pv->config.creds.id)
		free(pv->config.creds.id);
	if (pv->config.creds.prn)
		free(pv->config.creds.prn);
	if (pv->config.creds.secret)
		free(pv->config.creds.secret);
	if (pv->config.creds.token)
		free(pv->config.creds.token);

	if (pv->config.creds.tpm.key)
		free(pv->config.creds.tpm.key);
	if (pv->config.creds.tpm.cert)
		free(pv->config.creds.tpm.cert);

	if (pv->config.secureboot.truststore)
		free(pv->config.secureboot.truststore);

	if (pv->config.factory.autotok)
		free(pv->config.factory.autotok);
}

void pv_config_set_system_init_mode(init_mode_t mode)
{
	pv_get_instance()->config.sys.init_mode = mode;
}

void pv_config_set_debug_shell(bool shell)
{
	pv_get_instance()->config.debug.shell = shell;
}
void pv_config_set_debug_shell_autologin(bool shell)
{
	pv_get_instance()->config.debug.shell_autologin = shell;
}
void pv_config_set_debug_ssh(bool ssh)
{
	pv_get_instance()->config.debug.ssh = ssh;
}

inline void pv_config_set_creds_id(char *id)
{
	pv_get_instance()->config.creds.id = id;
}
inline void pv_config_set_creds_prn(char *prn)
{
	pv_get_instance()->config.creds.prn = prn;
}
inline void pv_config_set_creds_secret(char *secret)
{
	pv_get_instance()->config.creds.secret = secret;
}

char *pv_config_get_policy()
{
	return pv_get_instance()->config.policy;
}

init_mode_t pv_config_get_system_init_mode()
{
	return pv_get_instance()->config.sys.init_mode;
}
char *pv_config_get_system_libdir()
{
	return pv_get_instance()->config.sys.libdir;
}
char *pv_config_get_system_etcdir()
{
	return pv_get_instance()->config.sys.etcdir;
}
char *pv_config_get_system_usrdir()
{
	return pv_get_instance()->config.sys.usrdir;
}
char *pv_config_get_system_rundir()
{
	return pv_get_instance()->config.sys.rundir;
}
char *pv_config_get_system_mediadir()
{
	return pv_get_instance()->config.sys.mediadir;
}
char *pv_config_get_system_confdir()
{
	return pv_get_instance()->config.sys.confdir;
}

bool pv_config_get_system_early_driver_load()
{
	return pv_get_instance()->config.sys.auto_load_drivers;
}

bool pv_config_get_system_mount_securityfs()
{
	return pv_get_instance()->config.sys.mount_securityfs;
}
char *pv_config_get_system_apparmor_profiles()
{
	return pv_get_instance()->config.sys.apparmor_profiles;
}
bool pv_config_get_debug_shell()
{
	return pv_get_instance()->config.debug.shell;
}
bool pv_config_get_debug_shell_autologin()
{
	return pv_get_instance()->config.debug.shell_autologin;
}
bool pv_config_get_debug_ssh()
{
	return pv_get_instance()->config.debug.ssh;
}
char *pv_config_get_debug_ssh_authorized_keys()
{
	return pv_get_instance()->config.debug.ssh_authorized_keys;
}
char *pv_config_get_cache_usrmetadir()
{
	return pv_get_instance()->config.cache.usrmetadir;
}
char *pv_config_get_cache_devmetadir()
{
	return pv_get_instance()->config.cache.devmetadir;
}
char *pv_config_get_cache_dropbearcachedir()
{
	return pv_get_instance()->config.cache.dropbearcachedir;
}

char *pv_config_get_creds_type()
{
	return pv_get_instance()->config.creds.type;
}
char *pv_config_get_creds_host()
{
	return pv_get_instance()->config.creds.host;
}
int pv_config_get_creds_port()
{
	return pv_get_instance()->config.creds.port;
}
char *pv_config_get_creds_host_proxy()
{
	return pv_get_instance()->config.creds.host_proxy;
}
int pv_config_get_creds_port_proxy()
{
	return pv_get_instance()->config.creds.port_proxy;
}
int pv_config_get_creds_noproxyconnect()
{
	return pv_get_instance()->config.creds.noproxyconnect;
}
char *pv_config_get_creds_id()
{
	return pv_get_instance()->config.creds.id;
}
char *pv_config_get_creds_prn()
{
	return pv_get_instance()->config.creds.prn;
}
char *pv_config_get_creds_secret()
{
	return pv_get_instance()->config.creds.secret;
}
char *pv_config_get_creds_token()
{
	return pv_get_instance()->config.creds.token;
}

char *pv_config_get_creds_tpm_key()
{
	return pv_get_instance()->config.creds.tpm.key;
}
char *pv_config_get_creds_tpm_cert()
{
	return pv_get_instance()->config.creds.tpm.cert;
}

char *pv_config_get_factory_autotok()
{
	return pv_get_instance()->config.factory.autotok;
}

char *pv_config_get_storage_path()
{
	return pv_get_instance()->config.storage.path;
}
char *pv_config_get_storage_fstype()
{
	return pv_get_instance()->config.storage.fstype;
}
char *pv_config_get_storage_opts()
{
	return pv_get_instance()->config.storage.opts;
}
char *pv_config_get_storage_mntpoint()
{
	return pv_get_instance()->config.storage.mntpoint;
}
char *pv_config_get_storage_mnttype()
{
	return pv_get_instance()->config.storage.mnttype;
}
char *pv_config_get_storage_logtempsize()
{
	return pv_get_instance()->config.storage.logtempsize;
}
int pv_config_get_storage_wait()
{
	return pv_get_instance()->config.storage.wait;
}

int pv_config_get_storage_gc_reserved()
{
	return pv_get_instance()->config.storage.gc.reserved;
}
bool pv_config_get_storage_gc_keep_factory()
{
	return pv_get_instance()->config.storage.gc.keep_factory;
}
int pv_config_get_storage_gc_threshold()
{
	return pv_get_instance()->config.storage.gc.threshold;
}
int pv_config_get_storage_gc_threshold_defertime()
{
	return pv_get_instance()->config.storage.gc.threshold_defertime;
}

char *pv_config_get_disk_voldir()
{
	return pv_get_instance()->config.disk.voldir;
}
char *pv_config_get_disk_exportsdir()
{
	return pv_get_instance()->config.disk.exportsdir;
}
char *pv_config_get_disk_writabledir()
{
	return pv_get_instance()->config.disk.writabledir;
}

int pv_config_get_updater_interval()
{
	return pv_get_instance()->config.updater.interval;
}
int pv_config_get_updater_goals_timeout()
{
	return pv_get_instance()->config.updater.goals_timeout;
}
int pv_config_get_updater_network_timeout()
{
	return pv_get_instance()->config.updater.network_timeout;
}
bool pv_config_get_updater_network_use_tmp_objects()
{
	return pv_get_instance()->config.updater.use_tmp_objects;
}
int pv_config_get_updater_revision_retries()
{
	return pv_get_instance()->config.updater.revision_retries;
}
int pv_config_get_updater_revision_retry_timeout()
{
	return pv_get_instance()->config.updater.revision_retry_timeout;
}
int pv_config_get_updater_commit_delay()
{
	return pv_get_instance()->config.updater.commit_delay;
}

char *pv_config_get_bl_fitconfig()
{
	return pv_get_instance()->config.bl.fitconfig;
}
int pv_config_get_bl_type()
{
	return pv_get_instance()->config.bl.type;
}
bool pv_config_get_bl_mtd_only()
{
	return pv_get_instance()->config.bl.mtd_only;
}
char *pv_config_get_bl_mtd_path()
{
	return pv_get_instance()->config.bl.mtd_path;
}

bool pv_config_get_watchdog_enabled()
{
	return pv_get_instance()->config.wdt.enabled;
}
wdt_mode_t pv_config_get_watchdog_mode()
{
	return pv_get_instance()->config.wdt.mode;
}
int pv_config_get_watchdog_timeout()
{
	return pv_get_instance()->config.wdt.timeout;
}

char *pv_config_get_network_brdev()
{
	return pv_get_instance()->config.net.brdev;
}
char *pv_config_get_network_braddress4()
{
	return pv_get_instance()->config.net.braddress4;
}
char *pv_config_get_network_brmask4()
{
	return pv_get_instance()->config.net.brmask4;
}
char *pv_config_get_log_logdir()
{
	return pv_get_instance()->config.log.logdir;
}
int pv_config_get_log_logmax()
{
	return pv_get_instance()->config.log.logmax;
}
int pv_config_get_log_loglevel()
{
	return pv_get_instance()->config.log.loglevel;
}
int pv_config_get_log_logsize()
{
	return pv_get_instance()->config.log.logsize;
}
bool pv_config_get_log_push()
{
	return pv_get_instance()->config.log.push;
}
bool pv_config_get_log_capture()
{
	return pv_get_instance()->config.log.capture;
}
bool pv_config_get_log_loggers()
{
	return pv_get_instance()->config.log.loggers;
}
bool pv_config_get_log_stdout()
{
	return pv_get_instance()->config.log.std_out;
}
char *pv_config_get_log_filetree_timestamp_format()
{
	return pv_get_instance()->config.log.ts_filetree_fmt;
}
char *pv_config_get_log_singlefile_timestamp_format()
{
	return pv_get_instance()->config.log.ts_singlefile_fmt;
}
char *pv_config_get_log_stdout_timestamp_format()
{
	return pv_get_instance()->config.log.ts_stdout_fmt;
}
int pv_config_get_log_server_outputs()
{
	return pv_get_instance()->config.log.server.outputs;
}
bool pv_config_get_log_server_output_file_tree()
{
	return pv_get_instance()->config.log.server.outputs &
	       LOG_SERVER_OUTPUT_FILE_TREE;
}
bool pv_config_get_log_server_output_single_file()
{
	return pv_get_instance()->config.log.server.outputs &
	       LOG_SERVER_OUTPUT_SINGLE_FILE;
}

bool pv_config_get_log_server_output_stdout()
{
	return pv_get_instance()->config.log.server.outputs &
	       LOG_SERVER_OUTPUT_STDOUT;
}

bool pv_config_get_log_capture_dmesg()
{
	return pv_get_instance()->config.log.dmesg;
}

int pv_config_get_libthttp_loglevel()
{
	return pv_get_instance()->config.libthttp.loglevel;
}

char *pv_config_get_libthttp_certdir()
{
	return pv_get_instance()->config.libthttp.certdir;
}

int pv_config_get_lxc_loglevel()
{
	return pv_get_instance()->config.lxc.log_level;
}

bool pv_config_get_control_remote()
{
	return pv_get_instance()->config.control.remote;
}

secureboot_mode_t pv_config_get_secureboot_mode()
{
	return pv_get_instance()->config.secureboot.mode;
}

bool pv_config_get_secureboot_checksum()
{
	return pv_get_instance()->config.secureboot.checksum;
}

bool pv_config_get_secureboot_handlers()
{
	return pv_get_instance()->config.secureboot.handlers;
}

char *pv_config_get_secureboot_truststore()
{
	return pv_get_instance()->config.secureboot.truststore;
}

int pv_config_get_metadata_devmeta_interval()
{
	return pv_get_instance()->config.metadata.devmeta_interval;
}

int pv_config_get_metadata_usrmeta_interval()
{
	return pv_get_instance()->config.metadata.usrmeta_interval;
}

char *pv_config_get_json()
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, 512);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "policy");
		pv_json_ser_string(&js, pv_config_get_policy());
		pv_json_ser_key(&js, "system.init.mode");
		pv_json_ser_number(&js, pv_config_get_system_init_mode());
		pv_json_ser_key(&js, "system.libdir");
		pv_json_ser_string(&js, pv_config_get_system_libdir());
		pv_json_ser_key(&js, "system.etcdir");
		pv_json_ser_string(&js, pv_config_get_system_etcdir());
		pv_json_ser_key(&js, "system.rundir");
		pv_json_ser_string(&js, pv_config_get_system_rundir());
		pv_json_ser_key(&js, "system.usrdir");
		pv_json_ser_string(&js, pv_config_get_system_usrdir());
		pv_json_ser_key(&js, "system.mediadir");
		pv_json_ser_string(&js, pv_config_get_system_mediadir());
		pv_json_ser_key(&js, "system.confdir");
		pv_json_ser_string(&js, pv_config_get_system_confdir());
		pv_json_ser_key(&js, "system.drivers.load_early.auto");
		pv_json_ser_bool(&js, pv_config_get_system_early_driver_load());
		pv_json_ser_key(&js, "system.mount.securityfs");
		pv_json_ser_bool(&js, pv_config_get_system_mount_securityfs());
		pv_json_ser_key(&js, "system.apparmor.profiles");
		pv_json_ser_bool(&js, pv_config_get_system_apparmor_profiles());
		pv_json_ser_key(&js, "debug.shell");
		pv_json_ser_bool(&js, pv_config_get_debug_shell());
		pv_json_ser_key(&js, "debug.shell.autologin");
		pv_json_ser_bool(&js, pv_config_get_debug_shell_autologin());
		pv_json_ser_key(&js, "debug.ssh");
		pv_json_ser_bool(&js, pv_config_get_debug_ssh());
		pv_json_ser_key(&js, "debug.ssh_authorized_keys");
		pv_json_ser_string(&js,
				   pv_config_get_debug_ssh_authorized_keys());
		pv_json_ser_key(&js, "dropbear.cache.dir");
		pv_json_ser_string(&js, pv_config_get_cache_dropbearcachedir());
		pv_json_ser_key(&js, "cache.usrmetadir");
		pv_json_ser_string(&js, pv_config_get_cache_usrmetadir());
		pv_json_ser_key(&js, "cache.devmetadir");
		pv_json_ser_string(&js, pv_config_get_cache_devmetadir());
		pv_json_ser_key(&js, "bootloader.fitconfig");
		pv_json_ser_string(&js, pv_config_get_bl_fitconfig());
		pv_json_ser_key(&js, "bootloader.type");
		pv_json_ser_number(&js, pv_config_get_bl_type());
		pv_json_ser_key(&js, "bootloader.mtd_only");
		pv_json_ser_bool(&js, pv_config_get_bl_mtd_only());
		pv_json_ser_key(&js, "bootloader.mtd_env");
		pv_json_ser_string(&js, pv_config_get_bl_mtd_path());
		pv_json_ser_key(&js, "secureboot.mode");
		pv_json_ser_number(&js, pv_config_get_secureboot_mode());
		pv_json_ser_key(&js, "secureboot.truststore");
		pv_json_ser_string(&js, pv_config_get_secureboot_truststore());
		pv_json_ser_key(&js, "secureboot.checksum");
		pv_json_ser_bool(&js, pv_config_get_secureboot_checksum());
		pv_json_ser_key(&js, "secureboot.handlers");
		pv_json_ser_bool(&js, pv_config_get_secureboot_handlers());
		pv_json_ser_key(&js, "storage.device");
		pv_json_ser_string(&js, pv_config_get_storage_path());
		pv_json_ser_key(&js, "storage.fstype");
		pv_json_ser_string(&js, pv_config_get_storage_fstype());
		pv_json_ser_key(&js, "storage.opts");
		pv_json_ser_string(&js, pv_config_get_storage_opts());
		pv_json_ser_key(&js, "storage.mntpoint");
		pv_json_ser_string(&js, pv_config_get_storage_mntpoint());
		pv_json_ser_key(&js, "storage.mnttype");
		pv_json_ser_string(&js, pv_config_get_storage_mnttype());
		pv_json_ser_key(&js, "storage.logtempsize");
		pv_json_ser_string(&js, pv_config_get_storage_logtempsize());
		pv_json_ser_key(&js, "storage.wait");
		pv_json_ser_number(&js, pv_config_get_storage_wait());
		pv_json_ser_key(&js, "storage.gc.reserved");
		pv_json_ser_number(&js, pv_config_get_storage_gc_reserved());
		pv_json_ser_key(&js, "storage.gc.keep_factory");
		pv_json_ser_bool(&js, pv_config_get_storage_gc_keep_factory());
		pv_json_ser_key(&js, "storage.gc.threshold");
		pv_json_ser_number(&js, pv_config_get_storage_gc_threshold());
		pv_json_ser_key(&js, "storage.gc.threshold.defertime");
		pv_json_ser_number(
			&js, pv_config_get_storage_gc_threshold_defertime());
		pv_json_ser_key(&js, "disk.voldir");
		pv_json_ser_string(&js, pv_config_get_disk_voldir());
		pv_json_ser_key(&js, "disk.exportsdir");
		pv_json_ser_string(&js, pv_config_get_disk_exportsdir());
		pv_json_ser_key(&js, "disk.writabledir");
		pv_json_ser_string(&js, pv_config_get_disk_writabledir());
		pv_json_ser_key(&js, "updater.use_tmp_objects");
		pv_json_ser_bool(
			&js, pv_config_get_updater_network_use_tmp_objects());
		pv_json_ser_key(&js, "updater.goals.timeout");
		pv_json_ser_number(&js, pv_config_get_updater_goals_timeout());
		pv_json_ser_key(&js, "revision.retries");
		pv_json_ser_number(&js,
				   pv_config_get_updater_revision_retries());
		pv_json_ser_key(&js, "revision.retries.timeout");
		pv_json_ser_number(
			&js, pv_config_get_updater_revision_retry_timeout());
		pv_json_ser_key(&js, "wdt.enabled");
		pv_json_ser_bool(&js, pv_config_get_watchdog_enabled());
		pv_json_ser_key(&js, "wdt.mode");
		pv_json_ser_number(&js, pv_config_get_watchdog_mode());
		pv_json_ser_key(&js, "wdt.timeout");
		pv_json_ser_number(&js, pv_config_get_watchdog_timeout());
		pv_json_ser_key(&js, "net.brdev");
		pv_json_ser_string(&js, pv_config_get_network_brdev());
		pv_json_ser_key(&js, "net.braddress4");
		pv_json_ser_string(&js, pv_config_get_network_braddress4());
		pv_json_ser_key(&js, "net.brmask4");
		pv_json_ser_string(&js, pv_config_get_network_brmask4());
		pv_json_ser_key(&js, "lxc.log.level");
		pv_json_ser_number(&js, pv_config_get_lxc_loglevel());
		pv_json_ser_key(&js, "control.remote");
		pv_json_ser_bool(&js, pv_config_get_control_remote());

		pv_json_ser_key(&js, "creds.type");
		pv_json_ser_string(&js, pv_config_get_creds_type());
		pv_json_ser_key(&js, "creds.host");
		pv_json_ser_string(&js, pv_config_get_creds_host());
		pv_json_ser_key(&js, "creds.port");
		pv_json_ser_number(&js, pv_config_get_creds_port());
		pv_json_ser_key(&js, "creds.proxy.host");
		pv_json_ser_string(&js, pv_config_get_creds_host_proxy());
		pv_json_ser_key(&js, "creds.proxy.port");
		pv_json_ser_number(&js, pv_config_get_creds_port_proxy());
		pv_json_ser_key(&js, "creds.proxy.noproxyconnect");
		pv_json_ser_number(&js, pv_config_get_creds_noproxyconnect());
		pv_json_ser_key(&js, "creds.id");
		pv_json_ser_string(&js, pv_config_get_creds_id());
		pv_json_ser_key(&js, "creds.prn");
		pv_json_ser_string(&js, pv_config_get_creds_prn());
		pv_json_ser_key(&js, "creds.secret");
		pv_json_ser_string(&js, pv_config_get_creds_secret());
		pv_json_ser_key(&js, "creds.tpm.key");
		pv_json_ser_string(&js, pv_config_get_creds_tpm_key());
		pv_json_ser_key(&js, "creds.tpm.cert");
		pv_json_ser_string(&js, pv_config_get_creds_tpm_cert());
		pv_json_ser_key(&js, "factory.autotok");
		pv_json_ser_string(&js, pv_config_get_factory_autotok());
		pv_json_ser_key(&js, "updater.keep_factory");
		pv_json_ser_bool(&js, pv_config_get_storage_gc_keep_factory());
		pv_json_ser_key(&js, "updater.interval");
		pv_json_ser_number(&js, pv_config_get_updater_interval());
		pv_json_ser_key(&js, "updater.network_timeout");
		pv_json_ser_number(&js,
				   pv_config_get_updater_network_timeout());
		pv_json_ser_key(&js, "updater.commit.delay");
		pv_json_ser_number(&js, pv_config_get_updater_commit_delay());
		pv_json_ser_key(&js, "log.dir");
		pv_json_ser_string(&js, pv_config_get_log_logdir());
		pv_json_ser_key(&js, "log.maxsize");
		pv_json_ser_number(&js, pv_config_get_log_logmax());
		pv_json_ser_key(&js, "log.level");
		pv_json_ser_number(&js, pv_config_get_log_loglevel());
		pv_json_ser_key(&js, "log.buf_nitems");
		pv_json_ser_number(&js, pv_config_get_log_logsize());
		pv_json_ser_key(&js, "log.push");
		pv_json_ser_bool(&js, pv_config_get_log_push());
		pv_json_ser_key(&js, "log.capture");
		pv_json_ser_bool(&js, pv_config_get_log_capture());
		pv_json_ser_key(&js, "log.capture.dmesg");
		pv_json_ser_bool(&js, pv_config_get_log_capture_dmesg());
		pv_json_ser_key(&js, "log.loggers");
		pv_json_ser_bool(&js, pv_config_get_log_loggers());
		pv_json_ser_key(&js, "log.stdout");
		pv_json_ser_bool(&js, pv_config_get_log_stdout());
		pv_json_ser_key(&js, "log.filetree.timestamp.format");
		pv_json_ser_string(
			&js, pv_config_get_log_filetree_timestamp_format());
		pv_json_ser_key(&js, "log.singlefile.timestamp.format");
		pv_json_ser_string(
			&js, pv_config_get_log_singlefile_timestamp_format());
		pv_json_ser_key(&js, "log.stdout.timestamp.format");
		pv_json_ser_string(&js,
				   pv_config_get_log_stdout_timestamp_format());
		pv_json_ser_key(&js, "log.server.outputs");
		pv_json_ser_number(&js, pv_config_get_log_server_outputs());
		pv_json_ser_key(&js, "libthttp.log.level");
		pv_json_ser_number(&js, pv_config_get_libthttp_loglevel());
		pv_json_ser_key(&js, "libthttp.certsdir");
		pv_json_ser_string(&js, pv_config_get_libthttp_certdir());

		pv_json_ser_key(&js, "metadata.devmeta.interval");
		pv_json_ser_number(&js,
				   pv_config_get_metadata_devmeta_interval());
		pv_json_ser_key(&js, "metadata.usrmeta.interval");
		pv_json_ser_number(&js,
				   pv_config_get_metadata_usrmeta_interval());

		pv_json_ser_object_pop(&js);
	}

	return pv_json_ser_str(&js);
}

void pv_config_print()
{
	pv_log(INFO, "policy = '%s'", pv_config_get_policy());
	pv_log(INFO, "system.init.mode = %d", pv_config_get_system_init_mode());
	pv_log(INFO, "system.libdir = '%s'", pv_config_get_system_libdir());
	pv_log(INFO, "system.etcdir = '%s'", pv_config_get_system_etcdir());
	pv_log(INFO, "system.rundir = '%s'", pv_config_get_system_rundir());
	pv_log(INFO, "system.usrdir = '%s'", pv_config_get_system_usrdir());
	pv_log(INFO, "system.mediadir = '%s'", pv_config_get_system_mediadir());
	pv_log(INFO, "system.configdir = '%s'", pv_config_get_system_confdir());
	pv_log(INFO, "system.drivers.load_early.auto = %d",
	       pv_config_get_system_early_driver_load());
	pv_log(INFO, "system.mount.securityfs = %d",
	       pv_config_get_system_mount_securityfs());
	pv_log(INFO, "system.apparmor.profiles = %s",
	       pv_config_get_system_apparmor_profiles());
	pv_log(INFO, "debug.shell = %d", pv_config_get_debug_shell());
	pv_log(INFO, "debug.shell.autologin = %d",
	       pv_config_get_debug_shell_autologin());
	pv_log(INFO, "debug.ssh = %d", pv_config_get_debug_ssh());
	if (pv_config_get_debug_ssh_authorized_keys())
		pv_log(INFO, "debug.ssh_authorized_keys = %s",
		       pv_config_get_debug_ssh_authorized_keys());
	pv_log(INFO, "dropbear.cache.dir = '%s'",
	       pv_config_get_cache_dropbearcachedir());
	pv_log(INFO, "cache.usrmetadir = '%s'",
	       pv_config_get_cache_usrmetadir());
	pv_log(INFO, "cache.devmetadir = '%s'",
	       pv_config_get_cache_devmetadir());
	pv_log(INFO, "bootloader.fitconfig = %s", pv_config_get_bl_fitconfig());
	pv_log(INFO, "bootloader.type = %d", pv_config_get_bl_type());
	pv_log(INFO, "bootloader.mtd_only = %d", pv_config_get_bl_mtd_only());
	pv_log(INFO, "bootloader.mtd_env = '%s'", pv_config_get_bl_mtd_path());
	pv_log(INFO, "secureboot.mode = %d", pv_config_get_secureboot_mode());
	pv_log(INFO, "secureboot.truststore = '%s'",
	       pv_config_get_secureboot_truststore());
	pv_log(INFO, "secureboot.checksum = %d",
	       pv_config_get_secureboot_checksum());
	pv_log(INFO, "secureboot.handlers = %d",
	       pv_config_get_secureboot_handlers());
	pv_log(INFO, "storage.device = '%s'", pv_config_get_storage_path());
	pv_log(INFO, "storage.fstype = '%s'", pv_config_get_storage_fstype());
	pv_log(INFO, "storage.opts = '%s'", pv_config_get_storage_opts());
	pv_log(INFO, "storage.mntpoint = '%s'",
	       pv_config_get_storage_mntpoint());
	pv_log(INFO, "storage.mnttype = '%s'", pv_config_get_storage_mnttype());
	pv_log(INFO, "storage.logtempsize = '%s'",
	       pv_config_get_storage_logtempsize());
	pv_log(INFO, "storage.wait = %d", pv_config_get_storage_wait());
	pv_log(INFO, "storage.gc.reserved = %d",
	       pv_config_get_storage_gc_reserved());
	pv_log(INFO, "storage.gc.keep_factory = %d",
	       pv_config_get_storage_gc_keep_factory());
	pv_log(INFO, "storage.gc.threshold = %d",
	       pv_config_get_storage_gc_threshold());
	pv_log(INFO, "storage.gc.threshold.defertime = %d",
	       pv_config_get_storage_gc_threshold_defertime());
	pv_log(INFO, "disk.voldir = '%s'", pv_config_get_disk_voldir());
	pv_log(INFO, "disk.exportsdir = '%s'", pv_config_get_disk_exportsdir());
	pv_log(INFO, "disk.writabledir = '%s'",
	       pv_config_get_disk_writabledir());
	pv_log(INFO, "updater.use_tmp_objects = %d",
	       pv_config_get_updater_network_use_tmp_objects());
	pv_log(INFO, "updater.goals.timeout = %d",
	       pv_config_get_updater_goals_timeout());
	pv_log(INFO, "revision.retries = %d",
	       pv_config_get_updater_revision_retries());
	pv_log(INFO, "revision.retries.timeout = %d",
	       pv_config_get_updater_revision_retry_timeout());
	pv_log(INFO, "wdt.enabled = %d", pv_config_get_watchdog_enabled());
	pv_log(INFO, "wdt.mode = %d", pv_config_get_watchdog_mode());
	pv_log(INFO, "wdt.timeout = %d", pv_config_get_watchdog_timeout());
	pv_log(INFO, "net.brdev = %d", pv_config_get_network_brdev());
	pv_log(INFO, "net.braddress4 = '%s'",
	       pv_config_get_network_braddress4());
	pv_log(INFO, "net.brmask4 = '%s'", pv_config_get_network_brmask4());
	pv_log(INFO, "lxc.log.level = %d", pv_config_get_lxc_loglevel());
	pv_log(INFO, "control.remote = %d", pv_config_get_control_remote());
	pv_log(INFO, "creds.type= '%s'", pv_config_get_creds_type());
	pv_log(INFO, "creds.host = '%s'", pv_config_get_creds_host());
	pv_log(INFO, "creds.port = %d", pv_config_get_creds_port());
	pv_log(INFO, "creds.host_proxy = '%s'",
	       pv_config_get_creds_host_proxy());
	pv_log(INFO, "creds.port_proxy = %d", pv_config_get_creds_port_proxy());
	pv_log(INFO, "creds.noproxyconnect = %d",
	       pv_config_get_creds_noproxyconnect());
	pv_log(INFO, "creds.id = '%s'", pv_config_get_creds_id());
	pv_log(INFO, "creds.prn = '%s'", pv_config_get_creds_prn());
	pv_log(INFO, "creds.secret = '%s'", pv_config_get_creds_secret());
	pv_log(INFO, "creds.tpm.key = '%s'", pv_config_get_creds_tpm_key());
	pv_log(INFO, "creds.tpm.cert = '%s'", pv_config_get_creds_tpm_cert());
	pv_log(INFO, "factory.autotok = '%s'", pv_config_get_factory_autotok());
	pv_log(INFO, "updater.keep_factory = %d",
	       pv_config_get_storage_gc_keep_factory());
	pv_log(INFO, "updater.interval = %d", pv_config_get_updater_interval());
	pv_log(INFO, "updater.network_timeout = %d",
	       pv_config_get_updater_network_timeout());
	pv_log(INFO, "updater.commit.delay = %d",
	       pv_config_get_updater_commit_delay());
	pv_log(INFO, "log.dir = '%s'", pv_config_get_log_logdir());
	pv_log(INFO, "log.maxsize = %d", pv_config_get_log_logmax());
	pv_log(INFO, "log.level = %d", pv_config_get_log_loglevel());
	pv_log(INFO, "log.buf_nitems = %d", pv_config_get_log_logsize());
	pv_log(INFO, "log.push = %d", pv_config_get_log_push());
	pv_log(INFO, "log.capture = %d", pv_config_get_log_capture());
	pv_log(INFO, "log.capture.dmesg = %d",
	       pv_config_get_log_capture_dmesg());
	pv_log(INFO, "log.loggers = %d", pv_config_get_log_loggers());
	pv_log(INFO, "log.stdout = %d", pv_config_get_log_stdout());

	pv_log(INFO, "log.filetree.timestamp.format = %s",
	       pv_config_get_log_filetree_timestamp_format());
	pv_log(INFO, "log.singlefile.timestamp.format = %s",
	       pv_config_get_log_singlefile_timestamp_format());
	pv_log(INFO, "log.stdout.timestamp.format = %s",
	       pv_config_get_log_stdout_timestamp_format());
	pv_log(INFO, "log.server.outputs = %d",
	       pv_config_get_log_server_outputs());
	pv_log(INFO, "libthttp.loglevel = %d",
	       pv_config_get_libthttp_loglevel());
	pv_log(INFO, "libthttp.certsdir = %s",
	       pv_config_get_libthttp_certdir());
	pv_log(INFO, "metadata.devmeta.interval = %d",
	       pv_config_get_metadata_devmeta_interval());
	pv_log(INFO, "metadata.usrmeta.interval = %d",
	       pv_config_get_metadata_usrmeta_interval());
}

int pv_config_init(char *path)
{
	struct pantavisor *pv = pv_get_instance();

	if (!path)
		path = PV_PANTAVISOR_CONFIG_PATH;

	pv_log(DEBUG, "loading config from %s\n", path);
	if (pv_config_load_file(path, &pv->config) < 0) {
		pv_log(FATAL, "unable to parse %s\n", path);
		return -1;
	}

	return 0;
}

static int pv_config_load_creds(struct pv_init *this)
{
	struct pantavisor *pv = pv_get_instance();
	char path[PATH_MAX];
	struct stat st;

	if (!pv_config_get_control_remote())
		return 0;

	pv_paths_storage_config_file(path, PATH_MAX, PANTAHUB_FNAME);

	if (stat(path, &st)) {
		pv_log(ERROR, "cannot find creds in %s", path);
		return -1;
	}

	if (pv_config_load_creds_from_file(path, &pv->config)) {
		pv_log(ERROR, "cannot load creds from %s", path);
		return -1;
	}

	return 0;
}

static int pv_config_trail(struct pv_init *this)
{
	int res = -1;
	char path[PATH_MAX];
	struct pantavisor *pv = pv_get_instance();
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

	if (pv_config_override_config_from_file(path, &pv->config)) {
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
