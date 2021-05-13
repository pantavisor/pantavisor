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

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/stat.h>

#include <linux/limits.h>

#include "config.h"
#include "init.h"
#include "config_parser.h"
#include "utils.h"
#include "bootloader.h"
#include "state.h"
#include "storage.h"

#define MODULE_NAME             "config"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static char* config_get_value_string(struct dl_list *config_list, char *key, char* default_value)
{
	char *item = config_get_value(config_list, key);

	if (!item)
		item = default_value;

	if (!item)
		return NULL;

	return strdup(item);
}

static int config_get_value_int(struct dl_list *config_list, char *key, int default_value)
{
	char *item = config_get_value(config_list, key);
	int value = default_value;

	if (!item)
		return value;

	value = atoi(item);

	return value;
}

static bool config_get_value_bool(struct dl_list *config_list, char *key, bool default_value)
{
	char *item = config_get_value(config_list, key);
	bool value = default_value;

	if (!item)
		return value;

	value = atoi(item);

	return value;
}

static int config_get_value_bl_type(struct dl_list *config_list, char *key, int default_value)
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

static int config_get_value_logsize(struct dl_list *config_list, char *key, int default_value)
{
	int value = config_get_value_int(config_list, key, default_value);

	if (value >= 1024)
		value = default_value;

	return value;
}

static void config_override_value_string(struct dl_list *config_list, char *key, char **out)
{
	char *item = config_get_value(config_list, key);

	if (*out)
		free(*out);

	if (item)
		*out = strdup(item);
	else
		*out = NULL;
}

static void config_override_value_int(struct dl_list *config_list, char *key, int *out)
{
	char *item = config_get_value(config_list, key);

	if (item)
		*out = atoi(item);
}

static void config_override_value_bool(struct dl_list *config_list, char *key, bool *out)
{
	char *item = config_get_value(config_list, key);

	if (item)
		*out = atoi(item);
}

static void config_override_value_logsize(struct dl_list *config_list, char *key, int *out)
{
	char *item = config_get_value(config_list, key);

	if (item)
		*out = atoi(item) * 1024;
}

static int pv_config_load_config_from_file(char *path, struct pantavisor_config *config)
{
	DEFINE_DL_LIST(config_list);

	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	// for overrides
	config_parse_cmdline(&config_list, "pv_");

	config->cache.dropbearcachedir = config_get_value_string(&config_list, "dropbear.cache.dir", "/storage/cache/dropbear");
	config->cache.metacachedir = config_get_value_string(&config_list, "meta.cache.dir", "/storage/cache/meta");

	config->bl.type = config_get_value_bl_type(&config_list, "bootloader.type", BL_UBOOT_PLAIN);
	config->bl.mtd_only = config_get_value_bool(&config_list, "bootloader.mtd_only", false);
	config->bl.mtd_path = config_get_value_string(&config_list, "bootloader.mtd_env", NULL);

	config->storage.path = config_get_value_string(&config_list, "storage.device", NULL);
	config->storage.fstype = config_get_value_string(&config_list, "storage.fstype", NULL);
	config->storage.opts = config_get_value_string(&config_list, "storage.opts", NULL);
	config->storage.mntpoint = config_get_value_string(&config_list, "storage.mntpoint", NULL);
	config->storage.mnttype = config_get_value_string(&config_list, "storage.mnttype", NULL);
	config->storage.logtempsize = config_get_value_string(&config_list, "storage.logtempsize", NULL);
	config->storage.wait = config_get_value_int(&config_list, "storage.wait", 5);

	config->storage.gc.reserved = config_get_value_int(&config_list, "storage.gc.reserved", 5);
	config->storage.gc.keep_factory = config_get_value_bool(&config_list, "storage.gc.keep_factory", false);
	config->storage.gc.threshold = config_get_value_int(&config_list, "storage.gc.threshold", 0);

	config->net.brdev = config_get_value_string(&config_list, "net.brdev", "lxcbr0");
	config->net.braddress4 = config_get_value_string(&config_list, "net.braddress4", "10.0.3.1");
	config->net.brmask4 = config_get_value_string(&config_list, "net.brmask4", "255.255.255.0");

	config->updater.use_tmp_objects = config_get_value_bool(&config_list, "updater.use_tmp_objects", false);

	config->updater.revision_retries = config_get_value_int(&config_list, "revision.retries", 10);
	config->updater.revision_retry_timeout = config_get_value_int(&config_list, "revision.retries.timeout", 2 * 60);
	config->wdt.enabled = config_get_value_bool(&config_list, "wdt.enabled", true);
	config->wdt.timeout = config_get_value_int(&config_list, "wdt.timeout", 15);

	config->lxc.log_level = config_get_value_int(&config_list, "lxc.log.level", 2);

	config->control.remote = config_get_value_bool(&config_list, "control.remote", true);

	config_clear_items(&config_list);

	return 0;
}

static int pv_config_load_creds_from_file(char *path, struct pantavisor_config *config)
{
	DEFINE_DL_LIST(config_list);

	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	// for overrides
	config_parse_cmdline(&config_list, "ph_");

	config->creds.type = config_get_value_string(&config_list, "creds.type", "builtin");
	config->creds.host = config_get_value_string(&config_list, "creds.host", "192.168.53.1");
	config->creds.port = config_get_value_int(&config_list, "creds.port", 12365);
	config->creds.host_proxy = config_get_value_string(&config_list, "creds.proxy.host", NULL);
	config->creds.port_proxy = config_get_value_int(&config_list, "creds.proxy.port", 3218);
	config->creds.id = config_get_value_string(&config_list, "creds.id", NULL);
	config->creds.prn = config_get_value_string(&config_list, "creds.prn", NULL);
	config->creds.secret = config_get_value_string(&config_list, "creds.secret", NULL);

	config->creds.tpm.key = config_get_value_string(&config_list, "creds.tpm.key", NULL);
	config->creds.tpm.cert = config_get_value_string(&config_list, "creds.tpm.cert", NULL);

	config->factory.autotok = config_get_value_string(&config_list, "factory.autotok", NULL);

	config->storage.gc.keep_factory = config_get_value_bool(&config_list, "updater.keep_factory", false);
	config->updater.interval = config_get_value_int(&config_list, "updater.interval", 60);
	config->updater.network_timeout = config_get_value_int(&config_list, "updater.network_timeout", 2 * 60);
	config->updater.commit_delay = config_get_value_int(&config_list, "updater.commit.delay", 3 * 60);

	config->log.logdir = config_get_value_string(&config_list, "log.dir", "/storage/logs/");
	config->log.logmax = config_get_value_int(&config_list, "log.maxsize", (1 << 21)); // 2 MiB
	config->log.loglevel = config_get_value_int(&config_list, "log.level", 0);
	config->log.logsize = config_get_value_logsize(&config_list, "log.buf_nitems", 128) * 1024;
	config->log.push = config_get_value_bool(&config_list, "log.push", true);
	config->log.capture = config_get_value_bool(&config_list, "log.capture", true);

	config_clear_items(&config_list);

	return 0;
}

static int pv_config_override_config_from_file(char *path, struct pantavisor_config *config)
{
	DEFINE_DL_LIST(config_list);

	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	config_override_value_string(&config_list, "creds.proxy.host", &config->creds.host_proxy);
	config_override_value_int(&config_list, "creds.proxy.port", &config->creds.port_proxy);
	config_override_value_int(&config_list, "storage.gc.reserved", &config->storage.gc.reserved);
	config_override_value_bool(&config_list, "storage.gc.keep_factory", &config->storage.gc.keep_factory);
	config_override_value_int(&config_list, "storage.gc.threshold", &config->storage.gc.threshold);

	config_override_value_bool(&config_list, "updater.use_tmp_objects", &config->updater.use_tmp_objects);
	config_override_value_int(&config_list, "revision.retries", &config->updater.revision_retries);
	config_override_value_int(&config_list, "revision.retries.timeout", &config->updater.revision_retry_timeout);
	config_override_value_bool(&config_list, "updater.keep_factory", &config->storage.gc.keep_factory);
	config_override_value_int(&config_list, "updater.interval", &config->updater.interval);
	config_override_value_int(&config_list, "updater.network_timeout", &config->updater.network_timeout);
	config_override_value_int(&config_list, "updater.commit.delay", &config->updater.commit_delay);

	config_override_value_int(&config_list, "log.maxsize", &config->log.logmax);
	config_override_value_int(&config_list, "log.level", &config->log.loglevel);
	config_override_value_logsize(&config_list, "log.buf_nitems", &config->log.logsize);
	config_override_value_bool(&config_list, "log.push", &config->log.push);
	config_override_value_bool(&config_list, "log.capture", &config->log.capture);

	config_override_value_int(&config_list, "lxc.log.level", &config->lxc.log_level);

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
	char buf[128];

	sprintf(buf, "%d", value);

	return write_config_tuple_string(fd, key, buf);
}

static int pv_config_save_creds_to_file(struct pantavisor_config *config, char *path)
{
	int fd;
	char tmp_path[PATH_MAX];

	sprintf(tmp_path, "%s-XXXXXX", path);
	mkstemp(tmp_path);
	fd = open(tmp_path, O_RDWR | O_SYNC | O_CREAT | O_TRUNC, 644);
	if (!fd) {
		pv_log(ERROR, "unable to open temporary credentials config");
		return -1;
	}

	write_config_tuple_string(fd, "creds.type", config->creds.type);
	write_config_tuple_string(fd, "creds.host", config->creds.host);
	write_config_tuple_int(fd, "creds.port", config->creds.port);
	if (config->creds.host_proxy) {
		write_config_tuple_string(fd, "creds.proxy.host", config->creds.host_proxy);
		write_config_tuple_int(fd, "creds.proxy.port", config->creds.port_proxy);
	}
	write_config_tuple_string(fd, "creds.id", config->creds.id);
	write_config_tuple_string(fd, "creds.prn", config->creds.prn);
	write_config_tuple_string(fd, "creds.secret", config->creds.secret);

	write_config_tuple_string(fd, "creds.tpm.key", config->creds.tpm.key);
	write_config_tuple_string(fd, "creds.tpm.cert", config->creds.tpm.cert);

	write_config_tuple_int(fd, "updater.interval", config->updater.interval);
	write_config_tuple_int(fd, "updater.network_timeout", config->updater.network_timeout);
	write_config_tuple_int(fd, "updater.commit.delay", config->updater.commit_delay);
	write_config_tuple_int(fd, "updater.keep_factory", config->storage.gc.keep_factory); // deprecated

	write_config_tuple_int(fd, "log.level", config->log.loglevel);
	write_config_tuple_int(fd, "log.buf_nitems", config->log.logsize / 1024);

	close(fd);
	rename(tmp_path, path);

	return 0;
}

int pv_config_load_creds()
{
	struct pantavisor *pv = pv_get_instance();
	char config_path[256];
	struct stat st;

	if (pv->unclaimed)
		sprintf(config_path, "%s/config/unclaimed.config", pv->config.storage.mntpoint);
	else
		sprintf(config_path, "%s/config/pantahub.config", pv->config.storage.mntpoint);

	if (stat(config_path, &st))
		return -1;

	return pv_config_load_creds_from_file(config_path, &pv->config);
}

int pv_config_save_creds()
{
	struct pantavisor *pv = pv_get_instance();
	char config_path[256];

	if (pv->unclaimed)
		sprintf(config_path, "%s/config/unclaimed.config", pv->config.storage.mntpoint);
	else
		sprintf(config_path, "%s/config/pantahub.config", pv->config.storage.mntpoint);

	return pv_config_save_creds_to_file(&pv->config, config_path);
}

void pv_config_override_value(char* key, char* value)
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
	else if (!strcmp(key, "updater.interval"))
		pv->config.updater.interval = atoi(value);
	else if (!strcmp(key, "log.level"))
		pv->config.log.loglevel = atoi(value);
	else if (!strcmp(key, "pantahub.log.push") || !strcmp(key, "log.push"))
		pv->config.log.push = atoi(value);
}

void pv_config_free()
{
	struct pantavisor *pv = pv_get_instance();

	if (pv->config.cache.metacachedir)
		free(pv->config.cache.metacachedir);
	if (pv->config.cache.dropbearcachedir)
		free(pv->config.cache.dropbearcachedir);

	if (pv->config.log.logdir)
		free(pv->config.log.logdir);

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

	if (pv->config.factory.autotok)
		free(pv->config.factory.autotok);
}

inline void pv_config_set_creds_id(char *id) { pv_get_instance()->config.creds.id = id; }
inline void pv_config_set_creds_prn(char *prn) { pv_get_instance()->config.creds.prn = prn; }
inline void pv_config_set_creds_secret(char *secret) { pv_get_instance()->config.creds.secret = secret; }

char* pv_config_get_cache_metacachedir() { return pv_get_instance()->config.cache.metacachedir; }
char* pv_config_get_cache_dropbearcachedir() { return pv_get_instance()->config.cache.dropbearcachedir; }

char* pv_config_get_creds_type() { return pv_get_instance()->config.creds.type; }
char* pv_config_get_creds_host() { return pv_get_instance()->config.creds.host; }
int pv_config_get_creds_port() { return pv_get_instance()->config.creds.port; }
char* pv_config_get_creds_host_proxy() { return pv_get_instance()->config.creds.host_proxy; }
int pv_config_get_creds_port_proxy() { return pv_get_instance()->config.creds.port_proxy; }
char* pv_config_get_creds_id() { return pv_get_instance()->config.creds.id; }
char* pv_config_get_creds_prn() { return pv_get_instance()->config.creds.prn; }
char* pv_config_get_creds_secret() { return pv_get_instance()->config.creds.secret; }
char* pv_config_get_creds_token() { return pv_get_instance()->config.creds.token; }

char* pv_config_get_factory_autotok() { return pv_get_instance()->config.factory.autotok; }

char* pv_config_get_storage_path() { return pv_get_instance()->config.storage.path; }
char* pv_config_get_storage_fstype() { return pv_get_instance()->config.storage.fstype; }
char* pv_config_get_storage_opts() { return pv_get_instance()->config.storage.opts; }
char* pv_config_get_storage_mntpoint() { return pv_get_instance()->config.storage.mntpoint; }
char* pv_config_get_storage_mnttype() { return pv_get_instance()->config.storage.mnttype; }
char* pv_config_get_storage_logtempsize() { return pv_get_instance()->config.storage.logtempsize; }
int pv_config_get_storage_wait() { return pv_get_instance()->config.storage.wait; }

int pv_config_get_storage_gc_reserved() { return pv_get_instance()->config.storage.gc.reserved; }
bool pv_config_get_storage_gc_keep_factory() { return pv_get_instance()->config.storage.gc.keep_factory; }
int pv_config_get_storage_gc_threshold() { return pv_get_instance()->config.storage.gc.threshold; }

int pv_config_get_updater_interval() { return pv_get_instance()->config.updater.interval; }
int pv_config_get_updater_network_timeout() { return pv_get_instance()->config.updater.network_timeout; }
bool pv_config_get_updater_network_use_tmp_objects() { return pv_get_instance()->config.updater.use_tmp_objects; }
int pv_config_get_updater_revision_retries() { return pv_get_instance()->config.updater.revision_retries; }
int pv_config_get_updater_revision_retry_timeout() { return pv_get_instance()->config.updater.revision_retry_timeout; }
int pv_config_get_updater_commit_delay() { return pv_get_instance()->config.updater.commit_delay; }

int pv_config_get_bl_type() { return pv_get_instance()->config.bl.type; }
bool pv_config_get_bl_mtd_only() { return pv_get_instance()->config.bl.mtd_only; }
char* pv_config_get_bl_mtd_path() { return pv_get_instance()->config.bl.mtd_path; }

bool pv_config_get_watchdog_enabled() { return pv_get_instance()->config.wdt.enabled; }
int pv_config_get_watchdog_timeout() { return pv_get_instance()->config.wdt.timeout; }

char* pv_config_get_network_brdev() { return pv_get_instance()->config.net.brdev; }
char* pv_config_get_network_braddress4() { return pv_get_instance()->config.net.braddress4; }
char* pv_config_get_network_brmask4() { return pv_get_instance()->config.net.brmask4; }

char* pv_config_get_log_logdir() { return pv_get_instance()->config.log.logdir; }
int pv_config_get_log_logmax() { return pv_get_instance()->config.log.logmax; }
int pv_config_get_log_loglevel() { return pv_get_instance()->config.log.loglevel; }
int pv_config_get_log_logsize() { return pv_get_instance()->config.log.logsize; }
bool pv_config_get_log_push() { return pv_get_instance()->config.log.push; }
bool pv_config_get_log_capture() { return pv_get_instance()->config.log.capture; }

bool pv_config_get_control_remote() { return pv_get_instance()->config.control.remote; }

static int pv_config_init(struct pv_init *this)
{
	struct pantavisor *pv = pv_get_instance();

	if (pv_config_load_config_from_file("/etc/pantavisor.config", &pv->config) < 0) {
		printf("FATAL: unable to parse /etc/pantavisor.config\n");
		return -1;
	}

	return 0;
}

static int pv_config_creds(struct pv_init *this)
{
	char config_file[256];
	struct pantavisor *pv = pv_get_instance();

	sprintf(config_file, "%s/config/pantahub.config", pv_config_get_storage_mntpoint());
	if (pv_config_load_creds_from_file(config_file, &pv->config) < 0) {
		printf("FATAL: unable to parse %s/config/pantahub.config\n", pv_config_get_storage_mntpoint());
		return -1;
	}

	return 0;
}

static int pv_config_trail(struct pv_init *this)
{
	char path[PATH_MAX];
	struct pantavisor *pv = pv_get_instance();
	const char *rev = pv_bootloader_get_rev();
	char *config_name;

	config_name = pv_storage_get_initrd_config_name(rev);
	if (!config_name) {
		printf("INFO: initrd config not found\n");
		return 0;
	}

	sprintf(path, "%s/trails/%s/bsp/%s", pv_config_get_storage_mntpoint(), rev, config_name);
	free(config_name);

	if (pv_config_override_config_from_file(path, &pv->config)) {
		printf("FATAL: initrd config %s not found\n", path);
		return -1;
	}

	return 0;
}

struct pv_init pv_init_config =  {
	.init_fn = pv_config_init,
	.flags = 0,
};

struct pv_init pv_init_creds =  {
	.init_fn = pv_config_creds,
	.flags = 0,
};

struct pv_init pv_init_config_trail =  {
	.init_fn = pv_config_trail,
	.flags = 0,
};
