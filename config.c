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

#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <linux/limits.h>

#define MODULE_NAME             "config"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "config.h"

#include "init.h"
#include "config_parser.h"
#include "utils.h"

static DEFINE_DL_LIST(config_list);

static char* _config_get_value(char *key)
{
	return config_get_value(&config_list, key);
}

static char* config_get_value_string(char *key, char* default_value)
{
	char *item = _config_get_value(key);

	if (!item)
		item = strdup(default_value);

	return item;
}

static int config_get_value_int(char *key, int default_value)
{
	char *item = _config_get_value(key);
	int value = default_value;

	if (!item)
		return value;

	value = atoi(item);
	free(item);

	return value;
}

static bool config_get_value_bool(char *key, bool default_value)
{
	char *item = _config_get_value(key);
	bool value = default_value;

	if (!item)
		return value;

	value = atoi(item);
	free(item);

	return value;
}

static int config_get_value_bl_type(char *key, int default_value)
{
	char *item = _config_get_value(key);
	bool value = default_value;

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

// Fill config struct after parsing on-initramfs factory config
static int pv_config_from_file(char *path, struct pantavisor_config *config)
{
	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	// for overrides
	config_parse_cmdline(&config_list, "pv_");

	config->cache.dropbearcachedir = config_get_value_string("dropbear.cache.dir", "/storage/cache/dropbear");
	config->cache.metacachedir = config_get_value_string("meta.cache.dir", "/storage/cache/meta");

	config->bl.type = config_get_value_bl_type("bootloader.type", BL_UBOOT_PLAIN);
	config->bl.mtd_only = config_get_value_bool("bootloader.mtd_only", false);
	config->bl.mtd_path = config_get_value_string("bootloader.mtd_env", NULL);

	config->storage.path = config_get_value_string("storage.device", NULL);
	config->storage.fstype = config_get_value_string("storage.fstype", NULL);
	config->storage.opts = config_get_value_string("storage.opts", NULL);
	config->storage.mntpoint = config_get_value_string("storage.mntpoint", NULL);
	config->storage.mnttype = config_get_value_string("storage.mnttype", NULL);
	config->storage.wait = config_get_value_int("storage.wait", 5);

	config->storage.gc.reserved = config_get_value_int("storage.gc.reserved", 5);
	config->storage.gc.keep_factory = config_get_value_bool("storage.gc.keep_factory", false);
	config->storage.gc.threshold = config_get_value_int("storage.gc.threshold", 0);

	config->updater.use_tmp_objects = config_get_value_bool("updater.use_tmp_objects", true);
	config->updater.revision_retries = config_get_value_int("revision.retries", 10);
	config->updater.revision_retry_timeout = config_get_value_int("revision.retries.timeout", 2 * 60);

	config->wdt.enabled = config_get_value_bool("wdt.enabled", true);
	config->wdt.timeout = config_get_value_int("wdt.timeout", 15);

	config->net.brdev = config_get_value_string("net.brdev", "lxcbr0");
	config->net.braddress4 = config_get_value_string("net.braddress4", "10.0.3.1");
	config->net.brmask4 = config_get_value_string("net.brmask4", "255.255.255.0");

	config->lxc.log_level = config_get_value_int("lxc.log.level", 2);

	return 0;
}

// Fill config struct after parsing on-initramfs factory config
static int ph_config_from_file(char *path, struct pantavisor_config *config)
{
	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	// for overrides
	config_parse_cmdline(&config_list, "ph_");

	item = _config_get_value("storage.logtempsize");
	config->storage.logtempsize = item ? strdup(item) : NULL;
	config->creds.type = config_get_value_string("creds.type", "builtin");
	config->creds.host = config_get_value_string("creds.host", "192.168.53.1");
	config->creds.port = config_get_value_int("creds.port", 12365);
	config->creds.id = config_get_value_string("creds.id", NULL);
	config->creds.prn = config_get_value_string("creds.prn", NULL);
	config->creds.secret = config_get_value_string("creds.secret", NULL);

	config->creds.tpm.key = config_get_value_string("creds.tpm.key", NULL);
	config->creds.tpm.cert = config_get_value_string("creds.tpm.cert", NULL);

	config->factory.autotok = config_get_value_string("factory.autotok", NULL);

	config->storage.gc.keep_factory = config_get_value_bool("updater.keep_factory", false);

	config->updater.interval = config_get_value_int("updater.interval", 60);
	config->updater.network_timeout = config_get_value_int("updater.network_timeout", 2 * 60);
	config->updater.commit_delay = config_get_value_int("updater.commit.delay", 3 * 60);

	config->log.logdir = config_get_value_string("log.dir", "/storage/logs/");
	config->log.logmax = config_get_value_int("log.maxsize", (1 << 21)); // 2 MiB
	config->log.loglevel = config_get_value_int("log.level", 0);
	config->log.logsize = config_get_value_int("log.buf_nitems", 128) * 1024;
	config->log.push = config_get_value_bool("log.push", true);
	config->log.capture = config_get_value_bool("log.capture", true);

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

static int ph_config_to_file(struct pantavisor_config *config, char *path)
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
	write_config_tuple_int(fd, "log.buf_nitems", config->log.logsize);

	close(fd);
	rename(tmp_path, path);

	return 0;
}

int pv_config_load()
{
	struct pantavisor *pv = get_pv_instance();
	char config_path[256];
	struct stat st;

	if (pv->flags & DEVICE_UNCLAIMED)
		sprintf(config_path, "%s/config/unclaimed.config", pv->config.storage.mntpoint);
	else
		sprintf(config_path, "%s/config/pantahub.config", pv->config.storage.mntpoint);

	if (stat(config_path, &st))
		return -1;

	return ph_config_from_file(config_path, &pv->config);
}

int pv_config_save()
{
	struct pantavisor *pv = get_pv_instance();
	char config_path[256];

	if (pv->flags & DEVICE_UNCLAIMED)
		sprintf(config_path, "%s/config/unclaimed.config", pv->config.storage.mntpoint);
	else
		sprintf(config_path, "%s/config/pantahub.config", pv->config.storage.mntpoint);

	return ph_config_to_file(&pv->config, config_path);
}

void pv_config_free()
{
	struct pantavisor *pv = get_pv_instance();

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

	if (pv->config.creds.type)
		free(pv->config.creds.type);
	if (pv->config.creds.host)
		free(pv->config.creds.host);
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

inline void pv_config_set_creds_id(char *id)
{
	struct pantavisor *pv = get_pv_instance();

	if (pv->config.creds.id)
		free(pv->config.creds.id);

	pv->config.creds.id = id;
}

inline void pv_config_set_creds_prn(char *prn)
{
	struct pantavisor *pv = get_pv_instance();

	if (pv->config.creds.prn)
		free(pv->config.creds.prn);

	pv->config.creds.prn = prn;
}

inline void pv_config_set_creds_secret(char *secret)
{
	struct pantavisor *pv = get_pv_instance();

	if (pv->config.creds.secret)
		free(pv->config.creds.secret);

	pv->config.creds.secret = secret;
}

static int pv_config_init(struct pv_init *this)
{
	char config_file[256];
	struct pantavisor *pv = get_pv_instance();

	if (pv_config_from_file(PV_CONFIG_FILENAME, &pv->config) < 0) {
		printf("FATAL: unable to parse pantavisor.config");
		return -1;
	}

	sprintf(config_file, "%s/config/pantahub.config", pv->config.storage.mntpoint);
	if (ph_config_from_file(config_file, &pv->config) < 0) {
		printf("FATAL: unable to parse pantahub.config");
		return -1;
	}

	return 0;
}

char* pv_config_get_cache_metacachedir() { return get_pv_instance()->config.cache.metacachedir; }
char* pv_config_get_cache_dropbearcachedir() { return get_pv_instance()->config.cache.dropbearcachedir; }

char* pv_config_get_creds_type() { return get_pv_instance()->config.creds.type; }
char* pv_config_get_creds_host() { return get_pv_instance()->config.creds.host; }
int pv_config_get_creds_port() { return get_pv_instance()->config.creds.port; }
char* pv_config_get_creds_id() { return get_pv_instance()->config.creds.id; }
char* pv_config_get_creds_prn() { return get_pv_instance()->config.creds.prn; }
char* pv_config_get_creds_secret() { return get_pv_instance()->config.creds.secret; }
char* pv_config_get_creds_token() { return get_pv_instance()->config.creds.token; }

char* pv_config_get_factory_autotok() { return get_pv_instance()->config.factory.autotok; }

char* pv_config_get_storage_path() { return get_pv_instance()->config.storage.path; }
char* pv_config_get_storage_fstype() { return get_pv_instance()->config.storage.fstype; }
char* pv_config_get_storage_opts() { return get_pv_instance()->config.storage.opts; }
char* pv_config_get_storage_mntpoint() { return get_pv_instance()->config.storage.mntpoint; }
char* pv_config_get_storage_mnttype() { return get_pv_instance()->config.storage.mnttype; }
int pv_config_get_storage_wait() { return get_pv_instance()->config.storage.wait; }

int pv_config_get_storage_gc_reserved() { return get_pv_instance()->config.storage.gc.reserved; }
bool pv_config_get_storage_gc_keep_factory() { return get_pv_instance()->config.storage.gc.keep_factory; }
int pv_config_get_storage_gc_threshold() { return get_pv_instance()->config.storage.gc.threshold; }

int pv_config_get_updater_interval() { return get_pv_instance()->config.updater.interval; }
int pv_config_get_updater_network_timeout() { return get_pv_instance()->config.updater.network_timeout; }
bool pv_config_get_updater_network_use_tmp_objects() { return get_pv_instance()->config.updater.use_tmp_objects; }
int pv_config_get_updater_revision_retries() { return get_pv_instance()->config.updater.revision_retries; }
int pv_config_get_updater_revision_retry_timeout() { return get_pv_instance()->config.updater.revision_retry_timeout; }
int pv_config_get_updater_commit_delay() { return get_pv_instance()->config.updater.commit_delay; }

int pv_config_get_bl_type() { return get_pv_instance()->config.bl.type; }
bool pv_config_get_bl_mtd_only() { return get_pv_instance()->config.bl.mtd_only; }
char* pv_config_get_bl_mtd_path() { return get_pv_instance()->config.bl.mtd_path; }

bool pv_config_get_watchdog_enabled() { return get_pv_instance()->config.wdt.enabled; }
int pv_config_get_watchdog_timeout() { return get_pv_instance()->config.wdt.timeout; }

char* pv_config_get_network_brdev() { return get_pv_instance()->config.net.brdev; }
char* pv_config_get_network_braddress4() { return get_pv_instance()->config.net.braddress4; }
char* pv_config_get_network_brmask4() { return get_pv_instance()->config.net.brmask4; }

char* pv_config_get_log_logdir() { return get_pv_instance()->config.log.logdir; }
int pv_config_get_log_logmax() { return get_pv_instance()->config.log.logmax; }
int pv_config_get_log_loglevel() { return get_pv_instance()->config.log.loglevel; }
int pv_config_get_log_logsize() { return get_pv_instance()->config.log.logsize; }
bool pv_config_get_log_push() { return get_pv_instance()->config.log.push; }
bool pv_config_get_log_capture() { return get_pv_instance()->config.log.capture; }

struct pv_init pv_init_config =  {
	.init_fn = pv_config_init,
	.flags = 0,
};
