/*
 * Copyright (c) 2017-2020 Pantacor Ltd.
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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#define MODULE_NAME             "config"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"
#include "utils.h"
#include "utils/list.h"
#include "init.h"

struct config_item {
	char *key;
	char *value;
	struct config_item *next;
	struct dl_list list;
};

static DEFINE_DL_LIST(config_list);

static struct config_item* _config_get_by_key(struct dl_list *list, char *key)
{
	struct config_item *curr = NULL, *tmp;
	if (key == NULL || dl_list_empty(list))
		return NULL;

	dl_list_for_each_safe(curr, tmp, list,
			      struct config_item, list) {
		if (strcmp(curr->key, key) == 0)
			return curr;
	}
	// Value not found
	return NULL;
}

static struct config_item* _config_add_item(struct dl_list *list,
						char *key, char *value)
{
	struct config_item *this;

	// Check if it already exists in config and change value instead
	this = _config_get_by_key(list, key);
	if (this) {
		if (this->value)
			free(this->value);

		this->value = strdup(value);
		return this;
	}

	// New item
	this = (struct config_item *) malloc(sizeof(struct config_item));

	if (!this) {
		pv_log(ERROR, "unable to allocate config item");
		goto out;
	}

	// Check empty key
	if (strcmp(key, "") == 0) {
		goto out;
	}
	// Set key
	this->key = strdup(key);

	// Check for empty value
	if (value)
		this->value = strdup(value);
	else
		this->value = strdup(""); // Empty value
	if (this->key && this->value)
		dl_list_add_tail(list, &this->list);
	else {
		goto out;
	}
	return this;
out:
	if (this && this->key)
		free(this->key);
	if (this && this->value)
		free(this->value);
	free(this);
	return NULL;
}

char* config_get_value(struct dl_list *list, char *key)
{
	struct config_item *curr = _config_get_by_key(list, key);

	if (curr)
		return curr->value;
	// Value not found
	return NULL;
}

static char* _config_get_value(char *key)
{
	return config_get_value(&config_list, key);
}

static struct config_item* _config_replace_item(struct dl_list *list,
						char *key, char *value)
{
	struct config_item *curr = NULL;

	if (key == NULL || dl_list_empty(list))
		return NULL;

	curr = _config_get_by_key(list, key);
	if (curr) {
		char *tmp_val = strdup(value);

		if (tmp_val) {
			free(curr->value);
			curr->value = tmp_val;
		}
		return curr;
	}
	// not found? add it
	return _config_add_item(list, key, value);
}

void config_clear_items(struct dl_list *list)
{
	struct config_item *curr = NULL, *tmp;

	if (dl_list_empty(list))
		return;
	dl_list_for_each_safe(curr, tmp, list,
			struct config_item, list) {
		dl_list_del(&curr->list);
		free(curr->key);
		free(curr->value);
		free(curr);
	}
}

void config_iterate_items(struct dl_list *list, int (*action)(char *key, char *value, void *opaque), void *opaque)
{
	struct config_item *curr = NULL, *tmp;

	if (dl_list_empty(list))
		return;
	if (!action)
		return;
	dl_list_for_each_safe(curr, tmp, list,
			struct config_item, list) {
		if (action(curr->key, curr->value, opaque))
			break;
	}
}

int load_key_value_file(const char *path, struct dl_list *list)
{
	FILE *fp;
	char *buff = NULL, *__real_key = NULL;
	struct stat st;

	fp = fopen(path, "r");
	if (!fp) {
		pv_log(INFO, "unable to find %s config file", path);
		return -1;
	}

	stat(path, &st);
	buff = calloc(1, st.st_size);
	if (!buff)
		goto out;

	while (fgets(buff, st.st_size, fp)) {
		// Remove newline from value (hacky)
		buff[strlen(buff)-1] = '\0';
		char *key = strstr(buff, "=");
		if (key) {
			char *value = key + 1;
			__real_key = (char*) calloc(1, key - buff + 1);
			if (__real_key) {
				sprintf(__real_key, "%.*s", (int)(key - buff), buff);
				_config_add_item(list, __real_key, value);
				free(__real_key);
			}
		}
	}
	free(buff);
out:
	fclose(fp);

	return 0;
}

static int _config_parse_cmdline(char *cmdline, char *hint)
{
	char *buf = NULL, *k = NULL, *nl = NULL;
	char *ptr_out = NULL, *ptr_in = NULL;
	char *token = NULL, *key = NULL, *value = NULL;

	buf = strdup(cmdline);
	token = strtok_r(buf, " ", &ptr_out);
	while (token) {
		if (strncmp(hint, token, strlen(hint)) == 0) {
			k = token + strlen(hint);
			key = strtok_r(k, "=", &ptr_in);
			value = strtok_r(NULL, "\0", &ptr_in);
			/*
			 * for things like XYZ= there would be nothing
			 * in the value as strtok returns only non-empty
			 * strings.
			 * */
			if (!value)
				value = ""; /*We keep the key but give it an empty value*/
			nl = strchr(value, '\n');
			if (nl) /* get rid of newline at end */
				*nl = '\0';
			_config_replace_item(&config_list, key, value);
		}
		token = strtok_r(NULL, " ", &ptr_out);
	}
	free(buf);

	return 0;
}

// Fill config struct after parsing on-initramfs factory config
int pv_config_from_file(char *path, struct pantavisor_config *config)
{
	char *item;
	struct pv_system *system = get_pv_system();

	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	// for overrides
	_config_parse_cmdline(system->cmdline, "pv_");

	item = _config_get_value("bootloader.type");
	if (item && !strcmp(item, "uboot"))
		config->bl.type = BL_UBOOT_PLAIN;
	else if (item && !strcmp(item, "uboot-pvk"))
		config->bl.type = BL_UBOOT_PVK;
	else if (item && !strcmp(item, "grub"))
		config->bl.type = BL_GRUB;

	item = _config_get_value("bootloader.mtd_only");
	if (item)
		config->bl.mtd_only = 1;
	else
		config->bl.mtd_only = 0;

	config->bl.mtd_path = _config_get_value("bootloader.mtd_env");

	config->rundir = getenv ("PV_RUNDIR");
	if (!config->rundir || !strlen(config->rundir))
		config->rundir = _config_get_value("rundir");
	if (!config->rundir || !strlen(config->rundir))
		config->rundir = system->rundir;

	config->pvdir = getenv ("PV_PVDIR");
	if (!config->pvdir || !strlen(config->pvdir))
		config->pvdir = _config_get_value("pvdir");
	if (!config->pvdir || !strlen(config->pvdir))
		config->pvdir = system->pvdir;

	config->etcdir = getenv ("PV_ETCDIR");
	if (!config->etcdir || !strlen(config->etcdir))
		config->etcdir = _config_get_value("etcdir");
	if (!config->etcdir || !strlen(config->etcdir))
		config->etcdir = system->etcdir;


	free(config->pvdir_challenge);
	config->pvdir_challenge = malloc((strlen(config->pvdir) + 1 + strlen("challenge") + 1) * sizeof(char));
	sprintf(config->pvdir_challenge, "%s/%s", config->pvdir, "challenge");

	free(config->pvdir_deviceid);
	config->pvdir_deviceid = malloc((strlen(config->pvdir) + 1 + strlen("device-id") + 1) * sizeof(char));
	sprintf(config->pvdir_deviceid, "%s/%s", config->pvdir, "device-id");

	free(config->pvdir_logsdir);
	config->pvdir_logsdir = malloc((strlen(config->pvdir) + 1 + strlen("logs") + 1) * sizeof(char));
	sprintf(config->pvdir_logsdir, "%s/%s", config->pvdir, "logs");

	free(config->pvdir_pantahubhost);
	config->pvdir_pantahubhost = malloc((strlen(config->pvdir) + 1 + strlen("pantahub-host") + 1) * sizeof(char));
	sprintf(config->pvdir_pantahubhost, "%s/%s", config->pvdir, "pantahub-host");

	free(config->pvdir_pvctrl);
	config->pvdir_pvctrl = malloc((strlen(config->pvdir) + 1 + strlen("pv-ctrl") + 1) * sizeof(char));
	sprintf(config->pvdir_pvctrl, "%s/%s", config->pvdir, "pv-ctrl");

	free(config->pvdir_logctrl);
	config->pvdir_logctrl = malloc((strlen(config->pvdir) + 1 + strlen("pv-ctrl-log") + 1) * sizeof(char));
	sprintf(config->pvdir_logctrl, "%s/%s", config->pvdir, "pv-ctrl-log");

	free(config->pvdir_usermeta);
	config->pvdir_usermeta = malloc((strlen(config->pvdir) + 1 + strlen("user-meta") + 1) * sizeof(char));
	sprintf(config->pvdir_usermeta, "%s/%s", config->pvdir, "user-meta");

	config->storage.path = _config_get_value("storage.device");
	config->storage.fstype = _config_get_value("storage.fstype");
	config->storage.opts = _config_get_value("storage.opts");
	config->storage.mnttype = _config_get_value("storage.mnttype");

	config->storage.mntpoint = _config_get_value("storage.mntpoint");
	if(!config->storage.mntpoint || !strlen(config->storage.mntpoint)){
		/* on embedded systems we default to vardir */
		config->storage.mntpoint = system->vardir;
	}

	item = _config_get_value("wdt.enabled");
	config->wdt.enabled = item ? atoi(item) : 1;

	item = _config_get_value("wdt.timeout");
	config->wdt.timeout = item ? atoi(item) : 15;

	config->net.brdev = _config_get_value("net.brdev");
	if (!config->net.brdev)
		config->net.brdev = strdup("lxcbr0");

	config->net.braddress4 = _config_get_value("net.braddress4");
	if (!config->net.braddress4)
		config->net.braddress4 = strdup("10.0.3.1");

	item = _config_get_value("revision.retries");
	if (item)
		sscanf(item, "%d", &config->revision_retries);

	item = _config_get_value("revision.retries.timeout");
	if (item)
		sscanf(item, "%d", &config->revision_retry_timeout);
	return 0;
}

// Fill config struct after parsing on-initramfs factory config
int ph_config_from_file(char *path, struct pantavisor_config *config)
{
	char *item;
	struct pv_system *system;

	if (load_key_value_file(path, &config_list) < 0)
		return -1;

	system = get_pv_system();

	// for overrides
	_config_parse_cmdline(system->cmdline, "ph_");

	config->logdir = getenv ("PV_LOGDIR");
	if (!config->logdir || !strlen(config->logdir))
		config->logdir = _config_get_value("log.dir");
	if (!config->logdir || !strlen(config->logdir))
		config->logdir = system->logdir;

	if (config->dropbearcachedir) free(config->dropbearcachedir);
	config->dropbearcachedir = _config_get_value("dropbear.cache.dir");
	if (!config->dropbearcachedir) {
		config->dropbearcachedir = calloc (sizeof(char) * (strlen(config->storage.mntpoint) + strlen("/cache/dropbear") + 2),1);
		config->dropbearcachedir = strcpy(config->dropbearcachedir, config->storage.mntpoint);
		config->dropbearcachedir = strcat(config->dropbearcachedir, "/cache/dropbear");
	} else {
		config->dropbearcachedir = strdup(config->dropbearcachedir);
	}

	if (config->metacachedir) free(config->metacachedir);
	config->metacachedir = _config_get_value("meta.cache.dir");
	if (!config->metacachedir) {
		config->metacachedir = calloc (sizeof(char) * (strlen(config->storage.mntpoint) + strlen("/cache/meta") + 2),1);
		config->metacachedir = strcpy(config->metacachedir, config->storage.mntpoint);
		config->metacachedir = strcat(config->metacachedir, "/cache/meta");
	} else {
		config->metacachedir = strdup(config->metacachedir);
	}

	item = _config_get_value("log.maxsize");
	if (item)
		config->logmax = atoi(item);
	else
		config->logmax = (1 << 21); // 2 MiB

	item = _config_get_value("log.level");
	if (item)
		config->loglevel = atoi(item);

	item = _config_get_value("log.buf_nitems");
	if (item) {
		int size_in_kb = 0;
		if (sscanf(item, "%d", &size_in_kb) == 1) {
			if (size_in_kb <=0 || size_in_kb >= 1024)
				size_in_kb = 128;
			config->logsize = size_in_kb * 1024;
		}
		else
			config->logsize = 128 * 1024;
	}
	else {
		config->logsize = 128 * 1024;
	}

	// default 300 second update interval
	item = _config_get_value("updater.interval");
	if (item)
		config->updater.interval = atoi(item);
	else
		config->updater.interval = 60;

	// default timeout for network-down rollback
	item = _config_get_value("updater.network_timeout");
	if (item)
		config->updater.network_timeout = atoi(item);
	else
		config->updater.network_timeout = 120;

	item = _config_get_value("updater.keep_factory");
	if (item)
		config->updater.keep_factory = atoi(item);

	config->creds.type = _config_get_value("creds.type");
	if (!config->creds.type)
		config->creds.type = strdup("builtin");

	if (!strcmp("builtin", config->creds.type)) {
		pv_log(INFO, "using builtin credential handler");
	} else if (strlen(config->creds.type) >= 4 &&
		!strncmp("ext-", config->creds.type, 4)) {
		pv_log(INFO, "using external credential handler %s", config->creds.type);
	} else {
		pv_log(ERROR, "no valid pantavisor credential type (%s) configured; giving up", config->creds.type);
		return -1;
	}

	config->creds.tpm.key = _config_get_value("creds.tpm.key");
	config->creds.tpm.cert = _config_get_value("creds.tpm.cert");
	config->creds.host = _config_get_value("creds.host");
	if (!config->creds.host) {
		config->creds.host = "192.168.0.2";
		pv_log(INFO, "no host set, using default: '%s'", config->creds.host);
	}

	item = _config_get_value("creds.port");
	if (item)
		config->creds.port = atoi(item);
	else
		config->creds.port = 12365;

	config->creds.id = _config_get_value("creds.id");
	config->creds.prn = _config_get_value("creds.prn");
	config->creds.secret = _config_get_value("creds.secret");
	config->factory.autotok = _config_get_value("factory.autotok");
	item = _config_get_value("updater.commit.delay");
	if (item)
		sscanf(item, "%d", &config->update_commit_delay);
	return 0;
}

static int write_config_tuple(int fd, char *key, char *value)
{
	int bytes = 0;

	bytes = write(fd, key, strlen(key));
	bytes += write(fd, "=", 1);
	bytes += write(fd, value, strlen(value));
	bytes += write(fd, "\n", 1);

	return bytes;
}

int ph_config_to_file(struct pantavisor_config *config, char *path)
{
	int fd;
	int bytes;
	char buf[128];
	char tmp_path[PATH_MAX];

	sprintf(tmp_path, "%s-XXXXXX", path);
	mkstemp(tmp_path);
	fd = open(tmp_path, O_RDWR | O_SYNC | O_CREAT | O_TRUNC, 644);
	if (!fd) {
		pv_log(ERROR, "unable to open temporary credentials config");
		return 1;
	}

	sprintf(buf, "%d", config->loglevel);
	bytes = write_config_tuple(fd, "log.level", buf);
	sprintf(buf, "%d", config->logsize);
	bytes = write_config_tuple(fd, "log.buf_nitems", buf);
	sprintf(buf, "%d", config->updater.interval);
	bytes = write_config_tuple(fd, "updater.interval", buf);
	sprintf(buf, "%d", config->updater.network_timeout);
	bytes = write_config_tuple(fd, "updater.network_timeout", buf);
	sprintf(buf, "%d", config->update_commit_delay);
	bytes = write_config_tuple(fd, "updater.commit.delay", buf);
	sprintf(buf, "%d", config->updater.keep_factory);
	bytes = write_config_tuple(fd, "updater.keep_factory", buf);
	bytes = write_config_tuple(fd, "creds.type", config->creds.type);
	bytes = write_config_tuple(fd, "creds.host", config->creds.host);
	sprintf(buf, "%d", config->creds.port);
	bytes = write_config_tuple(fd, "creds.port", buf);
	bytes = write_config_tuple(fd, "creds.id", config->creds.id);
	bytes = write_config_tuple(fd, "creds.prn", config->creds.prn);
	bytes = write_config_tuple(fd, "creds.secret", config->creds.secret);
	if (config->creds.tpm.key && config->creds.tpm.cert) {
		bytes = write_config_tuple(fd, "creds.tpm.key", config->creds.tpm.key);
		bytes = write_config_tuple(fd, "creds.tpm.cert", config->creds.tpm.cert);
	}

	close(fd);
	rename(tmp_path, path);

	return bytes;
}

char* ph_config_file_for_read()
{
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	const struct pv_system *system = get_pv_system();
	char *configfile = NULL;

	pv = get_pv_instance();
	if (!pv || !pv->config)
		goto out;
	config = pv->config;

	if (!system)
		goto out;

	configfile = getenv("PH_CONFIG") ? strdup(getenv("PH_CONFIG")) : NULL;
	if (!configfile) {
		configfile = calloc (sizeof(char) * (strlen(config->storage.mntpoint) + 1 + strlen("/config/pantahub.config")),1);
		strcat(configfile, config->storage.mntpoint);
		strcat(configfile, "/config/pantahub.config");
	}

	if (access(configfile, R_OK)) {
		configfile = calloc (sizeof(char) * (strlen(pv->system->etcdir) + 1 + strlen("/pantahub.config")),1);
		strcat(configfile, pv->system->etcdir);
		strcat(configfile, "/pantahub.config");
	}

	/* if file does not exist; use datadir one */
	if (access(configfile, R_OK)) {
		configfile = realloc(configfile, sizeof(char) * (strlen(system->datadir) + 1 + strlen("/pantahub.config")));
		configfile[0] = 0;
		strcat(configfile, system->datadir);
		strcat(configfile, "/pantahub.config");
	}

 out:
	return configfile;
}

/*
 * Don't free the returned value.
 * */
const char* pv_log_get_config_item(struct pv_logger_config *config,
		const char *key) {
	int i = 0;
	if (config->static_pair) {
		while (config->static_pair[i][0]) {
			if (!strncmp(config->static_pair[i][0], key, strlen(key)))
				return config->static_pair[i][1];
			i++;
		}
	} else if (config->pair) {
		while (config->pair[i][0]) {
			if (!strncmp(config->pair[i][0], key,strlen(key)))
				return config->pair[i][1];
			i++;
		}
	}
	return NULL;
}

static int pv_config_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	struct pv_system *system = NULL;
	int ret = -1;
	char *configfile;

	pv = get_pv_instance();
	if (!pv || !pv->config)
		goto out;
	config = pv->config;

	system = get_pv_system();

	configfile = getenv("PV_CONFIG");
	if (!configfile) {
		configfile = calloc (sizeof(char) * (strlen(system->etcdir) + 1 + strlen("/pantavisor.config")),1);
		strcat(configfile, system->etcdir);
		strcat(configfile, "/pantavisor.config");
	}

	/* if file does not exist; use datadir one */
	if (access(configfile, R_OK)) {
		configfile = realloc(configfile, sizeof(char) * (strlen(system->datadir) + 1 + strlen("/pantavisor.config")));
		configfile[0] = 0;
		strcat(configfile, system->datadir);
		strcat(configfile, "/pantavisor.config");
	}

	/* pantavisor must use this config if env is set */
	if (pv_config_from_file(configfile, config) < 0) {
		printf("FATAL: unable to parse pantavisor config %s", configfile);
		goto out;
	}
	ret = 0;
 out:
	return ret;
}

static int ph_config_init(struct pv_init *this)
{
	char *configfile;
	struct pantavisor *pv = NULL;
	struct pantavisor_config *config = NULL;
	int ret = -1;

	pv = get_pv_instance();
	if (!pv || !pv->config)
		goto out;
	config = pv->config;

	configfile = ph_config_file_for_read();

	if (ph_config_from_file(configfile, config) < 0) {
		printf("FATAL: error to parse pantahub config");
		goto out;
	}
	setenv("PH_CONFIG", configfile, true);

	ret = 0;
 out:
	return ret;
}

struct pv_init pv_init_config =  {
	.init_fn = pv_config_init,
	.flags = 0,
};

struct pv_init ph_init_config =  {
	.init_fn = ph_config_init,
	.flags = 0,
};

struct pantavisor_config* get_pv_config(void)
{
	if (!get_pv_instance())
		return NULL;
	return get_pv_instance()->config;
}
