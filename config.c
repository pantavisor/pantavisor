/*
 * Copyright (c) 2017 Pantacor Ltd.
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

#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#define MODULE_NAME             "config"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"
#include "utils.h"

struct config_item {
	char *key;
	char *value;
	struct config_item *next;
};

static struct config_item *head = 0;
static struct config_item *last;

static struct config_item* _config_get_by_key(char *key)
{
	struct config_item *curr;

	if (key == NULL)
		return NULL;

	for (curr = head; curr != NULL; curr = curr->next) {
		if (strcmp(curr->key, key) == 0)
			return curr;
	}

	// Value not found
	return NULL;
}

static struct config_item* _config_add_item(char *key, char *value)
{
	struct config_item *this;

	// Check if it already exists in config and change value instead
	this = _config_get_by_key(key);
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
		return NULL;
	}

	// Check empty key
	if (strcmp(key, "") == 0) {
		free(this);
		return NULL;
	}

	if (!head)
		head = this;
	else
		last->next = this;

	// Set key
	this->key = strdup(key);

	// Check for empty value
	if (value)
		this->value = strdup(value);
	else
		this->value = strdup(""); // Empty value

	this->next = NULL;
	last = this;

	return this;
}

static char* _config_get_value(char *key)
{
	struct config_item *curr;

	if (key == NULL)
		return NULL;

	for (curr = head; curr != NULL; curr = curr->next) {
		if (strcmp(curr->key, key) == 0)
			return curr->value;
	}

	// Value not found
	return NULL;
}

static struct config_item* _config_replace_item(char *key, char *value)
{
	struct config_item *curr = NULL;

	if (key == NULL)
		return NULL;

	for (curr = head; curr != NULL; curr = curr->next) {
		if (strcmp(curr->key, key) == 0) {
			if (curr->value)
				free(curr->value);
			curr->value = strdup(value);
			return curr;
		}
	}

	// not found? add it
	return _config_add_item(key, value);
}

static void _config_del_item(char *key)
{
	struct config_item *curr;
	struct config_item *prev;

	if (key == NULL)
		return;

	for (curr = prev = head; curr != NULL; curr = curr->next) {
		if (strcmp(curr->key, key) == 0) {
			free(curr->key);
			free(curr->value);
			if (prev != curr)
				prev->next = curr->next;
			free(curr);
		}
		prev = curr;
	}
}

static int load_key_value_file(char *path)
{
	char buff[1024];
	FILE *fp;
	char *__real_key = NULL;

	fp = fopen(path, "r");
	if (!fp) {
		pv_log(INFO, "unable to find %s config file", path);
		return -1;
	}

	while (fgets(buff, sizeof(buff), fp)) {
		// Remove newline from value (hacky)
		buff[strlen(buff)-1] = '\0';
		char *key = strstr(buff, "=");
		if (key) {
			char *value = key + 1;
			__real_key = (char*) calloc(1, key - buff + 1);
			if (__real_key) {
				sprintf(__real_key, "%.*s", (int)(key - buff), buff);
				_config_add_item(__real_key, value);
				free(__real_key);
			}
		}
	}
	fclose(fp);

	return 0;
}

static int _config_parse_cmdline(char *hint)
{
	int fd, bytes;
	char *buf = NULL, *k = NULL, *nl = NULL;
	char *ptr_out = NULL, *ptr_in = NULL;
	char *token = NULL, *key = NULL, *value = NULL;

	// Get current step revision from cmdline
	fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return -1;

	buf = calloc(1, sizeof(char) * (1024 + 1));
	if (!buf) {
		close(fd);
		return -1;
	}

	bytes = read_nointr(fd, buf, sizeof(char)*1024);
	if (!bytes) {
		close(fd);
		return -1;
	}
	close(fd);
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
			_config_replace_item(key, value);
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

	if (load_key_value_file(path) < 0)
		return -1;

	// for overrides
	_config_parse_cmdline("pv_");

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
	config->storage.path = _config_get_value("storage.device");
	config->storage.fstype = _config_get_value("storage.fstype");
	config->storage.opts = _config_get_value("storage.opts");
	config->storage.mntpoint = _config_get_value("storage.mntpoint");
	config->storage.mnttype = _config_get_value("storage.mnttype");

	item = _config_get_value("wdt.enabled");
	config->wdt.enabled = item ? 1 : 0;

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

	if (load_key_value_file(path) < 0)
		return -1;

	// for overrides
	_config_parse_cmdline("ph_");

	config->logdir = _config_get_value("log.dir");
	if (!config->logdir)
		config->logdir = strdup("/storage/logs/");

	config->dropbearcachedir = _config_get_value("dropbear.cache.dir");
	if (!config->dropbearcachedir)
		config->dropbearcachedir = strdup("/storage/cache/dropbear");

	config->metacachedir = _config_get_value("meta.cache.dir");
	if (!config->metacachedir)
		config->metacachedir = strdup("/storage/cache/meta");

	item = _config_get_value("log.maxsize");
	if (item)
		config->logmax = atoi(item);
	else
		config->logmax = (1 << 21); // 2 MiB

	item = _config_get_value("log.level");
	if (item)
		config->loglevel = atoi(item);

	item = _config_get_value("log.buf_nitems");
	if (item)
		config->logsize = atoi(item);
	else
		config->logsize = 16;

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

	config->creds.host = _config_get_value("creds.host");
	if (!config->creds.host) {
		config->creds.host = strdup("192.168.53.1");
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

	fd = open(path, O_RDWR | O_SYNC | O_CREAT | O_TRUNC, 644);
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
	sprintf(buf, "%d", config->updater.keep_factory);
	bytes = write_config_tuple(fd, "updater.keep_factory", buf);
	bytes = write_config_tuple(fd, "creds.host", config->creds.host);
	sprintf(buf, "%d", config->creds.port);
	bytes = write_config_tuple(fd, "creds.port", buf);
	bytes = write_config_tuple(fd, "creds.id", config->creds.id);
	bytes = write_config_tuple(fd, "creds.prn", config->creds.prn);
	bytes = write_config_tuple(fd, "creds.secret", config->creds.secret);

	close(fd);

	return bytes;
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
