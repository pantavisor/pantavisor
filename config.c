#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

#define MODULE_NAME             "config"
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

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
		this->value = strdup(value);
		return this;
	}

	// New item
	this = (struct config_item *) malloc(sizeof(struct config_item));

	if (!this) {
		sc_log(ERROR, "unable to allocate config item");
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

	fp = fopen(path, "r");
	if (!fp) {
		sc_log(INFO, "unable to find %s config file", path);
		return -1;
	}

	while (fgets(buff, sizeof(buff), fp)) {
		// Remove newline from value (hacky)
		buff[strlen(buff)-1] = '\0';

		char *key = strtok(buff, "=");
		char *value = strtok(NULL, "=");

		_config_add_item(key, value);
	}
	fclose(fp);

	return 0;
}

// Fill config struct after parsing on-initramfs factory config
int sc_config_from_file(char *path, struct systemc_config *config)
{
	char *item;

	if (load_key_value_file(path) < 0)
		return -1;

	item = _config_get_value("loglevel");
	if (item)
		config->loglevel = atoi(item);

	item = _config_get_value("bootloader_type");
	sc_log(DEBUG, "bl_type='%s'\n", item);
	if (item && !strcmp(item, "uboot-pvk"))
		config->bl_type = UBOOT_PVK;
	else
		config->bl_type = UBOOT_PLAIN;

	config->storage.path = _config_get_value("storage_device");
	config->storage.fstype = _config_get_value("storage_fstype");
	config->storage.opts = _config_get_value("storage_opts");
	config->storage.mntpoint = _config_get_value("storage_mntpoint");

	return 0;
}

// FIXME: add override capability for static config
// Fill config struct after parsing on-initramfs factory config
int ph_config_from_file(char *path, struct systemc_config *config)
{
	char *item;

	if (load_key_value_file(path) < 0)
		return -1;

	config->creds.host = _config_get_value("creds_host");
	if (!config->creds.host) {
		config->creds.host = strdup("192.168.53.1");
		sc_log(INFO, "no host set, using default: '%s'", config->creds.host);
	}

	item = _config_get_value("creds_port");
	if (item)
		config->creds.port = atoi(item);
	else
		config->creds.port = 12365;

	config->creds.id = _config_get_value("creds_id");
	config->creds.prn = _config_get_value("creds_prn");
	config->creds.secret = _config_get_value("creds_secret");

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

int ph_config_to_file(struct systemc_config *config, char *path)
{
	int fd;
	int bytes;
	char sport[6];

	fd = open(path, O_RDWR | O_SYNC | O_CREAT, 644);
	if (!fd) {
		sc_log(ERROR, "unable to open temporary credentials config");
		return 1;
	}

	bytes = write_config_tuple(fd, "creds_host", config->creds.host);
	sprintf(sport, "%d", config->creds.port);
	bytes = write_config_tuple(fd, "creds_port", sport);
	bytes = write_config_tuple(fd, "creds_id", config->creds.id);
	bytes = write_config_tuple(fd, "creds_prn", config->creds.prn);
	bytes = write_config_tuple(fd, "creds_secret", config->creds.secret);

	close(fd);

	return bytes;
}
