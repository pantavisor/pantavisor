#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

struct config_item {
	char *key;
	char *value;
	struct config_item *next;
};

static struct config_item *head = 0;
static struct config_item *last;

struct config_item* _config_add_item(char *key, char *value)
{
	struct config_item *this = (struct config_item *) malloc(sizeof(struct config_item));

	if (!this) {
		printf("Unable to allocate config item\n");
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

char* _config_get_value(char *key)
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

void _config_del_item(char *key)
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

// Fill config struct after parsing on-initramfs factory config
int config_from_file(char *path, struct systemc_config *config)
{
	char buff[1024];
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp) {
		printf("Unable to find device config file\n");
		return -1;
	}

	while (fgets(buff, sizeof(buff), fp)) {
		// Remove newline from value (hacky)
		buff[strlen(buff)-1] = '\0';

		char *key = strtok(buff, "=");
		char *value = strtok(NULL, "=");

		_config_add_item(key, value);
	}

	config->storage.path = _config_get_value("storage_device");
	config->storage.fstype = _config_get_value("storage_fstype");
	config->storage.opts = _config_get_value("storage_opts");
	config->storage.mntpoint = _config_get_value("storage_mntpoint");

	config->creds.host = _config_get_value("creds_username");
	config->creds.port = atoi(_config_get_value("creds_port"));
	config->creds.username = _config_get_value("creds_username");
	config->creds.password = _config_get_value("creds_password");
	config->creds.secret = _config_get_value("creds_secret");

	return 0;
}

