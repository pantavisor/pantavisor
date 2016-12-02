#ifndef SC_CONFIG_H
#define SC_CONFIG_H

struct systemc_creds {
	char *host;
	int port;
	char *id;
	char *abrn;
	char *secret;
};

struct systemc_storage {
	char *path;
	char *fstype;
	char *opts;
	char *mntpoint;
};

struct systemc_config {
	char *name;
	int loglevel;
	struct systemc_creds creds; 
	struct systemc_storage storage;
};

struct config_item* _config_add_item(char *key, char *value);
char* _config_get_value(char *key);
void _config_del_item(char *key);

// Fill config struct after parsing on-initramfs factory config
int config_from_file(char *path, struct systemc_config *config);

#endif
