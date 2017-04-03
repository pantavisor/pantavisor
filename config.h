#ifndef SC_CONFIG_H
#define SC_CONFIG_H

struct systemc_creds {
	char *host;
	int port;
	char *id;
	char *prn;
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
	char *bl_type;
	struct systemc_creds creds; 
	struct systemc_storage storage;
};

// Fill config struct after parsing on-initramfs factory config
int sc_config_from_file(char *path, struct systemc_config *config);
int ph_config_from_file(char *path, struct systemc_config *config);
int ph_config_to_file(struct systemc_config *config, char *path);

#endif
