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
#ifndef PV_CONFIG_H
#define PV_CONFIG_H
#include <stdbool.h>
#include <sys/types.h>
#include <stdlib.h>
#include "utils/list.h"
enum {
	BL_UBOOT_PLAIN = 0,
	BL_UBOOT_PVK,
	BL_GRUB
};

struct pantavisor_factory {
	char *autotok;
};

struct pantavisor_tpm {
	char *key;
	char *cert;
};

struct pantavisor_creds {
	char *type;
	char *host;
	int port;
	char *id;
	char *prn;
	char *secret;
	char *token;
	struct pantavisor_tpm tpm;
};

struct pantavisor_storage {
	char *path;
	char *fstype;
	char *opts;
	char *mntpoint;
	char *mnttype;
	int wait;
};

struct pantavisor_updater {
	int interval;
	int keep_factory;
	int network_timeout;
};

struct pantavisor_bootloader {
	int type;
	int mtd_only;
	char *mtd_path;
};

struct pantavisor_watchdog {
	int enabled;
	int timeout;
};

struct pantavisor_network {
	char *brdev;
	char *braddress4;
	char *brmask4;
};

struct pantavisor_log {
	char *logdir;
	int logmax;
	int loglevel;
	int logsize;
	bool push;
};

struct pantavisor_config {
	char *name;
	char *metacachedir;
	char *dropbearcachedir;
	int revision_retries;
	int revision_retry_timeout;
	int update_commit_delay;
	struct pantavisor_bootloader bl;
	struct pantavisor_creds creds;
	struct pantavisor_factory factory;
	struct pantavisor_storage storage;
	struct pantavisor_updater updater;
	struct pantavisor_watchdog wdt;
	struct pantavisor_network net;
	struct pantavisor_log log;
};

// Fill config struct after parsing on-initramfs factory config
int pv_config_from_file(char *path, struct pantavisor_config *config);
int ph_config_from_file(char *path, struct pantavisor_config *config);
int ph_config_to_file(struct pantavisor_config *config, char *path);

struct pv_logger_config {
	struct dl_list item_list;
	/*
	 * This is a null terminated list of key/value
	 * pairs for the log configuration.
	 * */
	const char ***pair; /*equiv to char *pair[][2]. key, val*/
	/*
	 * Only when logger config is statically allocated.
	 * Do not use both pair and static_pair.
	 * */
	const char* (*static_pair)[2];
};

int load_key_value_file(const char *path, struct dl_list *list);
char* config_get_value(struct dl_list *list, char *key);
void config_iterate_items(struct dl_list *list, int (*action)(char *key, char *value, void *opaque), void *opaque);
void config_clear_items(struct dl_list *list);

const char* pv_log_get_config_item(struct pv_logger_config *config, const char *key);
static void pv_logger_config_free(struct pv_logger_config *item_config)
{
	int i = 0;

	if (!item_config)
		return;

	while (item_config->pair[i][0]) {
		if (item_config->pair[i][1])
			free((void*)item_config->pair[i][1]);
		free((void*)item_config->pair[i][0]);
		free((void*)item_config->pair[i]);
		i++;
	}
	/*
	 * We've a NULL terminated pair..
	 * */
	free((void*)item_config->pair[i]);
	free(item_config);
}
#endif
