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

#ifndef PV_CONFIG_H
#define PV_CONFIG_H

#include <stdbool.h>

#include "utils/list.h"

typedef enum { IM_EMBEDDED, IM_STANDALONE, IM_APPENGINE } init_mode_t;

struct pantavisor_system {
	init_mode_t init_mode;
	char *libdir;
	char *etcdir;
	char *usrdir;
	char *rundir;
	char *mediadir;
	char *confdir;
};

struct pantavisor_debug {
	bool shell;
	bool ssh;
};

struct pantavisor_cache {
	char *usrmetadir;
	char *devmetadir;
	char *dropbearcachedir;
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
	char *host_proxy;
	int port_proxy;
	int noproxyconnect;
	char *id;
	char *prn;
	char *secret;
	char *token;
	struct pantavisor_tpm tpm;
};

struct pantavisor_gc {
	int reserved;
	bool keep_factory;
	int threshold;
	int threshold_defertime;
};

struct pantavisor_storage {
	char *path;
	char *fstype;
	char *opts;
	char *mntpoint;
	char *mnttype;
	char *logtempsize;
	int wait;
	struct pantavisor_gc gc;
};

struct pantavisor_disk {
	char *voldir;
	char *exportsdir;
	char *writabledir;
};

struct pantavisor_updater {
	int interval;
	int goals_timeout;
	int network_timeout;
	bool use_tmp_objects;
	int revision_retries;
	int revision_retry_timeout;
	int commit_delay;
};

enum { BL_UBOOT_PLAIN = 0, BL_UBOOT_PVK, BL_GRUB };

struct pantavisor_bootloader {
	int type;
	bool mtd_only;
	char *mtd_path;
	char *dtb;
	char *ovl;
};

struct pantavisor_watchdog {
	bool enabled;
	int timeout;
};

struct pantavisor_network {
	char *brdev;
	char *braddress4;
	char *brmask4;
};

typedef enum {
	LOG_SERVER_OUTPUT_NULL_SINK = 1 << 0,
	LOG_SERVER_OUTPUT_SINGLE_FILE = 1 << 1,
	LOG_SERVER_OUTPUT_FILE_TREE = 1 << 2,
	LOG_SERVER_OUTPUT_SIZE
} log_server_output_mask_t;

struct pantavisor_log_server {
	int outputs;
};

struct pantavisor_log {
	char *logdir;
	int logmax;
	int loglevel;
	int logsize;
	bool push;
	bool capture;
	bool loggers;
	bool std_out;
	struct pantavisor_log_server server;
};

struct pantavisor_lxc {
	int log_level;
};

struct pantavisor_control {
	bool remote;
};

struct pantavisor_libthttp {
	int loglevel;
};

typedef enum {
	SB_DISABLED,
	SB_AUDIT,
	SB_LENIENT,
	SB_STRICT,
} secureboot_mode_t;

struct pantavisor_secureboot {
	secureboot_mode_t mode;
	char *certdir;
	bool checksum;
};

struct pantavisor_metadata {
	int devmeta_interval;
};

struct pantavisor_config {
	struct pantavisor_system sys;
	struct pantavisor_debug debug;
	struct pantavisor_cache cache;
	struct pantavisor_bootloader bl;
	struct pantavisor_creds creds;
	struct pantavisor_factory factory;
	struct pantavisor_storage storage;
	struct pantavisor_disk disk;
	struct pantavisor_updater updater;
	struct pantavisor_watchdog wdt;
	struct pantavisor_network net;
	struct pantavisor_log log;
	struct pantavisor_lxc lxc;
	struct pantavisor_control control;
	struct pantavisor_libthttp libthttp;
	struct pantavisor_secureboot secureboot;
	struct pantavisor_metadata metadata;
};

int pv_config_init(char *path);

int pv_config_load_creds(void);
int pv_config_save_creds(void);

void pv_config_override_value(const char *key, const char *value);

void pv_config_free(void);

void pv_config_set_system_init_mode(init_mode_t mode);

void pv_config_set_debug_shell(bool shell);
void pv_config_set_debug_ssh(bool ssh);

void pv_config_set_creds_id(char *id);
void pv_config_set_creds_prn(char *prn);
void pv_config_set_creds_secret(char *secret);

init_mode_t pv_config_get_system_init_mode(void);
char *pv_config_get_system_libdir(void);
char *pv_config_get_system_etcdir(void);
char *pv_config_get_system_usrdir(void);
char *pv_config_get_system_rundir(void);
char *pv_config_get_system_mediadir(void);
char *pv_config_get_system_confdir(void);

bool pv_config_get_debug_shell(void);
bool pv_config_get_debug_ssh(void);

char *pv_config_get_cache_usrmetadir(void);
char *pv_config_get_cache_devmetadir(void);
char *pv_config_get_cache_dropbearcachedir(void);

char *pv_config_get_creds_type(void);
char *pv_config_get_creds_host(void);
int pv_config_get_creds_port(void);
char *pv_config_get_creds_host_proxy(void);
int pv_config_get_creds_port_proxy(void);
int pv_config_get_creds_noproxyconnect(void);
char *pv_config_get_creds_id(void);
char *pv_config_get_creds_prn(void);
char *pv_config_get_creds_secret(void);
char *pv_config_get_creds_token(void);

char *pv_config_get_creds_tpm_key(void);
char *pv_config_get_creds_tpm_cert(void);

char *pv_config_get_factory_autotok(void);

char *pv_config_get_storage_path(void);
char *pv_config_get_storage_fstype(void);
char *pv_config_get_storage_opts(void);
char *pv_config_get_storage_mntpoint(void);
char *pv_config_get_storage_mnttype(void);
char *pv_config_get_storage_logtempsize(void);
int pv_config_get_storage_wait(void);

int pv_config_get_storage_gc_reserved(void);
bool pv_config_get_storage_gc_keep_factory(void);
int pv_config_get_storage_gc_threshold(void);
int pv_config_get_storage_gc_threshold_defertime(void);

char *pv_config_get_disk_voldir(void);
char *pv_config_get_disk_exportsdir(void);
char *pv_config_get_disk_writabledir(void);

int pv_config_get_updater_interval(void);
int pv_config_get_updater_goals_timeout(void);
int pv_config_get_updater_network_timeout(void);
bool pv_config_get_updater_network_use_tmp_objects(void);
int pv_config_get_updater_revision_retries(void);
int pv_config_get_updater_revision_retry_timeout(void);
int pv_config_get_updater_commit_delay(void);

char *pv_config_get_bl_dtb(void);
char *pv_config_get_bl_ovl(void);
int pv_config_get_bl_type(void);
bool pv_config_get_bl_mtd_only(void);
char *pv_config_get_bl_mtd_path(void);

bool pv_config_get_watchdog_enabled(void);
int pv_config_get_watchdog_timeout(void);

char *pv_config_get_network_brdev(void);
char *pv_config_get_network_braddress4(void);
char *pv_config_get_network_brmask4(void);

char *pv_config_get_log_logdir(void);
int pv_config_get_log_logmax(void);
int pv_config_get_log_loglevel(void);
int pv_config_get_log_logsize(void);
bool pv_config_get_log_push(void);
bool pv_config_get_log_capture(void);
bool pv_config_get_log_loggers(void);
bool pv_config_get_log_stdout(void);
int pv_config_get_libthttp_loglevel(void);

int pv_config_get_log_server_outputs(void);
bool pv_config_get_log_server_output_file_tree(void);
bool pv_config_get_log_server_output_single_file(void);

int pv_config_get_lxc_loglevel(void);
bool pv_config_get_control_remote(void);

secureboot_mode_t pv_config_get_secureboot_mode(void);
char *pv_config_get_secureboot_certdir(void);
bool pv_config_get_secureboot_checksum(void);

int pv_config_get_metadata_devmeta_interval(void);

char *pv_config_get_json(void);

#endif
