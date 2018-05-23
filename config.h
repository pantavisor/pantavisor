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

enum {
	BL_UBOOT_PLAIN = 0,
	BL_UBOOT_PVK,
	BL_GRUB
};

struct pantavisor_creds {
	char *host;
	int port;
	char *id;
	char *prn;
	char *secret;
};

struct pantavisor_storage {
	char *path;
	char *fstype;
	char *opts;
	char *mntpoint;
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

struct pantavisor_config {
	char *name;
	char *logdir;
	int loglevel;
	int logsize;
	struct pantavisor_bootloader bl;
	struct pantavisor_creds creds;
	struct pantavisor_storage storage;
	struct pantavisor_updater updater;
};

// Fill config struct after parsing on-initramfs factory config
int pv_config_from_file(char *path, struct pantavisor_config *config);
int ph_config_from_file(char *path, struct pantavisor_config *config);
int ph_config_to_file(struct pantavisor_config *config, char *path);

#endif
