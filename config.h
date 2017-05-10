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
#ifndef SC_CONFIG_H
#define SC_CONFIG_H

enum {
	UBOOT_PLAIN = 0,
	UBOOT_PVK
};

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

struct systemc_updater {
	int interval;
	int keep_factory;
	int network_timeout;
};

struct systemc_config {
	char *name;
	int loglevel;
	int bl_type;
	struct systemc_creds creds;
	struct systemc_storage storage;
	struct systemc_updater updater;
};

// Fill config struct after parsing on-initramfs factory config
int sc_config_from_file(char *path, struct systemc_config *config);
int ph_config_from_file(char *path, struct systemc_config *config);
int ph_config_to_file(struct systemc_config *config, char *path);

#endif
