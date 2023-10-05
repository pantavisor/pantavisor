/*
 * Copyright (c) 2023 Pantacor Ltd.
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

#ifndef PV_DISK_H
#define PV_DISK_H

#include <string.h>

#include "utils/list.h"
#include "state.h"

typedef enum {
	DISK_UNKNOWN,
	DISK_DIR,
	DISK_DM_CRYPT_VERSATILE,
	DISK_DM_CRYPT_CAAM,
	DISK_DM_CRYPT_DCP,
	DISK_SWAP,
	DISK_VOLUME
} pv_disk_t;

typedef enum {
	DISK_FORMAT_UNKNOWN,
	DISK_FORMAT_SWAP,
	DISK_FORMAT_EXT4,
	DISK_FORMAT_EXT3
} pv_disk_format_t;

typedef enum {
	DISK_STATUS_ERROR,
	DISK_STATUS_MOUNTED,
	DISK_STATUS_NOT_MOUNTED
} pv_disk_status_t;

struct pv_disk {
	char *name;
	pv_disk_t type;
	pv_disk_format_t format;
	char *path;
	char *uuid;
	char *mount_ops;
	char *format_ops;
	char *provision_ops;
	char *provision;
	char *mount_target;
	bool def;
	bool mounted;
	// pv_disk
	struct dl_list list;
};

struct pv_disk *pv_disk_add(struct pv_state *s);
int pv_disk_mount_swap(struct pv_state *s);
int pv_disk_umount_all(struct pv_state *s);
void pv_disk_empty(struct pv_state *s);
int pv_disk_mount_handler(struct pv_disk *disk, const char *action);

inline const char *pv_disk_format_to_str(pv_disk_format_t type)
{
	switch (type) {
	case DISK_FORMAT_UNKNOWN:
		return "unknown";
	case DISK_FORMAT_SWAP:
		return "swap";
	case DISK_FORMAT_EXT4:
		return "ext4";
	case DISK_FORMAT_EXT3:
		return "ext3";
	}
	return "unknown";
}

inline pv_disk_format_t pv_disk_str_to_format(const char *format_str)
{
	if (format_str) {
		if (!strcmp(format_str, "swap"))
			return DISK_FORMAT_SWAP;
		else if (!strcmp(format_str, "ext4"))
			return DISK_FORMAT_EXT4;
		else if (!strcmp(format_str, "ext3"))
			return DISK_FORMAT_EXT3;
	}
	return DISK_FORMAT_UNKNOWN;
}

inline const char *pv_disk_type_to_str(pv_disk_t type)
{
	switch (type) {
	case DISK_UNKNOWN:
		return "unknown";
	case DISK_DIR:
		return "dir";
	case DISK_DM_CRYPT_VERSATILE:
		return "versatile";
	case DISK_DM_CRYPT_CAAM:
		return "caam";
	case DISK_DM_CRYPT_DCP:
		return "dcp";
	case DISK_SWAP:
		return "swap-disk";
	case DISK_VOLUME:
		return "volume-disk";
	}
	return "unknown";
}

inline pv_disk_t pv_disk_str_to_type(const char *type_str)
{
	if (type_str) {
		if (!strcmp(type_str, "directory"))
			return DISK_DIR;
		else if (!strcmp(type_str, "dm-crypt-versatile"))
			return DISK_DM_CRYPT_VERSATILE;
		else if (!strcmp(type_str, "dm-crypt-caam"))
			return DISK_DM_CRYPT_CAAM;
		else if (!strcmp(type_str, "dm-crypt-dcp"))
			return DISK_DM_CRYPT_DCP;
		else if (!strcmp(type_str, "swap-disk"))
			return DISK_SWAP;
		else if (!strcmp(type_str, "volume-disk"))
			return DISK_VOLUME;
	}

	return DISK_UNKNOWN;
}

extern struct pv_disk_impl zram_impl;
extern struct pv_disk_impl crypt_impl;
extern struct pv_disk_impl volume_impl;
extern struct pv_disk_impl swap_impl;

#endif
