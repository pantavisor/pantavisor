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
#ifndef PV_VOLUMES_H
#define PV_VOLUMES_H

typedef enum {
	DISK_UNKNOWN,
	DISK_DIR,
	DISK_DM_CRYPT_VERSATILE,
	DISK_DM_CRYPT_CAAM,
	DISK_DM_CRYPT_DCP
} pv_disk_t;

struct pv_disk {
	char *name;
	pv_disk_t type;
	char *path;
	char *uuid;
	char *options;
	bool def;
	struct dl_list list; // pv_disk
};

typedef enum {
	VOL_LOOPIMG,
	VOL_PERMANENT,
	VOL_REVISION,
	VOL_BOOT,
	VOL_UNKNOWN
} pv_volume_t;

struct pv_volume {
	char *name;
	char *mode;
	char *src;
	char *dest;
	pv_volume_t type;
	int loop_fd;
	int file_fd;
	char *umount_cmd;
	struct pv_platform *plat;
	struct dl_list list; // pv_volume
	struct pv_disk *disk;
	char *uid, *gid;
};

void pv_volume_free(struct pv_volume *v);

struct pv_disk* pv_disk_add(struct pv_state *s);
void pv_disks_empty(struct pv_state *s);

struct pv_volume* pv_volume_add_with_disk(struct pv_state *s, char *name, char *disk);
struct pv_volume* pv_volume_add(struct pv_state *s, char *name);

int pv_volume_mount(struct pv_volume *v);
int pv_volume_unmount(struct pv_volume *v);

void pv_volumes_empty(struct pv_state *s);

int pv_volumes_mount_firmware_modules(void);

#endif // PV_VOLUMES_H
