/*
 * PVCM Remote Filesystem — public API
 *
 * Mount Linux directories on the MCU via pvcm-run.
 * Uses Zephyr's standard filesystem API (fs_open, fs_read, etc.).
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PANTAVISOR_PVCM_FS_H
#define PANTAVISOR_PVCM_FS_H

#include <zephyr/fs/fs.h>

/* Filesystem type for fs_mount_t.type */
#define FS_TYPE_PVCMFS (FS_TYPE_EXTERNAL_BASE + 0)

/*
 * Mount a Linux directory.
 * The share name matches a --fs-share on pvcm-run.
 * Example: pvcm_fs_mount("/storage", "storage");
 */
int pvcm_fs_mount(const char *mount_point, const char *share_name);

/* Server thread handlers (called from pvcm_server dispatch) */
void pvcm_fs_on_resp(const uint8_t *buf, int len);
void pvcm_fs_on_data(const uint8_t *buf, int len);
void pvcm_fs_on_end(const uint8_t *buf, int len);

#endif
