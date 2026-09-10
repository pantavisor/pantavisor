/*
 * pvcm-run filesystem bridge
 *
 * Serves Linux directories to the MCU as remote filesystems.
 * Handles FS_REQ/FS_DATA/FS_END frames from MCU, executes
 * operations on the Linux VFS, sends FS_RESP/FS_DATA/FS_END back.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_FS_BRIDGE_H
#define PVCM_FS_BRIDGE_H

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"

#define PVCM_MAX_FS_SHARES 8

/* Add a share: --fs-share /mcu-path=/linux-path */
int pvcm_fs_bridge_add_share(const char *spec);

/* Initialize the filesystem bridge */
int pvcm_fs_bridge_init(struct pvcm_transport *t);

/* Handle incoming FS frames from MCU */
int pvcm_fs_bridge_on_req(struct pvcm_transport *t,
			   const uint8_t *buf, int len);
int pvcm_fs_bridge_on_data(struct pvcm_transport *t,
			    const uint8_t *buf, int len);
int pvcm_fs_bridge_on_end(struct pvcm_transport *t,
			   const uint8_t *buf, int len);

#endif
