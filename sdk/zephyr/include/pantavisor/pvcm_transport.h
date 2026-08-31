/*
 * Pantavisor RTOS SDK -- Transport abstraction
 *
 * Same abstraction as the Linux pvcm-run side.
 * Two implementations: UART (polling) and RPMsg (OpenAMP).
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PANTAVISOR_PVCM_TRANSPORT_H
#define PANTAVISOR_PVCM_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

struct pvcm_transport {
	int (*init)(void);
	int (*send_frame)(const void *payload, size_t len);
	int (*recv_frame)(void *payload, size_t max_len, int timeout_ms);
};

/* CRC32 shared by both transports */
uint32_t pvcm_crc32(const void *data, size_t len);

/* Get the active transport (selected by Kconfig) */
const struct pvcm_transport *pvcm_transport_get(void);

#endif
