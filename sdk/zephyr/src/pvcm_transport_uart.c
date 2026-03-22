/*
 * PVCM UART Transport
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(pvcm_uart, CONFIG_LOG_DEFAULT_LEVEL);

/* TODO: UART transport implementation
 * - sync byte detection and frame reassembly
 * - CRC32 validation
 * - send/recv via Zephyr UART async API
 */
