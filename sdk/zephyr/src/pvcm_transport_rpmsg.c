/*
 * PVCM RPMsg Transport
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(pvcm_rpmsg, CONFIG_LOG_DEFAULT_LEVEL);

/* TODO: RPMsg transport implementation
 * - OpenAMP endpoint setup
 * - frame send/recv via rpmsg_send / rpmsg_recv callback
 * - CRC32 validation
 */
