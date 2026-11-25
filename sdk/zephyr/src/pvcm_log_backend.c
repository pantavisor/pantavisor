/*
 * PVCM Log Backend -- Zephyr log -> PVCM_OP_LOG frames
 *
 * Routes all LOG_INF/WRN/ERR output to pvcm-manager via the
 * PVCM transport. pvcm-manager forwards to the Pantavisor log server.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_backend.h>
#include <zephyr/logging/log_output.h>
#include <pantavisor/pvcm_protocol.h>

/* TODO: implement log backend hooks
 *
 * The backend captures Zephyr log messages, formats them into
 * pvcm_log_t frames, and sends them via the PVCM transport.
 *
 * For Phase 1 this is a stub -- log output goes to the normal
 * Zephyr console backend. The PVCM forwarding will be wired
 * once the transport layer is functional.
 */
