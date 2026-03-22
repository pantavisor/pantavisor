/*
 * PVCM Heartbeat -- mandatory heartbeat task
 *
 * Sends PVCM_EVT_HEARTBEAT at CONFIG_PANTAVISOR_HEARTBEAT_INTERVAL_MS.
 * Includes uptime, crash_count, and optional app health status.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>

LOG_MODULE_REGISTER(pvcm_heartbeat, CONFIG_LOG_DEFAULT_LEVEL);

#define PVCM_HB_STACK_SIZE  1024
#define PVCM_HB_PRIORITY    8

static pvcm_health_cb_t health_cb;

void pvcm_register_health_cb(pvcm_health_cb_t cb)
{
	health_cb = cb;
}

static void pvcm_heartbeat_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("PVCM heartbeat starting (%d ms interval)",
		CONFIG_PANTAVISOR_HEARTBEAT_INTERVAL_MS);

	while (1) {
		uint8_t status = PVCM_HEALTH_OK;

		if (health_cb) {
			status = health_cb();
		}

		/* TODO: build and send heartbeat frame via transport */
		LOG_DBG("heartbeat: status=%d uptime=%u",
			status, (uint32_t)(k_uptime_get() / 1000));

		k_sleep(K_MSEC(CONFIG_PANTAVISOR_HEARTBEAT_INTERVAL_MS));
	}
}

K_THREAD_DEFINE(pvcm_heartbeat, PVCM_HB_STACK_SIZE,
		pvcm_heartbeat_thread, NULL, NULL, NULL,
		PVCM_HB_PRIORITY, 0, 0);
