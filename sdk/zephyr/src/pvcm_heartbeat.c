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
#include <pantavisor/pvcm_transport.h>

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

	const struct pvcm_transport *transport = pvcm_transport_get();

	LOG_INF("PVCM heartbeat starting (%d ms interval)",
		CONFIG_PANTAVISOR_HEARTBEAT_INTERVAL_MS);

	/* wait for transport to be ready (server thread inits it) */
	k_sleep(K_MSEC(1000));

	while (1) {
		uint8_t status = PVCM_HEALTH_OK;

		if (health_cb)
			status = health_cb();

		uint32_t uptime = (uint32_t)(k_uptime_get() / 1000);

		pvcm_heartbeat_t hb = {
			.op = PVCM_EVT_HEARTBEAT,
			.status = status,
			.uptime_s = (uint16_t)(uptime & 0xFFFF),
			.crash_count = 0, /* TODO: from flash state */
		};

		if (transport) {
			transport->send_frame(&hb,
				sizeof(hb) - sizeof(uint32_t));
		}

		LOG_DBG("heartbeat: status=%d uptime=%us", status, uptime);

		k_sleep(K_MSEC(CONFIG_PANTAVISOR_HEARTBEAT_INTERVAL_MS));
	}
}

K_THREAD_DEFINE(pvcm_heartbeat, PVCM_HB_STACK_SIZE,
		pvcm_heartbeat_thread, NULL, NULL, NULL,
		PVCM_HB_PRIORITY, 0, 0);
