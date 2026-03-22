/*
 * PVCM Server -- mandatory protocol server task
 *
 * Handles all incoming PVCM frames, dispatches to handlers,
 * manages transport lifecycle.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>

LOG_MODULE_REGISTER(pvcm_server, CONFIG_LOG_DEFAULT_LEVEL);

#define PVCM_SERVER_STACK_SIZE  2048
#define PVCM_SERVER_PRIORITY    7

static void pvcm_server_thread(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("PVCM server starting (protocol v%d)", PVCM_PROTOCOL_VERSION);

	/* TODO: init transport, enter recv loop, dispatch opcodes */
	while (1) {
		k_sleep(K_FOREVER);
	}
}

K_THREAD_DEFINE(pvcm_server, PVCM_SERVER_STACK_SIZE,
		pvcm_server_thread, NULL, NULL, NULL,
		PVCM_SERVER_PRIORITY, 0, 0);
