/*
 * PVCM Shell Demo -- Phase 1
 *
 * Minimal Zephyr application demonstrating the Pantavisor MCU SDK.
 * All mandatory modules (server, heartbeat, log backend) start
 * automatically. Shell commands registered via CONFIG_PANTAVISOR_SHELL.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm.h>

LOG_MODULE_REGISTER(pvcm_demo, CONFIG_LOG_DEFAULT_LEVEL);

int main(void)
{
	LOG_INF("PVCM shell demo starting");

	/* pvcm_server, pvcm_heartbeat, pvcm_log_backend already running */
	/* shell commands registered via CONFIG_PANTAVISOR_SHELL */

	return 0;
}
