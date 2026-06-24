/*
 * PVCM State -- flash state read/write
 *
 * Manages the pvcm_flash_state_t structure in MCU internal flash.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm_protocol.h>

LOG_MODULE_REGISTER(pvcm_state, CONFIG_LOG_DEFAULT_LEVEL);

static pvcm_flash_state_t state;

int pvcm_state_load(void)
{
	/* TODO: read from flash partition */
	LOG_INF("PVCM state: load");
	return 0;
}

int pvcm_state_save(void)
{
	/* TODO: write to flash partition */
	LOG_INF("PVCM state: save");
	return 0;
}

const pvcm_flash_state_t *pvcm_state_get(void)
{
	return &state;
}
