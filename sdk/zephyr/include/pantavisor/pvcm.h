/*
 * Pantavisor RTOS SDK -- Public API
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PANTAVISOR_PVCM_H
#define PANTAVISOR_PVCM_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Health callback -- called by heartbeat module before each heartbeat.
 * Return PVCM_HEALTH_OK or PVCM_HEALTH_DEGRADED.
 */
typedef uint8_t (*pvcm_health_cb_t)(void);

void pvcm_register_health_cb(pvcm_health_cb_t cb);

/*
 * REST client API (requires CONFIG_PANTAVISOR_BRIDGE)
 */
typedef void (*pvcm_rest_cb_t)(uint16_t status_code,
			       const char *body, void *ctx);

int pvcm_get(const char *path, pvcm_rest_cb_t cb, void *ctx);
int pvcm_post(const char *path, const char *body,
	      pvcm_rest_cb_t cb, void *ctx);
int pvcm_put(const char *path, const char *body,
	     pvcm_rest_cb_t cb, void *ctx);
int pvcm_delete(const char *path, pvcm_rest_cb_t cb, void *ctx);

/*
 * Log API (for non-Zephyr log users, e.g. FreeRTOS compat)
 */
void pvcm_log(uint8_t level, const char *module, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* PANTAVISOR_PVCM_H */
