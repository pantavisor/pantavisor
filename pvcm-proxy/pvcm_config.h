/*
 * pvcm-proxy config parser
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_CONFIG_H
#define PVCM_CONFIG_H

#include <stdint.h>

struct pvcm_config {
	char name[64];
	char config_path[256];

	/* from run.json mcu section */
	char device[64];
	char transport[16];   /* "uart" or "rpmsg" */
	uint32_t baudrate;

	/* firmware path (relative to container dir) */
	char firmware[128];
};

int pvcm_config_parse(struct pvcm_config *cfg, const char *run_json_path);

#endif
