/*
 * pvcm-run config parser
 * SPDX-License-Identifier: MIT
 */

#ifndef PVCM_CONFIG_H
#define PVCM_CONFIG_H

#include <stdint.h>

struct pvcm_config {
	char name[64];
	char config_path[256];

	/* from run.json mcu section */
	char device[64];        /* /dev/ttyACM0 or auto-discovered for rpmsg */
	char transport[16];     /* "uart" or "rpmsg" */
	uint32_t baudrate;

	/* remoteproc (internal M core) */
	char remoteproc[32];    /* "remoteproc0" — sysfs instance name */

	/* firmware path (relative to container dir) */
	char firmware[128];
};

int pvcm_config_parse(struct pvcm_config *cfg, const char *run_json_path);

#endif
