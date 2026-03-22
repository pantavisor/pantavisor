/*
 * pvcm-proxy config parser -- minimal JSON parsing for run.json
 *
 * Only extracts the fields we need from the MCU run.json:
 *   mcu.device, mcu.transport, mcu.baudrate, firmware
 *
 * Uses simple string matching -- no JSON library dependency.
 * The run.json is small and well-structured (pvr generates it).
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* extract a JSON string value for a given key */
static int json_get_str(const char *json, const char *key,
			char *out, size_t out_size)
{
	char search[128];
	snprintf(search, sizeof(search), "\"%s\"", key);

	const char *p = strstr(json, search);
	if (!p)
		return -1;

	/* skip past key and find the colon */
	p += strlen(search);
	p = strchr(p, ':');
	if (!p)
		return -1;
	p++;

	/* skip whitespace */
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;

	if (*p != '"')
		return -1;
	p++; /* skip opening quote */

	/* copy until closing quote */
	size_t i = 0;
	while (*p && *p != '"' && i < out_size - 1) {
		out[i++] = *p++;
	}
	out[i] = '\0';

	return 0;
}

/* extract a JSON integer value for a given key */
static int json_get_int(const char *json, const char *key, uint32_t *out)
{
	char search[128];
	snprintf(search, sizeof(search), "\"%s\"", key);

	const char *p = strstr(json, search);
	if (!p)
		return -1;

	p += strlen(search);
	p = strchr(p, ':');
	if (!p)
		return -1;
	p++;

	/* skip whitespace */
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		p++;

	*out = (uint32_t)strtoul(p, NULL, 10);
	return 0;
}

int pvcm_config_parse(struct pvcm_config *cfg, const char *run_json_path)
{
	FILE *f = fopen(run_json_path, "r");
	if (!f) {
		fprintf(stderr, "[pvcm-proxy] cannot open %s: %m\n",
			run_json_path);
		return -1;
	}

	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (size <= 0 || size > 65536) {
		fclose(f);
		return -1;
	}

	char *json = malloc(size + 1);
	if (!json) {
		fclose(f);
		return -1;
	}

	if (fread(json, 1, size, f) != (size_t)size) {
		free(json);
		fclose(f);
		return -1;
	}
	json[size] = '\0';
	fclose(f);

	/* parse fields */
	json_get_str(json, "device", cfg->device, sizeof(cfg->device));
	json_get_str(json, "transport", cfg->transport, sizeof(cfg->transport));

	if (json_get_int(json, "baudrate", &cfg->baudrate) != 0)
		cfg->baudrate = PVCM_DEFAULT_BAUDRATE;

	/* firmware field is optional */
	cfg->firmware[0] = '\0';
	json_get_str(json, "firmware", cfg->firmware, sizeof(cfg->firmware));

	/* default transport */
	if (cfg->transport[0] == '\0')
		strncpy(cfg->transport, "uart", sizeof(cfg->transport));

	/* default device from container name */
	if (cfg->device[0] == '\0')
		strncpy(cfg->device, cfg->name, sizeof(cfg->device));

	free(json);

	fprintf(stdout, "[pvcm-proxy] config: device=%s transport=%s "
		"baudrate=%u firmware=%s\n",
		cfg->device, cfg->transport, cfg->baudrate,
		cfg->firmware[0] ? cfg->firmware : "(none)");

	return 0;
}
