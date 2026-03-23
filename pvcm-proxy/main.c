/*
 * pvcm-proxy -- per-MCU runtime process
 *
 * One instance per MCU container, started by the pv_pvcm plugin
 * inside a mount namespace. From xconnect's perspective this IS
 * the container.
 *
 * Copyright (c) 2024-2026 Pantacor Ltd.
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pvcm_config.h"
#include "pvcm_transport.h"
#include "pvcm_protocol.h"
#include "pvcm_bridge.h"

static volatile bool running = true;

static void signal_handler(int sig)
{
	(void)sig;
	running = false;
}

static int listen_port = 18081;

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --name <name> [options]\n"
		"\n"
		"Options:\n"
		"  --name, -n <name>        Container name (required)\n"
		"  --config, -c <path>      Path to run.json\n"
		"  --device, -d <path>      UART device (overrides run.json)\n"
		"  --firmware, -f <path>    Firmware ELF path (for future use)\n"
		"  --transport, -t <type>   Transport: uart or rpmsg (default: uart)\n"
		"  --baudrate, -b <rate>    UART baudrate (default: 921600)\n"
		"  --listen-port, -p <port> HTTP listener port (default: 18081)\n"
		"  --help, -h               Show this help\n"
		"\n"
		"If --config is given, device/transport/baudrate are read from\n"
		"run.json but can be overridden by CLI flags.\n"
		"\n"
		"Examples:\n"
		"  %s --name mcu0 --device /dev/ttyACM0\n"
		"  %s --name mcu0 --config /trails/0/mcu0/run.json\n"
		"  %s --name mcu0 --remoteproc remoteproc0\n"
		"  %s --name mcu0 --remoteproc remoteproc0 --firmware fw.elf\n",
		prog, prog, prog, prog, prog);
}

static int parse_args(int argc, char **argv, struct pvcm_config *cfg)
{
	static struct option long_opts[] = {
		{ "name", required_argument, NULL, 'n' },
		{ "config", required_argument, NULL, 'c' },
		{ "device", required_argument, NULL, 'd' },
		{ "firmware", required_argument, NULL, 'f' },
		{ "transport", required_argument, NULL, 't' },
		{ "baudrate", required_argument, NULL, 'b' },
		{ "remoteproc", required_argument, NULL, 'r' },
		{ "listen-port", required_argument, NULL, 'p' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	/* CLI overrides (applied after config parse) */
	const char *cli_device = NULL;
	const char *cli_firmware = NULL;
	const char *cli_transport = NULL;
	const char *cli_remoteproc = NULL;
	uint32_t cli_baudrate = 0;

	int opt;
	while ((opt = getopt_long(argc, argv, "n:c:d:f:t:b:r:p:h",
				  long_opts, NULL)) != -1) {
		switch (opt) {
		case 'n':
			strncpy(cfg->name, optarg, sizeof(cfg->name) - 1);
			break;
		case 'c':
			strncpy(cfg->config_path, optarg,
				sizeof(cfg->config_path) - 1);
			break;
		case 'd':
			cli_device = optarg;
			break;
		case 'f':
			cli_firmware = optarg;
			break;
		case 't':
			cli_transport = optarg;
			break;
		case 'b':
			cli_baudrate = (uint32_t)atoi(optarg);
			break;
		case 'r':
			cli_remoteproc = optarg;
			break;
		case 'p':
			listen_port = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			return -1;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (!cfg->name[0]) {
		usage(argv[0]);
		return -1;
	}

	/* apply CLI overrides */
	if (cli_device)
		strncpy(cfg->device, cli_device, sizeof(cfg->device) - 1);
	if (cli_firmware)
		strncpy(cfg->firmware, cli_firmware,
			sizeof(cfg->firmware) - 1);
	if (cli_transport)
		strncpy(cfg->transport, cli_transport,
			sizeof(cfg->transport) - 1);
	if (cli_remoteproc)
		strncpy(cfg->remoteproc, cli_remoteproc,
			sizeof(cfg->remoteproc) - 1);
	if (cli_baudrate)
		cfg->baudrate = cli_baudrate;

	return 0;
}

/*
 * Load MCU firmware via remoteproc.
 * For i.MX8MN: copies ELF to /lib/firmware/, writes to remoteproc sysfs.
 * For external MCUs: firmware is flashed via PVCM protocol after connect.
 */
static int write_sysfs(const char *path, const char *value)
{
	FILE *f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "[pvcm-proxy] cannot write %s: %m\n", path);
		return -1;
	}
	fputs(value, f);
	fclose(f);
	return 0;
}

static int read_sysfs(const char *path, char *buf, size_t size)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	if (!fgets(buf, size, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	/* strip newline */
	char *nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	return 0;
}

/*
 * Discover ttyRPMSG device from remoteproc instance.
 * Walks /sys/class/tty/ttyRPMSG* and finds one whose device
 * path contains the remoteproc's device.
 * Falls back to /dev/ttyRPMSG0 if discovery fails.
 */
static int discover_rpmsg_tty(const char *remoteproc, char *device,
			      size_t device_size)
{
	/* simple approach: try /dev/ttyRPMSG0..3 */
	for (int i = 0; i < 4; i++) {
		char path[64];
		snprintf(path, sizeof(path), "/dev/ttyRPMSG%d", i);
		if (access(path, R_OK | W_OK) == 0) {
			strncpy(device, path, device_size - 1);
			fprintf(stdout, "[pvcm-proxy] discovered RPMsg "
				"device: %s\n", device);
			return 0;
		}
	}

	fprintf(stderr, "[pvcm-proxy] no ttyRPMSG device found\n");
	return -1;
}

static int load_firmware(struct pvcm_config *cfg)
{
	if (!cfg->remoteproc[0]) {
		if (cfg->firmware[0])
			fprintf(stdout, "[pvcm-proxy] external MCU, firmware "
				"will be checked after connect\n");
		else
			fprintf(stdout, "[pvcm-proxy] no remoteproc, "
				"assuming MCU already running\n");
		return 0;
	}

	/* internal M core via remoteproc */
	char rproc_path[128];
	snprintf(rproc_path, sizeof(rproc_path),
		 "/sys/class/remoteproc/%s", cfg->remoteproc);

	if (access(rproc_path, F_OK) != 0) {
		fprintf(stderr, "[pvcm-proxy] remoteproc not found: %s\n",
			rproc_path);
		return -1;
	}

	/* check current state */
	char state[32] = "";
	char state_path[160];
	snprintf(state_path, sizeof(state_path), "%s/state", rproc_path);
	read_sysfs(state_path, state, sizeof(state));

	fprintf(stdout, "[pvcm-proxy] remoteproc %s state: %s\n",
		cfg->remoteproc, state);

	if (strcmp(state, "running") == 0) {
		fprintf(stdout, "[pvcm-proxy] M core already running\n");
		goto discover;
	}

	/* load firmware if specified */
	if (cfg->firmware[0]) {
		if (access(cfg->firmware, R_OK) != 0) {
			fprintf(stderr, "[pvcm-proxy] firmware not found: "
				"%s\n", cfg->firmware);
			return -1;
		}

		/* copy to /lib/firmware/ */
		char fw_name[64];
		const char *base = strrchr(cfg->firmware, '/');
		base = base ? base + 1 : cfg->firmware;
		snprintf(fw_name, sizeof(fw_name), "%s", base);

		char dest[256];
		snprintf(dest, sizeof(dest), "/lib/firmware/%s", fw_name);

		if (access(dest, F_OK) != 0) {
			char cmd[512];
			snprintf(cmd, sizeof(cmd), "cp '%s' '%s'",
				 cfg->firmware, dest);
			fprintf(stdout, "[pvcm-proxy] copying firmware: "
				"%s -> %s\n", cfg->firmware, dest);
			if (system(cmd) != 0) {
				fprintf(stderr, "[pvcm-proxy] firmware copy "
					"failed\n");
				return -1;
			}
		}

		/* set firmware name */
		char fw_path[160];
		snprintf(fw_path, sizeof(fw_path), "%s/firmware", rproc_path);
		fprintf(stdout, "[pvcm-proxy] setting firmware: %s\n",
			fw_name);
		if (write_sysfs(fw_path, fw_name) < 0)
			return -1;
	}

	/* start M core */
	fprintf(stdout, "[pvcm-proxy] starting M core via %s\n",
		cfg->remoteproc);
	if (write_sysfs(state_path, "start") < 0)
		return -1;

	/* wait for RPMsg device to appear */
	fprintf(stdout, "[pvcm-proxy] waiting for RPMsg device...\n");
	sleep(2);

discover:
	/* auto-discover the ttyRPMSG device */
	if (cfg->device[0] == '\0') {
		if (discover_rpmsg_tty(cfg->remoteproc, cfg->device,
				       sizeof(cfg->device)) < 0)
			return -1;
	}

	/* set transport to rpmsg if not already */
	if (cfg->transport[0] == '\0' || strcmp(cfg->transport, "uart") == 0)
		strncpy(cfg->transport, "rpmsg", sizeof(cfg->transport));

	return 0;
}

int main(int argc, char **argv)
{
	struct pvcm_config cfg = { 0 };
	cfg.baudrate = PVCM_DEFAULT_BAUDRATE;
	strncpy(cfg.transport, "uart", sizeof(cfg.transport));

	if (parse_args(argc, argv, &cfg) < 0)
		return 1;

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	fprintf(stdout, "[pvcm-proxy] starting for MCU '%s'\n", cfg.name);

	/* parse run.json if provided, then re-apply CLI overrides */
	if (cfg.config_path[0]) {
		/* save CLI overrides */
		char saved_device[64] = "", saved_transport[16] = "";
		char saved_firmware[128] = "", saved_remoteproc[32] = "";
		uint32_t saved_baudrate = 0;
		if (cfg.device[0])
			strncpy(saved_device, cfg.device, sizeof(saved_device));
		if (cfg.transport[0] && strcmp(cfg.transport, "uart") != 0)
			strncpy(saved_transport, cfg.transport,
				sizeof(saved_transport));
		if (cfg.firmware[0])
			strncpy(saved_firmware, cfg.firmware,
				sizeof(saved_firmware));
		if (cfg.remoteproc[0])
			strncpy(saved_remoteproc, cfg.remoteproc,
				sizeof(saved_remoteproc));
		saved_baudrate = cfg.baudrate;

		if (pvcm_config_parse(&cfg, cfg.config_path) < 0)
			fprintf(stderr, "[pvcm-proxy] warning: could not "
				"parse config, using CLI args\n");

		/* re-apply CLI overrides over config values */
		if (saved_device[0])
			strncpy(cfg.device, saved_device, sizeof(cfg.device));
		if (saved_transport[0])
			strncpy(cfg.transport, saved_transport,
				sizeof(cfg.transport));
		if (saved_firmware[0])
			strncpy(cfg.firmware, saved_firmware,
				sizeof(cfg.firmware));
		if (saved_remoteproc[0])
			strncpy(cfg.remoteproc, saved_remoteproc,
				sizeof(cfg.remoteproc));
		if (saved_baudrate != PVCM_DEFAULT_BAUDRATE)
			cfg.baudrate = saved_baudrate;
	}

	/* load firmware / start M core if remoteproc specified
	 * This may also auto-discover the device path */
	if (cfg.remoteproc[0]) {
		if (load_firmware(&cfg) < 0)
			return 1;
	} else if (cfg.firmware[0]) {
		load_firmware(&cfg);
	}

	/* need at least a device by now */
	if (!cfg.device[0]) {
		fprintf(stderr, "[pvcm-proxy] no device specified. "
			"Use --device, --remoteproc, or --config\n");
		return 1;
	}

	/* select transport */
	struct pvcm_transport *transport;
	if (strcmp(cfg.transport, "rpmsg") == 0) {
		transport = &pvcm_transport_rpmsg;
	} else {
		transport = &pvcm_transport_uart;
	}

	/* open transport */
	if (transport->open(transport, cfg.device, cfg.baudrate) < 0) {
		fprintf(stderr, "[pvcm-proxy] failed to open %s\n",
			cfg.device);
		return 1;
	}

	/* set up protocol session */
	struct pvcm_session session = {
		.transport = transport,
		.connected = false,
	};

	/* handshake with MCU */
	int retries = 5;
	while (retries-- > 0 && running) {
		if (pvcm_handshake(&session) == 0)
			break;
		fprintf(stderr, "[pvcm-proxy] handshake failed, "
			"retrying (%d left)\n", retries);
		sleep(2);
	}

	if (!session.connected) {
		fprintf(stderr, "[pvcm-proxy] MCU '%s' not responding "
			"on %s\n", cfg.name, cfg.device);
		transport->close(transport);
		return 1;
	}

	/* start HTTP bridge */
	pvcm_bridge_init(transport);
	pvcm_bridge_start_listener(transport, listen_port);

	/* main protocol loop */
	pvcm_run(&session, &running);

	/* shutdown */
	fprintf(stdout, "[pvcm-proxy] shutting down MCU '%s'\n", cfg.name);
	transport->close(transport);

	return 0;
}
