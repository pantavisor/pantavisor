/*
 * pvcm-proxy -- per-MCU runtime process
 *
 * One instance per MCU container, started by the pv_pvcm plugin
 * inside a mount namespace. From xconnect's perspective this IS
 * the container.
 *
 * Responsibilities:
 *  - Open transport (UART or RPMsg) to the MCU
 *  - Speak PVCM protocol (handshake, heartbeat, log, REST/DBus bridge)
 *  - Flash firmware if needed
 *  - Monitor MCU health
 *  - Create service sockets for xconnect
 *  - Bridge xconnect sockets ↔ PVCM protocol frames
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

#include "../protocol/pvcm_protocol.h"

static volatile bool running = true;

static void signal_handler(int sig)
{
	(void)sig;
	running = false;
}

struct pvcm_config {
	const char *name;     /* container name */
	const char *config;   /* path to run.json */
	const char *device;   /* transport device path */
	const char *transport; /* "uart" or "rpmsg" */
	uint32_t baudrate;
};

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s --name <name> --config <run.json>\n", prog);
}

static int parse_args(int argc, char **argv, struct pvcm_config *cfg)
{
	static struct option long_opts[] = {
		{ "name", required_argument, NULL, 'n' },
		{ "config", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "n:c:h", long_opts, NULL)) !=
	       -1) {
		switch (opt) {
		case 'n':
			cfg->name = optarg;
			break;
		case 'c':
			cfg->config = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return -1;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (!cfg->name || !cfg->config) {
		usage(argv[0]);
		return -1;
	}

	return 0;
}

/*
 * Probe MCU via PVCM HELLO.
 * Returns 0 if MCU responds with HELLO_RESP, -1 otherwise.
 */
static int pvcm_probe(int transport_fd)
{
	/* TODO: send HELLO frame, wait for HELLO_RESP */
	fprintf(stdout, "[pvcm-proxy] probing MCU...\n");
	return 0;
}

/*
 * Run heartbeat monitor loop.
 * Receives PVCM_EVT_HEARTBEAT frames every 5s from MCU.
 * Reports health status to stdout (captured by pantavisor logger).
 */
static int pvcm_heartbeat_loop(int transport_fd)
{
	while (running) {
		/* TODO: read frame from transport
		 * - if HEARTBEAT: log status, update health
		 * - if LOG: forward to stdout
		 * - if REST_REQ/DBUS_CALL: bridge to xconnect socket
		 * - if timeout: MCU unresponsive, report degraded
		 */
		sleep(1);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct pvcm_config cfg = {
		.name = NULL,
		.config = NULL,
		.device = NULL,
		.transport = "uart",
		.baudrate = PVCM_DEFAULT_BAUDRATE,
	};

	if (parse_args(argc, argv, &cfg) < 0)
		return 1;

	/* install signal handlers for clean shutdown */
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	fprintf(stdout, "[pvcm-proxy] starting for MCU '%s' (config=%s)\n",
		cfg.name, cfg.config);

	/* TODO: parse run.json to get device, transport, baudrate, firmware */

	/* TODO: open transport (UART or RPMsg) */
	int transport_fd = -1;

	/* probe MCU */
	if (pvcm_probe(transport_fd) < 0) {
		fprintf(stderr,
			"[pvcm-proxy] MCU '%s' not responding, will retry\n",
			cfg.name);
		/* TODO: SMP probe for virgin MCUboot, firmware install */
	}

	fprintf(stdout, "[pvcm-proxy] MCU '%s' connected\n", cfg.name);

	/* TODO: check firmware version, flash if needed */

	/* TODO: create service sockets in our namespace for xconnect */

	/* main loop: heartbeat monitor + protocol dispatch */
	pvcm_heartbeat_loop(transport_fd);

	/* shutdown: signal MCU, close transport */
	fprintf(stdout, "[pvcm-proxy] shutting down MCU '%s'\n", cfg.name);

	/* TODO: send shutdown to MCU, close transport fd */

	return 0;
}
