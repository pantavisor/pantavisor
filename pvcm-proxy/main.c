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

static volatile bool running = true;

static void signal_handler(int sig)
{
	(void)sig;
	running = false;
}

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
			strncpy(cfg->name, optarg, sizeof(cfg->name) - 1);
			break;
		case 'c':
			strncpy(cfg->config_path, optarg,
				sizeof(cfg->config_path) - 1);
			break;
		case 'h':
			usage(argv[0]);
			return -1;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (!cfg->name[0] || !cfg->config_path[0]) {
		usage(argv[0]);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct pvcm_config cfg = { 0 };
	cfg.baudrate = PVCM_DEFAULT_BAUDRATE;

	if (parse_args(argc, argv, &cfg) < 0)
		return 1;

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);

	fprintf(stdout, "[pvcm-proxy] starting for MCU '%s'\n", cfg.name);

	/* parse run.json */
	if (pvcm_config_parse(&cfg, cfg.config_path) < 0) {
		fprintf(stderr, "[pvcm-proxy] failed to parse config\n");
		return 1;
	}

	/* select transport */
	struct pvcm_transport *transport;
	if (strcmp(cfg.transport, "rpmsg") == 0) {
		/* TODO: RPMsg transport */
		fprintf(stderr, "[pvcm-proxy] RPMsg transport not yet "
			"implemented\n");
		return 1;
	} else {
		transport = &pvcm_transport_uart;
	}

	/* open transport */
	if (transport->open(transport, cfg.device, cfg.baudrate) < 0) {
		fprintf(stderr, "[pvcm-proxy] failed to open transport\n");
		return 1;
	}

	/* set up protocol session */
	struct pvcm_session session = {
		.transport = transport,
		.connected = false,
	};

	/* handshake with MCU */
	int retries = 3;
	while (retries-- > 0 && running) {
		if (pvcm_handshake(&session) == 0)
			break;
		fprintf(stderr, "[pvcm-proxy] handshake failed, "
			"retrying (%d left)\n", retries);
		sleep(1);
	}

	if (!session.connected) {
		fprintf(stderr, "[pvcm-proxy] MCU '%s' not responding\n",
			cfg.name);
		transport->close(transport);
		return 1;
	}

	/* main protocol loop */
	pvcm_run(&session, &running);

	/* shutdown */
	fprintf(stdout, "[pvcm-proxy] shutting down MCU '%s'\n", cfg.name);
	transport->close(transport);

	return 0;
}
