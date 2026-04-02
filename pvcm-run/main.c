/*
 * pvcm-run -- per-MCU runtime process
 *
 * One instance per MCU container, started by the pv_pvcm plugin
 * inside a mount namespace. From xconnect's perspective this IS
 * the container.
 *
 * Architecture: single-threaded, event-driven via libevent.
 *   - Transport fd read event: dispatches PVCM frames
 *   - evhttp listener: inbound HTTP to MCU
 *   - D-Bus fd read event: signal delivery + async call replies
 *   - Heartbeat timer: monitors MCU health
 *   - Signal events: clean shutdown on SIGTERM/SIGINT
 *
 * Copyright (c) 2024-2026 Pantacor Ltd.
 * SPDX-License-Identifier: MIT
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <event2/event.h>

#include "pvcm_config.h"
#include "pvcm_transport.h"
#include "pvcm_protocol.h"
#include "pvcm_bridge.h"
#include "pvcm_dbus_bridge.h"
#include "pvcm_fs_bridge.h"

static FILE *dbglog = NULL;
static char dbus_socket[256] = "";

/* log to both stdout/stderr and debug file */
#define pvcm_log(fmt, ...) do {                                           \
	fprintf(stdout, "[pvcm-run] " fmt "\n", ##__VA_ARGS__);         \
	if (dbglog) {                                                     \
		fprintf(dbglog, "[pvcm-run] " fmt "\n", ##__VA_ARGS__); \
		fflush(dbglog);                                           \
	}                                                                 \
} while (0)

#define pvcm_err(fmt, ...) do {                                           \
	fprintf(stderr, "[pvcm-run] " fmt "\n", ##__VA_ARGS__);         \
	if (dbglog) {                                                     \
		fprintf(dbglog, "[pvcm-run] ERROR: " fmt "\n", ##__VA_ARGS__); \
		fflush(dbglog);                                           \
	}                                                                 \
} while (0)

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
		"  --route <spec>           HTTP route: name=unix:/path or name=tcp:host:port\n"
		"  --fs-share <spec>        FS share: name=/linux/path\n"
		"  --dbus-socket <path>     D-Bus socket path (enables D-Bus bridge)\n"
		"  --dbus-session           Use session D-Bus (for testing)\n"
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
		{ "route", required_argument, NULL, 'R' },
		{ "fs-share", required_argument, NULL, 'F' },
		{ "dbus-socket", required_argument, NULL, 'D' },
		{ "dbus-session", no_argument, NULL, 'S' },
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
		case 'D':
			strncpy(dbus_socket, optarg, sizeof(dbus_socket) - 1);
			break;
		case 'S': {
			/* use session D-Bus for testing */
			const char *addr = getenv("DBUS_SESSION_BUS_ADDRESS");
			if (addr) {
				/* extract path from unix:path=/run/user/1000/bus */
				const char *p = strstr(addr, "path=");
				if (p) {
					p += 5;
					const char *end = strchr(p, ',');
					size_t len = end ? (size_t)(end - p) : strlen(p);
					if (len >= sizeof(dbus_socket))
						len = sizeof(dbus_socket) - 1;
					memcpy(dbus_socket, p, len);
					dbus_socket[len] = '\0';
				}
			}
			break;
		}
		case 'R':
			if (pvcm_bridge_add_route(optarg) < 0) {
				fprintf(stderr, "invalid route: %s\n", optarg);
				return -1;
			}
			break;
		case 'F':
			if (pvcm_fs_bridge_add_share(optarg) < 0) {
				fprintf(stderr, "invalid fs-share: %s\n", optarg);
				return -1;
			}
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
 */
static int write_sysfs(const char *path, const char *value)
{
	FILE *f = fopen(path, "w");
	if (!f) {
		pvcm_err("cannot write %s: %m", path);
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
	char *nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	return 0;
}

static int discover_rpmsg_tty(const char *remoteproc, char *device,
			      size_t device_size)
{
	for (int i = 0; i < 4; i++) {
		char path[64];
		snprintf(path, sizeof(path), "/dev/ttyRPMSG%d", i);
		if (access(path, R_OK | W_OK) == 0) {
			strncpy(device, path, device_size - 1);
			pvcm_log("discovered RPMsg device: %s", device);
			return 0;
		}
	}

	pvcm_err("no ttyRPMSG device found");
	return -1;
}

static int load_firmware(struct pvcm_config *cfg)
{
	if (!cfg->remoteproc[0]) {
		if (cfg->firmware[0])
			pvcm_log("external MCU, firmware will be checked after connect");
		else
			pvcm_log("no remoteproc, assuming MCU already running");
		return 0;
	}

	char rproc_path[128];
	snprintf(rproc_path, sizeof(rproc_path),
		 "/sys/class/remoteproc/%s", cfg->remoteproc);

	if (access(rproc_path, F_OK) != 0) {
		pvcm_err("remoteproc not found: %s", rproc_path);
		return -1;
	}

	char state[32] = "";
	char state_path[160];
	snprintf(state_path, sizeof(state_path), "%s/state", rproc_path);
	read_sysfs(state_path, state, sizeof(state));

	pvcm_log("remoteproc %s state: %s", cfg->remoteproc, state);

	if (strcmp(state, "running") == 0) {
		pvcm_log("M core already running");
		goto discover;
	}

	if (cfg->firmware[0]) {
		if (access(cfg->firmware, R_OK) != 0) {
			pvcm_err("firmware not found: %s", cfg->firmware);
			return -1;
		}

		char fw_name[64];
		const char *base = strrchr(cfg->firmware, '/');
		if (base) {
			char fw_dir[256];
			size_t dir_len = base - cfg->firmware;
			if (dir_len >= sizeof(fw_dir))
				dir_len = sizeof(fw_dir) - 1;
			memcpy(fw_dir, cfg->firmware, dir_len);
			fw_dir[dir_len] = '\0';
			base++;

			pvcm_log("setting firmware search path: %s", fw_dir);
			write_sysfs("/sys/module/firmware_class"
				    "/parameters/path", fw_dir);
		} else {
			base = cfg->firmware;
		}
		snprintf(fw_name, sizeof(fw_name), "%s", base);

		char fw_rproc_path[160];
		snprintf(fw_rproc_path, sizeof(fw_rproc_path),
			 "%s/firmware", rproc_path);
		pvcm_log("setting firmware: %s", fw_name);
		if (write_sysfs(fw_rproc_path, fw_name) < 0)
			return -1;
	}

	pvcm_log("starting M core via %s", cfg->remoteproc);
	if (write_sysfs(state_path, "start") < 0)
		return -1;

	if (cfg->firmware[0]) {
		pvcm_log("restoring firmware search path");
		write_sysfs("/sys/module/firmware_class"
			    "/parameters/path", "");
	}

	pvcm_log("waiting for RPMsg device...");
	sleep(2);

discover:
	if (cfg->device[0] == '/' && access(cfg->device, R_OK | W_OK) == 0) {
		pvcm_log("using explicit device: %s", cfg->device);
		goto rpmsg_found;
	}

	{
		int rpmsg_retries = 15;
		while (rpmsg_retries-- > 0) {
			if (discover_rpmsg_tty(cfg->remoteproc, cfg->device,
					       sizeof(cfg->device)) == 0)
				goto rpmsg_found;
			pvcm_log("waiting for ttyRPMSG (%d retries left)",
				 rpmsg_retries);
			sleep(2);
		}
		pvcm_err("ttyRPMSG never appeared");
		return -1;
	}
rpmsg_found:

	if (cfg->transport[0] == '\0' || strcmp(cfg->transport, "uart") == 0)
		strncpy(cfg->transport, "rpmsg", sizeof(cfg->transport));

	return 0;
}

/* ---- Event callbacks ---- */

/* Transport fd is readable — dispatch PVCM frames */
static void transport_read_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	struct pvcm_session *s = arg;

	/* drain all available frames */
	for (;;) {
		int ret = pvcm_dispatch_one(s);
		if (ret <= 0)
			break;
	}
}

/* Heartbeat timer — check if MCU is still alive */
static void heartbeat_timer_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	struct pvcm_session *s = arg;

	time_t now = time(NULL);
	time_t elapsed = now - s->last_heartbeat_time;

	if (elapsed > 15) {
		fprintf(stderr, "[pvcm-run] heartbeat timeout (%lds)\n",
			elapsed);
	}
}

/* Signal handler — break event loop */
static void signal_cb(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	struct event_base *base = arg;
	event_base_loopbreak(base);
}

/* ---- main ---- */

int main(int argc, char **argv)
{
	struct pvcm_config cfg = { 0 };
	cfg.baudrate = PVCM_DEFAULT_BAUDRATE;
	strncpy(cfg.transport, "uart", sizeof(cfg.transport));

	/* disable stdio buffering so logs appear immediately */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	if (parse_args(argc, argv, &cfg) < 0)
		return 1;

	mkdir("/storage/logs/current/claudecli", 0755);
	dbglog = fopen("/storage/logs/current/claudecli/pvcm-run.log", "w");

	pvcm_log("starting pvcm-run for MCU '%s'", cfg.name);

	/* parse run.json if provided, then re-apply CLI overrides */
	if (cfg.config_path[0]) {
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
			pvcm_err("could not parse config, using CLI args");

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

	/* auto-discover firmware ELF from config directory */
	if (!cfg.firmware[0] && cfg.config_path[0]) {
		char dir[256];
		strncpy(dir, cfg.config_path, sizeof(dir) - 1);
		char *slash = strrchr(dir, '/');
		if (slash) {
			*slash = '\0';
			DIR *d = opendir(dir);
			if (d) {
				struct dirent *ent;
				while ((ent = readdir(d)) != NULL) {
					size_t len = strlen(ent->d_name);
					if (len > 4 && strcmp(ent->d_name + len - 4, ".elf") == 0) {
						snprintf(cfg.firmware,
							 sizeof(cfg.firmware),
							 "%s/%s", dir,
							 ent->d_name);
						pvcm_log("auto-discovered firmware: %s",
							 cfg.firmware);
						break;
					}
				}
				closedir(d);
			}
		}
	}

	/* load firmware / start M core */
	if (cfg.remoteproc[0]) {
		if (load_firmware(&cfg) < 0)
			return 1;
	} else if (cfg.firmware[0]) {
		load_firmware(&cfg);
	}

	if (!cfg.device[0]) {
		pvcm_err("no device specified. Use --device, --remoteproc, or --config");
		return 1;
	}

	/* select transport */
	struct pvcm_transport *transport;
	if (strcmp(cfg.transport, "rpmsg") == 0)
		transport = &pvcm_transport_rpmsg;
	else
		transport = &pvcm_transport_uart;

	/* open transport */
	if (transport->open(transport, cfg.device, cfg.baudrate) < 0) {
		pvcm_err("failed to open %s", cfg.device);
		return 1;
	}

	/* set up protocol session */
	struct pvcm_session session = {
		.transport = transport,
		.connected = false,
	};

	/* blocking handshake — before event loop */
	int retries = 5;
	while (retries-- > 0) {
		if (pvcm_handshake(&session) == 0)
			break;
		pvcm_err("handshake failed, retrying (%d left)", retries);
		sleep(2);
	}

	if (!session.connected) {
		pvcm_err("MCU '%s' not responding on %s", cfg.name,
			 cfg.device);
		transport->close(transport);
		return 1;
	}

	/* switch transport fd to non-blocking for event loop */
	int flags = fcntl(transport->fd, F_GETFL, 0);
	fcntl(transport->fd, F_SETFL, flags | O_NONBLOCK);

	/* create event base */
	struct event_base *base = event_base_new();
	if (!base) {
		pvcm_err("event_base_new failed");
		transport->close(transport);
		return 1;
	}

	/* transport read event */
	struct event *transport_ev = event_new(base, transport->fd,
					       EV_READ | EV_PERSIST,
					       transport_read_cb, &session);
	event_add(transport_ev, NULL);

	/* transport write queue — send_frame becomes non-blocking enqueue */
	pvcm_transport_setup_write_event(transport, base);

	/* heartbeat timer (5s interval) */
	struct event *heartbeat_ev = event_new(base, -1, EV_PERSIST,
					       heartbeat_timer_cb, &session);
	struct timeval hb_tv = { .tv_sec = 5, .tv_usec = 0 };
	event_add(heartbeat_ev, &hb_tv);

	/* signal events for clean shutdown */
	struct event *sigterm_ev = evsignal_new(base, SIGTERM, signal_cb, base);
	struct event *sigint_ev = evsignal_new(base, SIGINT, signal_cb, base);
	event_add(sigterm_ev, NULL);
	event_add(sigint_ev, NULL);

	/* start HTTP bridge */
	pvcm_bridge_init(transport);
	pvcm_bridge_start_listener(base, transport, listen_port);

	/* start filesystem bridge */
	pvcm_fs_bridge_init(transport);

	/* start D-Bus bridge */
	if (dbus_socket[0]) {
		if (pvcm_dbus_bridge_init(base, transport, dbus_socket) < 0)
			pvcm_err("D-Bus bridge init failed (continuing without)");
	}

	pvcm_log("entering event loop");

	/* run the event loop — single thread, no mutex, no pthread */
	event_base_dispatch(base);

	/* shutdown */
	pvcm_log("shutting down MCU '%s'", cfg.name);
	pvcm_dbus_bridge_cleanup();

	event_free(transport_ev);
	event_free(heartbeat_ev);
	event_free(sigterm_ev);
	event_free(sigint_ev);
	event_base_free(base);

	transport->close(transport);
	return 0;
}
