/*
 * PVCM Shell Commands -- optional
 *
 * Registers 'pv' shell commands for interactive debug:
 *   pv status       - show PVCM connection status and boot state
 *   pv containers   - list containers in current revision
 *   pv heartbeat    - show heartbeat stats
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm_protocol.h>

LOG_MODULE_REGISTER(pvcm_shell, CONFIG_LOG_DEFAULT_LEVEL);

static int cmd_pv_status(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(sh, "PVCM protocol v%d", PVCM_PROTOCOL_VERSION);
	shell_print(sh, "Transport: %s",
		    IS_ENABLED(CONFIG_PANTAVISOR_TRANSPORT_RPMSG) ?
		    "RPMsg" : "UART");
	shell_print(sh, "Heartbeat: %d ms",
		    CONFIG_PANTAVISOR_HEARTBEAT_INTERVAL_MS);

	/* TODO: show connection state, boot state from pvcm_state */

	return 0;
}

static int cmd_pv_containers(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	/* TODO: query container list via REST gateway */
	shell_print(sh, "(not yet connected to pvcm-manager)");

	return 0;
}

static int cmd_pv_heartbeat(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	shell_print(sh, "Uptime: %lld s", k_uptime_get() / 1000);

	/* TODO: show crash_count, health status */

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(pv_cmds,
	SHELL_CMD(status, NULL, "Show PVCM status", cmd_pv_status),
	SHELL_CMD(containers, NULL, "List containers", cmd_pv_containers),
	SHELL_CMD(heartbeat, NULL, "Show heartbeat stats", cmd_pv_heartbeat),
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(pv, &pv_cmds, "Pantavisor MCU commands", NULL);
