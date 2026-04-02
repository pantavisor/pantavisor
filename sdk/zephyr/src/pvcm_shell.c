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
#include <stdlib.h>
#include <string.h>
#include <pantavisor/pvcm.h>
#include <pantavisor/pvcm_protocol.h>
#include <pantavisor/pvcm_transport.h>

LOG_MODULE_REGISTER(pvcm_shell, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_PANTAVISOR_BRIDGE
static const struct shell *http_shell;
static K_SEM_DEFINE(http_done_sem, 0, 1);

static void http_response_cb(uint16_t status_code,
			     const char *body, size_t body_len,
			     const char *headers, void *ctx)
{
	if (http_shell)
		shell_print(http_shell, "HTTP %d (%zu bytes)", status_code,
			    body_len);
	k_sem_give(&http_done_sem);
}

static void http_error_cb(int error, const char *msg, void *ctx)
{
	if (http_shell)
		shell_error(http_shell, "HTTP error %d: %s", error,
			    msg ? msg : "unknown");
	k_sem_give(&http_done_sem);
}
#endif

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

#ifdef CONFIG_PANTAVISOR_BRIDGE
/*
 * pv http [METHOD] <url> [body]
 *
 * Examples:
 *   pv http http://pv-ctrl.pvlocal/containers
 *   pv http GET pv-ctrl /containers
 *   pv http POST http://pv-ctrl.pvlocal/data {"key":"value"}
 *   pv http PUT pv-ctrl /config {"mode":"auto"}
 *   pv http DELETE http://pv-ctrl.pvlocal/data/1
 */
static int cmd_pv_http(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: pv http [METHOD] <url> [body]\n"
			    "  pv http http://pv-ctrl.pvlocal/containers\n"
			    "  pv http POST http://host.pvlocal/api {\"k\":\"v\"}\n"
			    "  pv http pv-ctrl /path");
		return -EINVAL;
	}

	/* parse optional method */
	uint8_t method = PVCM_HTTP_GET;
	const char *method_str = "GET";
	int arg_idx = 1;

	if (strcmp(argv[1], "GET") == 0 || strcmp(argv[1], "POST") == 0 ||
	    strcmp(argv[1], "PUT") == 0 || strcmp(argv[1], "DELETE") == 0) {
		if (strcmp(argv[1], "POST") == 0) {
			method = PVCM_HTTP_POST; method_str = "POST";
		} else if (strcmp(argv[1], "PUT") == 0) {
			method = PVCM_HTTP_PUT; method_str = "PUT";
		} else if (strcmp(argv[1], "DELETE") == 0) {
			method = PVCM_HTTP_DELETE; method_str = "DELETE";
		}
		arg_idx = 2;
		if (arg_idx >= argc) {
			shell_error(sh, "need URL after method");
			return -EINVAL;
		}
	}

	/* parse URL / host / path */
	char host_hdr[128] = "";
	const char *path;

	if (strncmp(argv[arg_idx], "http://", 7) == 0) {
		const char *hp = argv[arg_idx] + 7;
		const char *slash = strchr(hp, '/');
		if (slash) {
			size_t hlen = slash - hp;
			if (hlen >= sizeof(host_hdr))
				hlen = sizeof(host_hdr) - 1;
			memcpy(host_hdr, hp, hlen);
			host_hdr[hlen] = '\0';
			path = slash;
		} else {
			strncpy(host_hdr, hp, sizeof(host_hdr) - 1);
			path = "/";
		}
		arg_idx++;
	} else if (arg_idx + 1 < argc && argv[arg_idx][0] != '/') {
		snprintf(host_hdr, sizeof(host_hdr), "%s.pvlocal", argv[arg_idx]);
		arg_idx++;
		path = argv[arg_idx];
		arg_idx++;
	} else {
		path = argv[arg_idx];
		arg_idx++;
	}

	/* remaining args = body */
	const char *body = (arg_idx < argc) ? argv[arg_idx] : NULL;
	size_t body_len = body ? strlen(body) : 0;

	http_shell = sh;
	k_sem_reset(&http_done_sem);

	struct pvcm_http_callbacks cb = {
		.on_response = http_response_cb,
		.on_error = http_error_cb,
	};

	/* build headers */
	char headers[256] = "";
	int hoff = 0;
	if (host_hdr[0])
		hoff += snprintf(headers + hoff, sizeof(headers) - hoff,
				 "Host: %s\r\n", host_hdr);
	if (body_len > 0)
		hoff += snprintf(headers + hoff, sizeof(headers) - hoff,
				 "Content-Type: application/json\r\n");

	shell_print(sh, "%s %s%s%s%s ...",
		    method_str,
		    host_hdr[0] ? "http://" : "",
		    host_hdr[0] ? host_hdr : "",
		    path,
		    body_len > 0 ? " (with body)" : "");

	struct pvcm_http_request req = {
		.method = method,
		.path = path,
		.headers = hoff > 0 ? headers : NULL,
		.body = body,
		.body_len = body_len,
	};
	int ret = pvcm_http(&req, &cb);

	if (ret) {
		shell_error(sh, "send failed: %d", ret);
		http_shell = NULL;
		return ret;
	}

	if (k_sem_take(&http_done_sem, K_SECONDS(15)) != 0)
		shell_error(sh, "timeout");

	http_shell = NULL;
	return 0;
}
#endif

#ifdef CONFIG_PANTAVISOR_DBUS
static const struct shell *dbus_shell;
static K_SEM_DEFINE(dbus_done_sem, 0, 1);

static void dbus_call_cb(uint8_t error, const char *result,
			  size_t result_len, void *ctx)
{
	if (dbus_shell) {
		if (error != PVCM_DBUS_OK)
			shell_error(dbus_shell, "D-Bus error %d: %s", error,
				    result_len > 0 ? result : "(no details)");
		else
			shell_print(dbus_shell, "%s",
				    result_len > 0 ? result : "(empty)");
	}
	k_sem_give(&dbus_done_sem);
}

static void dbus_signal_cb(const char *sender, const char *obj_path,
			    const char *interface, const char *member,
			    const char *args_json, void *ctx)
{
	const struct shell *sh = ctx;
	shell_print(sh, "[signal] %s %s %s.%s: %s",
		    sender, obj_path, interface, member,
		    args_json[0] ? args_json : "(no args)");
}

static int cmd_pv_dbus_call(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 5) {
		shell_print(sh, "Usage: pv dbus call <dest> <path> <iface> <method> [args_json]");
		return -EINVAL;
	}

	dbus_shell = sh;
	k_sem_reset(&dbus_done_sem);

	const char *args = argc > 5 ? argv[5] : NULL;
	shell_print(sh, "D-Bus call: %s %s %s.%s", argv[1], argv[2], argv[3], argv[4]);
	int ret = pvcm_dbus_call(argv[1], argv[2], argv[3], argv[4],
				 args, dbus_call_cb, NULL);
	if (ret) {
		shell_error(sh, "send failed: %d", ret);
		dbus_shell = NULL;
		return ret;
	}

	if (k_sem_take(&dbus_done_sem, K_SECONDS(15)) != 0)
		shell_error(sh, "timeout");

	dbus_shell = NULL;
	return 0;
}

static int cmd_pv_dbus_list(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	dbus_shell = sh;
	k_sem_reset(&dbus_done_sem);

	shell_print(sh, "D-Bus ListNames ...");
	int ret = pvcm_dbus_call("org.freedesktop.DBus",
				 "/org/freedesktop/DBus",
				 "org.freedesktop.DBus",
				 "ListNames", NULL,
				 dbus_call_cb, NULL);
	if (ret) {
		shell_error(sh, "send failed: %d", ret);
		dbus_shell = NULL;
		return ret;
	}

	if (k_sem_take(&dbus_done_sem, K_SECONDS(15)) != 0)
		shell_error(sh, "timeout");

	dbus_shell = NULL;
	return 0;
}

static int cmd_pv_dbus_subscribe(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 5) {
		shell_print(sh, "Usage: pv dbus subscribe <sender> <path> <iface> <signal>");
		shell_print(sh, "  Use '-' for any field to match all");
		return -EINVAL;
	}

	const char *sender = strcmp(argv[1], "-") == 0 ? NULL : argv[1];
	const char *path   = strcmp(argv[2], "-") == 0 ? NULL : argv[2];
	const char *iface  = strcmp(argv[3], "-") == 0 ? NULL : argv[3];
	const char *signal = strcmp(argv[4], "-") == 0 ? NULL : argv[4];

	int sid = pvcm_dbus_subscribe(sender, path, iface, signal,
				      dbus_signal_cb, (void *)sh);
	if (sid < 0) {
		shell_error(sh, "subscribe failed: %d", sid);
		return sid;
	}

	shell_print(sh, "subscribed: sub_id=%d", sid);
	return 0;
}

static int cmd_pv_dbus_unsub(const struct shell *sh, size_t argc, char **argv)
{
	if (argc < 2) {
		shell_print(sh, "Usage: pv dbus unsubscribe <sub_id>");
		return -EINVAL;
	}

	int sid = atoi(argv[1]);
	int ret = pvcm_dbus_unsubscribe(sid);
	if (ret)
		shell_error(sh, "unsubscribe failed: %d", ret);
	else
		shell_print(sh, "unsubscribed: sub_id=%d", sid);

	return ret;
}

SHELL_STATIC_SUBCMD_SET_CREATE(pv_dbus_cmds,
	SHELL_CMD(call, NULL,
		  "Call D-Bus method: <dest> <path> <iface> <method> [args]",
		  cmd_pv_dbus_call),
	SHELL_CMD(list, NULL,
		  "List D-Bus names (shortcut for ListNames)",
		  cmd_pv_dbus_list),
	SHELL_CMD(subscribe, NULL,
		  "Subscribe to signal: <sender> <path> <iface> <signal>",
		  cmd_pv_dbus_subscribe),
	SHELL_CMD(unsubscribe, NULL,
		  "Unsubscribe: <sub_id>",
		  cmd_pv_dbus_unsub),
	SHELL_SUBCMD_SET_END
);
#endif

/* ---- Transport ping test ---- */

static K_SEM_DEFINE(ping_done_sem, 0, 1);
static volatile int ping_frames_received;
static volatile int ping_bytes_received;
static volatile uint8_t ping_expected_seq;

void pvcm_echo_on_resp(const uint8_t *buf, int len)
{
	if (len < 4)
		return;
	const pvcm_echo_t *resp = (const pvcm_echo_t *)buf;

	if (resp->seq != ping_expected_seq)
		return;

	ping_frames_received++;
	ping_bytes_received += resp->data_len;

	/* signal completion on every frame — caller decides when done */
	k_sem_give(&ping_done_sem);
}

static int cmd_pv_ping(const struct shell *sh, size_t argc, char **argv)
{
	const struct pvcm_transport *t = pvcm_transport_get();
	if (!t) {
		shell_error(sh, "no transport");
		return -1;
	}

	/* pv ping <total_bytes>  — proxy splits response into 400-byte frames */
	int total = 100;
	if (argc >= 2)
		total = atoi(argv[1]);
	if (total < 1 || total > 1000000) {
		shell_error(sh, "size must be 1-1000000");
		return -1;
	}

	/* how many response frames to expect (proxy uses 400-byte chunks) */
	int expected_frames = (total + 399) / 400;

	static uint8_t seq_counter;
	seq_counter++;
	if (seq_counter == 0) seq_counter = 1;

	ping_expected_seq = seq_counter;
	ping_frames_received = 0;
	ping_bytes_received = 0;
	k_sem_reset(&ping_done_sem);

	/* send ECHO with data_len = total requested size */
	pvcm_echo_t echo = {
		.op = PVCM_OP_ECHO,
		.seq = seq_counter,
		.data_len = (uint32_t)total,
	};
	t->send_frame(&echo, 8); /* op + seq + reserved + data_len */

	shell_print(sh, "ping %d bytes (expect %d frames)...",
		    total, expected_frames);

	/* collect response frames with timeout */
	int64_t deadline = k_uptime_get() + 10000; /* 10s total */
	while (ping_frames_received < expected_frames) {
		int64_t remaining = deadline - k_uptime_get();
		if (remaining <= 0)
			break;
		k_sem_take(&ping_done_sem, K_MSEC(remaining));
	}

	if (ping_frames_received == expected_frames) {
		shell_print(sh, "PASS: %d frames, %d bytes received",
			    ping_frames_received, ping_bytes_received);
	} else {
		shell_error(sh, "FAIL: got %d/%d frames, %d bytes "
			    "(timeout)",
			    ping_frames_received, expected_frames,
			    ping_bytes_received);
	}

	return ping_frames_received == expected_frames ? 0 : -1;
}

/* pv hdrtest <size> — sends request with a large synthetic header */
static int cmd_pv_hdrtest(const struct shell *sh, size_t argc, char **argv)
{
	int hdr_size = 600;
	if (argc >= 2)
		hdr_size = atoi(argv[1]);
	if (hdr_size < 10 || hdr_size > 4000) {
		shell_error(sh, "header size must be 10-4000");
		return -1;
	}

	/* build a large header: "X-Test: AAAA...AAA\r\nHost: pv-ctrl.pvlocal\r\n" */
	static char big_hdr[4096];
	int off = snprintf(big_hdr, sizeof(big_hdr), "X-Test: ");
	int fill = hdr_size - off - 2 - 23; /* minus "X-Test: " + \r\n + Host line */
	if (fill < 0) fill = 0;
	memset(big_hdr + off, 'A', fill);
	off += fill;
	off += snprintf(big_hdr + off, sizeof(big_hdr) - off,
			"\r\nHost: pv-ctrl.pvlocal\r\n");

	shell_print(sh, "GET /x with %d-byte header (%d frames)...",
		    off, (int)((strlen("/x") + off + 479) / 480));

	http_shell = sh;
	k_sem_reset(&http_done_sem);

	struct pvcm_http_request req = {
		.method = PVCM_HTTP_GET,
		.path = "/x",
		.headers = big_hdr,
	};
	struct pvcm_http_callbacks cb = {
		.on_response = http_response_cb,
		.on_error = http_error_cb,
	};
	int ret = pvcm_http(&req, &cb);
	if (ret) {
		shell_error(sh, "send failed: %d", ret);
		http_shell = NULL;
		return ret;
	}

	if (k_sem_take(&http_done_sem, K_SECONDS(15)) != 0)
		shell_error(sh, "timeout");

	http_shell = NULL;
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(pv_cmds,
	SHELL_CMD(status, NULL, "Show PVCM status", cmd_pv_status),
	SHELL_CMD(containers, NULL, "List containers", cmd_pv_containers),
	SHELL_CMD(heartbeat, NULL, "Show heartbeat stats", cmd_pv_heartbeat),
	SHELL_CMD(ping, NULL, "Transport ping: pv ping [bytes]",
		  cmd_pv_ping),
#ifdef CONFIG_PANTAVISOR_BRIDGE
	SHELL_CMD(http, NULL, "GET <url> via pvcm-run", cmd_pv_http),
	SHELL_CMD(hdrtest, NULL, "Header size test: pv hdrtest [bytes]",
		  cmd_pv_hdrtest),
#endif
#ifdef CONFIG_PANTAVISOR_DBUS
	SHELL_CMD(dbus, &pv_dbus_cmds, "D-Bus gateway commands", NULL),
#endif
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(pv, &pv_cmds, "Pantavisor MCU commands", NULL);
