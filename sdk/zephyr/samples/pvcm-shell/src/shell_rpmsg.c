/*
 * RPMsg shell transport backend.
 *
 * Creates a "rpmsg-tty" endpoint for the Zephyr shell. Linux sees
 * this as /dev/ttyRPMSGN — open it to get an interactive shell
 * on the MCU.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "shell_rpmsg.h"
#include <string.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(shell_rpmsg, LOG_LEVEL_DBG);

SHELL_RPMSG_DEFINE(shell_transport_rpmsg);
SHELL_DEFINE(shell_rpmsg_instance, "mcu:~$ ", &shell_transport_rpmsg,
	     4, 100, SHELL_FLAG_OLF_CRLF);

static bool shell_initialized;

static int rpmsg_shell_rx_cb(struct rpmsg_endpoint *ept, void *data,
			     size_t len, uint32_t src, void *priv)
{
	struct shell_rpmsg *sh = priv;

	/*
	 * First RX means Linux has bound the endpoint and set dest_addr.
	 * Now it's safe to init the shell (which writes the prompt).
	 */
	if (!shell_initialized) {
		shell_initialized = true;
		static const struct shell_backend_config_flags cfg_flags =
			SHELL_DEFAULT_BACKEND_CONFIG_FLAGS;
		shell_init(&shell_rpmsg_instance, NULL, cfg_flags, false, 0);
	}

	if (len > SHELL_RPMSG_RX_BUF_SIZE) {
		len = SHELL_RPMSG_RX_BUF_SIZE;
	}

	memcpy(sh->rx_buf, data, len);
	sh->rx_len = len;
	sh->rx_pos = 0;

	if (sh->handler) {
		sh->handler(SHELL_TRANSPORT_EVT_RX_RDY, sh->context);
	}

	return RPMSG_SUCCESS;
}

int shell_rpmsg_set_rpdev(struct shell_transport *transport,
			  struct rpmsg_device *rpdev)
{
	struct shell_rpmsg *sh = transport->ctx;
	int ret;

	sh->rpdev = rpdev;

	ret = rpmsg_create_ept(&sh->ept, rpdev, "rpmsg-tty",
			       RPMSG_ADDR_ANY, RPMSG_ADDR_ANY,
			       rpmsg_shell_rx_cb, NULL);
	if (ret) {
		LOG_ERR("failed to create shell rpmsg endpoint: %d", ret);
		return ret;
	}

	sh->ept.priv = sh;
	sh->ready = true;

	LOG_INF("shell rpmsg endpoint ready addr=0x%04x", sh->ept.addr);

	/* shell_init is deferred to first RX — Linux must bind first
	 * so dest_addr is set before the shell writes its prompt. */

	return 0;
}

static int init(const struct shell_transport *transport,
		const void *config,
		shell_transport_handler_t evt_handler,
		void *context)
{
	struct shell_rpmsg *sh = (struct shell_rpmsg *)transport->ctx;

	sh->handler = evt_handler;
	sh->context = context;
	sh->rx_len = 0;
	sh->rx_pos = 0;

	return 0;
}

static int uninit(const struct shell_transport *transport)
{
	struct shell_rpmsg *sh = (struct shell_rpmsg *)transport->ctx;

	if (sh->ready) {
		rpmsg_destroy_ept(&sh->ept);
		sh->ready = false;
	}

	return 0;
}

static int enable(const struct shell_transport *transport, bool blocking_tx)
{
	return 0;
}

static int shell_write(const struct shell_transport *transport,
		       const void *data, size_t length, size_t *cnt)
{
	struct shell_rpmsg *sh = (struct shell_rpmsg *)transport->ctx;

	if (!sh->ready) {
		*cnt = 0;
		return -ENODEV;
	}

	int ret = rpmsg_send(&sh->ept, data, length);
	if (ret < 0) {
		*cnt = 0;
		return ret;
	}

	*cnt = length;

	sh->handler(SHELL_TRANSPORT_EVT_TX_RDY, sh->context);

	return 0;
}

static int shell_read(const struct shell_transport *transport,
		      void *data, size_t length, size_t *cnt)
{
	struct shell_rpmsg *sh = (struct shell_rpmsg *)transport->ctx;

	if (sh->rx_pos < sh->rx_len) {
		size_t avail = sh->rx_len - sh->rx_pos;
		size_t to_copy = (avail < length) ? avail : length;

		memcpy(data, &sh->rx_buf[sh->rx_pos], to_copy);
		sh->rx_pos += to_copy;
		*cnt = to_copy;
	} else {
		*cnt = 0;
	}

	return 0;
}

const struct shell_transport_api shell_rpmsg_transport_api = {
	.init = init,
	.uninit = uninit,
	.enable = enable,
	.write = shell_write,
	.read = shell_read,
};

const struct shell *shell_backend_rpmsg_get_ptr(void)
{
	return &shell_rpmsg_instance;
}

/* shell_init is called from shell_rpmsg_set_rpdev() after the
 * RPMsg endpoint is created. No SYS_INIT needed. */
