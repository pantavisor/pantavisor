/*
 * RPMsg shell transport backend.
 *
 * Bridges the Zephyr shell to a dedicated RPMsg endpoint so Linux
 * can interact with the MCU shell via /dev/ttyRPMSGN.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SHELL_RPMSG_H__
#define SHELL_RPMSG_H__

#include <zephyr/shell/shell.h>
#include <openamp/open_amp.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const struct shell_transport_api shell_rpmsg_transport_api;

#define SHELL_RPMSG_RX_BUF_SIZE 256

struct shell_rpmsg {
	shell_transport_handler_t handler;
	void *context;
	struct rpmsg_endpoint ept;
	struct rpmsg_device *rpdev;
	struct k_sem rx_sem;
	uint8_t rx_buf[SHELL_RPMSG_RX_BUF_SIZE];
	size_t rx_len;
	size_t rx_pos;
	bool ready;
};

#define SHELL_RPMSG_DEFINE(_name)				\
	static struct shell_rpmsg _name##_shell_rpmsg;		\
	struct shell_transport _name = {			\
		.api = &shell_rpmsg_transport_api,		\
		.ctx = (struct shell_rpmsg *)&_name##_shell_rpmsg \
	}

/**
 * @brief Set the RPMsg device for the shell backend.
 *
 * Must be called after the RPMsg vdev is created and before
 * the shell is initialized. Creates the endpoint.
 */
int shell_rpmsg_set_rpdev(struct shell_transport *transport,
			  struct rpmsg_device *rpdev);

const struct shell *shell_backend_rpmsg_get_ptr(void);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_RPMSG_H__ */
