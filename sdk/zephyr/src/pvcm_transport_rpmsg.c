/*
 * PVCM RPMsg Transport -- Zephyr side
 *
 * Uses OpenAMP rpmsg_service for communication with the A53 Linux
 * host via shared memory. RPMsg provides message boundaries so we
 * still use the same frame format (sync + len + payload + crc32)
 * for consistency, but the sync bytes are redundant on RPMsg since
 * each message is already framed.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm_transport.h>
#include <pantavisor/pvcm_protocol.h>

#ifdef CONFIG_OPENAMP
#include <openamp/open_amp.h>
#include <metal/device.h>
#include <zephyr/drivers/ipm.h>

LOG_MODULE_REGISTER(pvcm_rpmsg, CONFIG_LOG_DEFAULT_LEVEL);

#define RPMSG_CHAN_NAME "pvcm"

static struct rpmsg_endpoint ep;
static bool ep_ready = false;

/* ring buffer for received frames */
#define RPMSG_RX_BUFSZ 2048
static uint8_t rx_buf[RPMSG_RX_BUFSZ];
static size_t rx_len = 0;
static K_SEM_DEFINE(rx_sem, 0, 1);

static int rpmsg_rx_cb(struct rpmsg_endpoint *ept, void *data,
		       size_t len, uint32_t src, void *priv)
{
	ARG_UNUSED(ept);
	ARG_UNUSED(src);
	ARG_UNUSED(priv);

	if (len > RPMSG_RX_BUFSZ) {
		LOG_ERR("rpmsg frame too large: %zu", len);
		return RPMSG_ERR_BUFF_SIZE;
	}

	memcpy(rx_buf, data, len);
	rx_len = len;
	k_sem_give(&rx_sem);

	return RPMSG_SUCCESS;
}

static void pvcm_rpmsg_ns_bind_cb(struct rpmsg_device *rdev,
			     const char *name,
			     uint32_t dest)
{
	LOG_INF("rpmsg ns bind: %s -> %u", name, dest);
}

static int rpmsg_init(void)
{
	/* TODO: full OpenAMP resource table initialization
	 *
	 * This requires:
	 * 1. Setting up the shared memory region (via device tree)
	 * 2. Creating the virtio/rpmsg device
	 * 3. Registering the endpoint
	 *
	 * The exact initialization depends on the SoC (i.MX8MN uses
	 * MU mailbox for kick, shared DDR for vring buffers).
	 * For now this is a placeholder that will be filled in when
	 * testing on actual Variscite hardware.
	 */
	LOG_INF("PVCM RPMsg transport initializing");

	/* rpmsg_create_ept(&ep, rdev, RPMSG_CHAN_NAME,
	 *                  RPMSG_ADDR_ANY, RPMSG_ADDR_ANY,
	 *                  rpmsg_rx_cb, NULL); */

	return 0;
}

static int rpmsg_send_frame(const void *payload, size_t len)
{
	if (!ep_ready) {
		LOG_ERR("rpmsg endpoint not ready");
		return -1;
	}

	/* build frame: sync + len + payload + crc32 */
	uint8_t frame[4 + len + 4];
	frame[0] = PVCM_SYNC_BYTE_0;
	frame[1] = PVCM_SYNC_BYTE_1;
	frame[2] = len & 0xFF;
	frame[3] = (len >> 8) & 0xFF;
	memcpy(&frame[4], payload, len);

	uint32_t crc = pvcm_crc32(payload, len);
	frame[4 + len + 0] = crc & 0xFF;
	frame[4 + len + 1] = (crc >> 8) & 0xFF;
	frame[4 + len + 2] = (crc >> 16) & 0xFF;
	frame[4 + len + 3] = (crc >> 24) & 0xFF;

	int ret = rpmsg_send(&ep, frame, 4 + len + 4);
	if (ret < 0) {
		LOG_ERR("rpmsg_send failed: %d", ret);
		return ret;
	}

	return 0;
}

static int rpmsg_recv_frame(void *payload, size_t max_len, int timeout_ms)
{
	if (k_sem_take(&rx_sem, K_MSEC(timeout_ms)) != 0)
		return -2; /* timeout */

	/* parse frame from rx_buf: skip sync + len header */
	if (rx_len < 8) { /* min: 4 header + 0 payload + 4 crc */
		LOG_ERR("rpmsg frame too short: %zu", rx_len);
		return -1;
	}

	if (rx_buf[0] != PVCM_SYNC_BYTE_0 || rx_buf[1] != PVCM_SYNC_BYTE_1) {
		LOG_ERR("rpmsg frame sync mismatch");
		return -1;
	}

	uint16_t plen = rx_buf[2] | (rx_buf[3] << 8);
	if (plen > max_len || (size_t)(4 + plen + 4) > rx_len) {
		LOG_ERR("rpmsg frame length mismatch");
		return -1;
	}

	/* verify CRC */
	uint32_t recv_crc = rx_buf[4 + plen] |
			    (rx_buf[4 + plen + 1] << 8) |
			    (rx_buf[4 + plen + 2] << 16) |
			    (rx_buf[4 + plen + 3] << 24);
	uint32_t calc_crc = pvcm_crc32(&rx_buf[4], plen);

	if (recv_crc != calc_crc) {
		LOG_ERR("rpmsg CRC mismatch: %08x vs %08x",
			recv_crc, calc_crc);
		return -1;
	}

	memcpy(payload, &rx_buf[4], plen);
	return (int)plen;
}

static const struct pvcm_transport rpmsg_transport = {
	.init = rpmsg_init,
	.send_frame = rpmsg_send_frame,
	.recv_frame = rpmsg_recv_frame,
};

#endif /* CONFIG_OPENAMP */

#ifdef CONFIG_PANTAVISOR_TRANSPORT_RPMSG
const struct pvcm_transport *pvcm_transport_get(void)
{
#ifdef CONFIG_OPENAMP
	return &rpmsg_transport;
#else
	return NULL;
#endif
}
#endif
