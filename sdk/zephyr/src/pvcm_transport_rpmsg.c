/*
 * PVCM RPMsg transport (Zephyr, Cortex-M)
 *
 * Flow control via vring backpressure:
 *   ISR holds vring buffers (rpmsg_hold_rx_buffer), queues pointers.
 *   Consumer thread parses PVCM frames from held buffers, then releases.
 *   When consumer can't keep up, held buffers fill the vring and the
 *   Linux sender gets ENOMEM — natural backpressure, no frame drops.
 *
 * Northbound API: same send_frame/recv_frame as UART transport.
 * Upper layers don't know about vring internals.
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm_protocol.h>
#include <pantavisor/pvcm_transport.h>

#ifdef CONFIG_OPENAMP
#include <openamp/open_amp.h>

LOG_MODULE_REGISTER(pvcm_rpmsg, CONFIG_LOG_DEFAULT_LEVEL);

/* ---- Zero-copy RX ring ----
 *
 * Lightweight ring of pointers into held vring buffers.
 * ISR produces, consumer thread consumes. No memcpy in ISR path.
 * Ring size must be >= vring buffer count (NUM_RPMSG_BUFF).
 */

#define RX_RING_SIZE 32 /* power of 2, >= CONFIG_OPENAMP_RSC_TABLE_NUM_RPMSG_BUFF */

struct rx_entry {
	void *data;    /* pointer into held vring buffer */
	size_t len;    /* RPMsg payload length */
};

static struct rx_entry rx_ring[RX_RING_SIZE];
static volatile uint32_t rx_head; /* ISR writes */
static volatile uint32_t rx_tail; /* consumer reads */
static K_SEM_DEFINE(rx_sem, 0, RX_RING_SIZE);

static struct rpmsg_endpoint *proto_ept;
static volatile bool transport_ready;

/* Mutex for rpmsg_send — multiple threads (heartbeat, shell) share TX vring */
static K_MUTEX_DEFINE(rpmsg_tx_mutex);

/*
 * RPMsg rx callback — ISR context.
 *
 * Holds the vring buffer to prevent reuse, queues a lightweight
 * pointer entry. The vring buffer stays allocated until the consumer
 * thread calls rpmsg_release_rx_buffer() after processing.
 */
int pvcm_rpmsg_rx_cb(struct rpmsg_endpoint *ept, void *data,
		     size_t len, uint32_t src, void *priv)
{
	ARG_UNUSED(src);
	ARG_UNUSED(priv);

	uint32_t next = (rx_head + 1) & (RX_RING_SIZE - 1);
	if (next == rx_tail) {
		/* ring full — don't hold, let vring reclaim the buffer.
		 * This shouldn't happen if ring size >= vring buffers. */
		LOG_WRN("rx ring full, dropping frame");
		return RPMSG_SUCCESS;
	}

	/* hold the vring buffer — sender can't reuse it until we release */
	rpmsg_hold_rx_buffer(ept, data);

	rx_ring[rx_head].data = data;
	rx_ring[rx_head].len = len;
	rx_head = next;

	k_sem_give(&rx_sem);
	return RPMSG_SUCCESS;
}

void pvcm_rpmsg_set_endpoint(struct rpmsg_endpoint *ept)
{
	rx_head = 0;
	rx_tail = 0;
	proto_ept = ept;
	transport_ready = true;
}

/* ---- Init ---- */

static int rpmsg_init(void)
{
	int tries = 0;

	while (!transport_ready && tries < 150) {
		k_msleep(200);
		tries++;
	}
	if (!transport_ready) {
		LOG_ERR("rpmsg transport not ready after 30s");
		return -1;
	}
	LOG_INF("rpmsg transport ready");
	return 0;
}

/* ---- TX ----
 *
 * Static frame buffer — protected by rpmsg_tx_mutex so multiple
 * threads (heartbeat, shell) can share it safely. No VLA on stack.
 */
#define TX_FRAME_MAX (4 + PVCM_MAX_CHUNK_SIZE + 8 + 4) /* sync+len + max payload + crc */
static uint8_t tx_frame[TX_FRAME_MAX];

static int rpmsg_send_frame(const void *payload, size_t len)
{
	if (!transport_ready || !proto_ept) {
		LOG_ERR("rpmsg endpoint not ready");
		return -1;
	}

	size_t frame_len = 4 + len + 4;
	if (frame_len > TX_FRAME_MAX) {
		LOG_ERR("frame too large: %zu", frame_len);
		return -1;
	}

	k_mutex_lock(&rpmsg_tx_mutex, K_FOREVER);

	tx_frame[0] = PVCM_SYNC_BYTE_0;
	tx_frame[1] = PVCM_SYNC_BYTE_1;
	tx_frame[2] = len & 0xFF;
	tx_frame[3] = (len >> 8) & 0xFF;
	memcpy(&tx_frame[4], payload, len);

	uint32_t crc = pvcm_crc32(payload, len);
	tx_frame[4 + len + 0] = crc & 0xFF;
	tx_frame[4 + len + 1] = (crc >> 8) & 0xFF;
	tx_frame[4 + len + 2] = (crc >> 16) & 0xFF;
	tx_frame[4 + len + 3] = (crc >> 24) & 0xFF;

	int ret = rpmsg_send(proto_ept, tx_frame, frame_len);
	k_mutex_unlock(&rpmsg_tx_mutex);

	if (ret < 0) {
		LOG_ERR("rpmsg_send failed: %d", ret);
		return ret;
	}

	return 0;
}

/* ---- RX ----
 *
 * Parse one PVCM frame from a held vring buffer, copy payload out,
 * release the vring buffer. Same northbound API as UART transport.
 */

static int rpmsg_recv_frame(void *payload, size_t max_len, int timeout_ms)
{
	if (k_sem_take(&rx_sem, K_MSEC(timeout_ms)) != 0)
		return -2; /* timeout */

	if (rx_tail == rx_head)
		return -1;

	struct rx_entry *e = &rx_ring[rx_tail];
	uint8_t *buf = e->data;
	size_t buf_len = e->len;
	int result = -1;

	if (buf_len < 8) {
		LOG_ERR("frame too short: %zu", buf_len);
		goto release;
	}

	if (buf[0] != PVCM_SYNC_BYTE_0 || buf[1] != PVCM_SYNC_BYTE_1) {
		LOG_ERR("sync mismatch: %02x %02x", buf[0], buf[1]);
		goto release;
	}

	uint16_t plen = buf[2] | (buf[3] << 8);
	if (plen > max_len || (size_t)(4 + plen + 4) > buf_len) {
		LOG_ERR("frame length: plen=%u max=%zu buf=%zu",
			plen, max_len, buf_len);
		goto release;
	}

	uint32_t recv_crc = buf[4 + plen] |
			    (buf[4 + plen + 1] << 8) |
			    (buf[4 + plen + 2] << 16) |
			    (buf[4 + plen + 3] << 24);
	uint32_t calc_crc = pvcm_crc32(&buf[4], plen);

	if (recv_crc != calc_crc) {
		LOG_ERR("CRC mismatch: %08x vs %08x", recv_crc, calc_crc);
		goto release;
	}

	memcpy(payload, &buf[4], plen);
	result = (int)plen;

release:
	rpmsg_release_rx_buffer(proto_ept, e->data);
	rx_tail = (rx_tail + 1) & (RX_RING_SIZE - 1);
	return result;
}

/* ---- Transport struct ---- */

static const struct pvcm_transport rpmsg_transport = {
	.init = rpmsg_init,
	.send_frame = rpmsg_send_frame,
	.recv_frame = rpmsg_recv_frame,
};

#endif /* CONFIG_OPENAMP */

/* Global accessor — selected by Kconfig */
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
