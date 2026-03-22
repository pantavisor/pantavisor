/*
 * PVCM UART Transport -- Zephyr side
 *
 * Uses Zephyr polling UART API for simplicity. The MCU side is
 * typically not performance-critical for the control channel.
 *
 * Frame format (same as Linux side):
 *   [ 0xAA | 0x55 | len 2B LE | payload | crc32 4B LE ]
 *
 * SPDX-License-Identifier: MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/logging/log.h>
#include <pantavisor/pvcm_transport.h>
#include <pantavisor/pvcm_protocol.h>

LOG_MODULE_REGISTER(pvcm_uart, CONFIG_LOG_DEFAULT_LEVEL);

#ifdef CONFIG_PANTAVISOR_TRANSPORT_UART

static const struct device *uart_dev;

static int uart_tx_byte(uint8_t b)
{
	uart_poll_out(uart_dev, b);
	return 0;
}

static int uart_tx_buf(const uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++)
		uart_poll_out(uart_dev, buf[i]);
	return 0;
}

static int uart_rx_byte(uint8_t *b, int timeout_ms)
{
	int64_t deadline = k_uptime_get() + timeout_ms;

	while (k_uptime_get() < deadline) {
		if (uart_poll_in(uart_dev, b) == 0)
			return 0;
		k_sleep(K_MSEC(1));
	}
	return -2; /* timeout */
}

static int uart_rx_buf(uint8_t *buf, size_t len, int timeout_ms)
{
	for (size_t i = 0; i < len; i++) {
		int ret = uart_rx_byte(&buf[i], timeout_ms);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int uart_init(void)
{
	/* try dedicated PVCM UART device first */
	uart_dev = device_get_binding(CONFIG_PANTAVISOR_UART_DEVICE);
	if (!uart_dev || !device_is_ready(uart_dev)) {
		/* fall back to DT uart0 */
		uart_dev = DEVICE_DT_GET_OR_NULL(DT_NODELABEL(uart0));
	}
	if (!uart_dev || !device_is_ready(uart_dev)) {
		/* last resort: console */
		uart_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));
	}
	if (!uart_dev || !device_is_ready(uart_dev)) {
		LOG_ERR("UART device not found");
		return -1;
	}

	LOG_INF("PVCM UART transport ready on %s", uart_dev->name);
	return 0;
}

static int uart_send_frame(const void *payload, size_t len)
{
	uint8_t header[4];
	header[0] = PVCM_SYNC_BYTE_0;
	header[1] = PVCM_SYNC_BYTE_1;
	header[2] = len & 0xFF;
	header[3] = (len >> 8) & 0xFF;

	uint32_t crc = pvcm_crc32(payload, len);
	uint8_t crc_bytes[4];
	crc_bytes[0] = crc & 0xFF;
	crc_bytes[1] = (crc >> 8) & 0xFF;
	crc_bytes[2] = (crc >> 16) & 0xFF;
	crc_bytes[3] = (crc >> 24) & 0xFF;

	uart_tx_buf(header, 4);
	uart_tx_buf(payload, len);
	uart_tx_buf(crc_bytes, 4);

	return 0;
}

static int uart_recv_frame(void *payload, size_t max_len, int timeout_ms)
{
	uint8_t b;

	/* wait for sync bytes */
	for (;;) {
		int ret = uart_rx_byte(&b, timeout_ms);
		if (ret != 0)
			return ret;

		if (b != PVCM_SYNC_BYTE_0)
			continue;

		ret = uart_rx_byte(&b, 100);
		if (ret != 0)
			continue;

		if (b == PVCM_SYNC_BYTE_1)
			break;
	}

	/* read length */
	uint8_t len_buf[2];
	if (uart_rx_buf(len_buf, 2, 1000) != 0)
		return -1;

	uint16_t len = len_buf[0] | (len_buf[1] << 8);
	if (len > max_len)
		return -1;

	/* read payload */
	if (uart_rx_buf(payload, len, 1000) != 0)
		return -1;

	/* read and verify CRC */
	uint8_t crc_buf[4];
	if (uart_rx_buf(crc_buf, 4, 1000) != 0)
		return -1;

	uint32_t recv_crc = crc_buf[0] | (crc_buf[1] << 8) |
			    (crc_buf[2] << 16) | (crc_buf[3] << 24);
	uint32_t calc_crc = pvcm_crc32(payload, len);

	if (recv_crc != calc_crc) {
		LOG_ERR("CRC mismatch: %08x vs %08x", recv_crc, calc_crc);
		return -1;
	}

	return (int)len;
}

static const struct pvcm_transport uart_transport = {
	.init = uart_init,
	.send_frame = uart_send_frame,
	.recv_frame = uart_recv_frame,
};

const struct pvcm_transport *pvcm_transport_get(void)
{
	return &uart_transport;
}

#endif /* CONFIG_PANTAVISOR_TRANSPORT_UART */
