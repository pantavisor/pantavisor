/*
 * pvcm-proxy UART transport
 *
 * Opens a tty device, configures baudrate, and implements
 * PVCM frame send/recv with sync bytes and CRC32.
 *
 * Frame format:
 *   [ 0xAA | 0x55 | len 2B LE | payload | crc32 4B LE ]
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

/* CRC32 (ISO 3309 / ITU-T V.42) */
static uint32_t crc32_table[256];
static int crc32_table_init = 0;

static void crc32_init_table(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++) {
			if (c & 1)
				c = 0xEDB88320 ^ (c >> 1);
			else
				c >>= 1;
		}
		crc32_table[i] = c;
	}
	crc32_table_init = 1;
}

static uint32_t crc32_calc(const void *data, size_t len)
{
	if (!crc32_table_init)
		crc32_init_table();

	const uint8_t *p = data;
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; i++)
		crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}

static speed_t baudrate_to_speed(uint32_t baud)
{
	switch (baud) {
	case 9600:    return B9600;
	case 19200:   return B19200;
	case 38400:   return B38400;
	case 57600:   return B57600;
	case 115200:  return B115200;
	case 230400:  return B230400;
	case 460800:  return B460800;
	case 921600:  return B921600;
	default:      return B921600;
	}
}

static int uart_open(struct pvcm_transport *t, const char *device,
		     uint32_t baudrate)
{
	int fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "[pvcm-proxy] cannot open %s: %m\n", device);
		return -1;
	}

	struct termios tty;
	if (tcgetattr(fd, &tty) != 0) {
		fprintf(stderr, "[pvcm-proxy] tcgetattr failed: %m\n");
		close(fd);
		return -1;
	}

	speed_t speed = baudrate_to_speed(baudrate);
	cfsetospeed(&tty, speed);
	cfsetispeed(&tty, speed);

	/* raw mode, 8N1 */
	cfmakeraw(&tty);
	tty.c_cflag &= ~(CSTOPB | PARENB);
	tty.c_cflag |= CS8 | CLOCAL | CREAD;

	/* no flow control */
	tty.c_cflag &= ~CRTSCTS;
	tty.c_iflag &= ~(IXON | IXOFF | IXANY);

	/* read returns immediately with whatever is available */
	tty.c_cc[VMIN] = 0;
	tty.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSANOW, &tty) != 0) {
		fprintf(stderr, "[pvcm-proxy] tcsetattr failed: %m\n");
		close(fd);
		return -1;
	}

	/* clear O_NONBLOCK after setup */
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

	tcflush(fd, TCIOFLUSH);

	t->fd = fd;
	fprintf(stdout, "[pvcm-proxy] UART opened: %s @ %u baud\n",
		device, baudrate);
	return 0;
}

static int uart_send_frame(struct pvcm_transport *t, const void *payload,
			   size_t len)
{
	uint8_t header[4];
	header[0] = PVCM_SYNC_BYTE_0;
	header[1] = PVCM_SYNC_BYTE_1;
	header[2] = len & 0xFF;
	header[3] = (len >> 8) & 0xFF;

	uint32_t crc = crc32_calc(payload, len);
	uint8_t crc_bytes[4];
	crc_bytes[0] = crc & 0xFF;
	crc_bytes[1] = (crc >> 8) & 0xFF;
	crc_bytes[2] = (crc >> 16) & 0xFF;
	crc_bytes[3] = (crc >> 24) & 0xFF;

	/* write header + payload + crc atomically via writev or sequential */
	if (write(t->fd, header, 4) != 4)
		return -1;
	if (write(t->fd, payload, len) != (ssize_t)len)
		return -1;
	if (write(t->fd, crc_bytes, 4) != 4)
		return -1;

	return 0;
}

static int uart_recv_frame(struct pvcm_transport *t, void *payload,
			   size_t max_len, int timeout_ms)
{
	struct pollfd pfd = { .fd = t->fd, .events = POLLIN };
	uint8_t buf[2];

	/* wait for sync bytes */
	for (;;) {
		int ret = poll(&pfd, 1, timeout_ms);
		if (ret <= 0)
			return ret == 0 ? -2 : -1; /* -2 = timeout */

		if (read(t->fd, &buf[0], 1) != 1)
			return -1;

		if (buf[0] != PVCM_SYNC_BYTE_0)
			continue;

		ret = poll(&pfd, 1, 100);
		if (ret <= 0)
			continue;

		if (read(t->fd, &buf[1], 1) != 1)
			return -1;

		if (buf[1] == PVCM_SYNC_BYTE_1)
			break;
	}

	/* read length (2 bytes LE) */
	uint8_t len_buf[2];
	if (read(t->fd, len_buf, 2) != 2)
		return -1;
	uint16_t len = len_buf[0] | (len_buf[1] << 8);

	if (len > max_len)
		return -1;

	/* read payload */
	size_t total = 0;
	while (total < len) {
		int ret = poll(&pfd, 1, 1000);
		if (ret <= 0)
			return -1;
		ssize_t n = read(t->fd, (uint8_t *)payload + total,
				 len - total);
		if (n <= 0)
			return -1;
		total += n;
	}

	/* read CRC32 */
	uint8_t crc_buf[4];
	total = 0;
	while (total < 4) {
		int ret = poll(&pfd, 1, 1000);
		if (ret <= 0)
			return -1;
		ssize_t n = read(t->fd, crc_buf + total, 4 - total);
		if (n <= 0)
			return -1;
		total += n;
	}

	uint32_t recv_crc = crc_buf[0] | (crc_buf[1] << 8) |
			    (crc_buf[2] << 16) | (crc_buf[3] << 24);
	uint32_t calc_crc = crc32_calc(payload, len);

	if (recv_crc != calc_crc) {
		fprintf(stderr, "[pvcm-proxy] CRC mismatch: recv=%08x "
			"calc=%08x\n", recv_crc, calc_crc);
		return -1;
	}

	return (int)len;
}

static void uart_close(struct pvcm_transport *t)
{
	if (t->fd >= 0) {
		close(t->fd);
		t->fd = -1;
	}
}

struct pvcm_transport pvcm_transport_uart = {
	.fd = -1,
	.name = "uart",
	.open = uart_open,
	.send_frame = uart_send_frame,
	.recv_frame = uart_recv_frame,
	.close = uart_close,
};
