/*
 * pvcm-proxy RPMsg transport
 *
 * RPMsg on Linux appears as /dev/rpmsgX character devices.
 * Messages have built-in boundaries (no stream reassembly needed).
 * We still use the PVCM frame format (sync + len + payload + crc32)
 * for consistency with UART, but RPMsg preserves message boundaries.
 *
 * The device path is typically:
 *   /dev/rpmsg0          - first RPMsg endpoint
 *   /dev/ttyRPMSG0       - RPMsg TTY (alternative interface)
 *   /dev/rpmsg_ctrl0     - control device for creating endpoints
 *
 * SPDX-License-Identifier: MIT
 */

#include "pvcm_transport.h"
#include "../protocol/pvcm_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

/* CRC32 — same as UART transport */
static uint32_t crc32_table[256];
static bool crc32_init_done = false;

static void crc32_init(void)
{
	for (uint32_t i = 0; i < 256; i++) {
		uint32_t c = i;
		for (int j = 0; j < 8; j++)
			c = (c & 1) ? 0xEDB88320 ^ (c >> 1) : c >> 1;
		crc32_table[i] = c;
	}
	crc32_init_done = true;
}

static uint32_t crc32_calc(const void *data, size_t len)
{
	if (!crc32_init_done)
		crc32_init();
	const uint8_t *p = data;
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; i++)
		crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}

static int rpmsg_open(struct pvcm_transport *t, const char *device,
		      uint32_t baudrate)
{
	(void)baudrate; /* RPMsg has no baudrate */

	int fd = open(device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "[pvcm-proxy] cannot open %s: %m\n", device);
		return -1;
	}

	/* Set raw mode — PVCM is a binary protocol, tty line discipline
	 * must not interpret newlines, echo, or do flow control */
	struct termios tio;
	if (tcgetattr(fd, &tio) == 0) {
		cfmakeraw(&tio);
		tcsetattr(fd, TCSANOW, &tio);
	}

	t->fd = fd;
	fprintf(stdout, "[pvcm-proxy] RPMsg opened: %s\n", device);
	return 0;
}

static int rpmsg_send_frame(struct pvcm_transport *t, const void *payload,
			    size_t len)
{
	/* build complete frame in one buffer for atomic write */
	uint8_t frame[4 + len + 4];
	frame[0] = PVCM_SYNC_BYTE_0;
	frame[1] = PVCM_SYNC_BYTE_1;
	frame[2] = len & 0xFF;
	frame[3] = (len >> 8) & 0xFF;
	memcpy(&frame[4], payload, len);

	uint32_t crc = crc32_calc(payload, len);
	frame[4 + len + 0] = crc & 0xFF;
	frame[4 + len + 1] = (crc >> 8) & 0xFF;
	frame[4 + len + 2] = (crc >> 16) & 0xFF;
	frame[4 + len + 3] = (crc >> 24) & 0xFF;

	/* single write — RPMsg preserves message boundaries */
	ssize_t n = write(t->fd, frame, 4 + len + 4);
	if (n != (ssize_t)(4 + len + 4)) {
		fprintf(stderr, "[pvcm-proxy] rpmsg write failed: %m\n");
		return -1;
	}

	return 0;
}

static int rpmsg_recv_frame(struct pvcm_transport *t, void *payload,
			    size_t max_len, int timeout_ms)
{
	struct pollfd pfd = { .fd = t->fd, .events = POLLIN };

	int ret = poll(&pfd, 1, timeout_ms);
	if (ret <= 0)
		return ret == 0 ? -2 : -1;

	/* RPMsg delivers complete messages — read entire frame at once */
	uint8_t buf[4 + max_len + 4];
	ssize_t n = read(t->fd, buf, sizeof(buf));
	if (n < 8) { /* min: 4 header + 0 payload + 4 crc */
		if (n < 0)
			fprintf(stderr, "[pvcm-proxy] rpmsg read failed: %m\n");
		return -1;
	}

	/* verify sync bytes */
	if (buf[0] != PVCM_SYNC_BYTE_0 || buf[1] != PVCM_SYNC_BYTE_1) {
		fprintf(stderr, "[pvcm-proxy] rpmsg sync mismatch "
			"(got 0x%02x 0x%02x, n=%zd)\n",
			buf[0], buf[1], n);
		return -1;
	}

	uint16_t len = buf[2] | (buf[3] << 8);
	if (len > max_len || (size_t)(4 + len + 4) > (size_t)n) {
		fprintf(stderr, "[pvcm-proxy] rpmsg frame length mismatch "
			"(len=%u, read=%zd)\n", len, n);
		return -1;
	}

	/* verify CRC */
	uint32_t recv_crc = buf[4 + len] | (buf[4 + len + 1] << 8) |
			    (buf[4 + len + 2] << 16) |
			    (buf[4 + len + 3] << 24);
	uint32_t calc_crc = crc32_calc(&buf[4], len);
	if (recv_crc != calc_crc) {
		fprintf(stderr, "[pvcm-proxy] rpmsg CRC mismatch "
			"(recv=0x%08x calc=0x%08x len=%u op=0x%02x)\n",
			recv_crc, calc_crc, len, buf[4]);
		return -1;
	}

	memcpy(payload, &buf[4], len);
	return (int)len;
}

static void rpmsg_close(struct pvcm_transport *t)
{
	if (t->fd >= 0) {
		close(t->fd);
		t->fd = -1;
	}
}

struct pvcm_transport pvcm_transport_rpmsg = {
	.fd = -1,
	.name = "rpmsg",
	.open = rpmsg_open,
	.send_frame = rpmsg_send_frame,
	.recv_frame = rpmsg_recv_frame,
	.close = rpmsg_close,
};
