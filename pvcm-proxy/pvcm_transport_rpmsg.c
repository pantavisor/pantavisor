/*
 * pvcm-proxy RPMsg transport
 *
 * RPMsg on Linux appears as /dev/ttyRPMSGN character devices.
 * The tty layer may concatenate multiple RPMsg messages in one
 * read(), so we maintain a residual buffer between calls.
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

/* CRC32 */
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

/* Residual buffer for handling concatenated RPMsg messages */
static uint8_t residual[4096];
static size_t residual_len = 0;

static int rpmsg_open(struct pvcm_transport *t, const char *device,
		      uint32_t baudrate)
{
	(void)baudrate;

	int fd = open(device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "[pvcm-proxy] cannot open %s: %m\n", device);
		return -1;
	}

	/* Set raw mode — PVCM is a binary protocol */
	struct termios tio;
	if (tcgetattr(fd, &tio) == 0) {
		cfmakeraw(&tio);
		tcsetattr(fd, TCSANOW, &tio);
	}

	t->fd = fd;
	residual_len = 0;
	fprintf(stdout, "[pvcm-proxy] RPMsg opened: %s\n", device);
	return 0;
}

static int rpmsg_send_frame(struct pvcm_transport *t, const void *payload,
			    size_t len)
{
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

	size_t total = 4 + len + 4;

	/* RPMsg vring has limited TX slots. If write fails (ENOMEM/EAGAIN),
	 * the MCU hasn't consumed the buffer yet. Retry with backoff. */
	for (int attempt = 0; attempt < 20; attempt++) {
		ssize_t n = write(t->fd, frame, total);
		if (n == (ssize_t)total)
			return 0;
		if (n >= 0) {
			/* partial write — shouldn't happen with RPMsg tty */
			fprintf(stderr, "[pvcm-proxy] rpmsg partial write: "
				"%zd/%zu\n", n, total);
			return -1;
		}
		if (errno != ENOMEM && errno != EAGAIN) {
			fprintf(stderr, "[pvcm-proxy] rpmsg write error: %m\n");
			return -1;
		}
		/* vring full — wait for MCU to consume, then retry */
		usleep(5000); /* 5ms */
	}

	fprintf(stderr, "[pvcm-proxy] rpmsg write failed after retries\n");
	return -1;
}

/*
 * Try to extract one PVCM frame from buf[0..buflen-1].
 * Returns payload length on success, -1 on parse error.
 * Sets *consumed to the total bytes consumed (header+payload+crc).
 */
static int parse_one_frame(const uint8_t *buf, size_t buflen,
			   void *payload, size_t max_len, size_t *consumed)
{
	if (buflen < 8)
		return -1;

	if (buf[0] != PVCM_SYNC_BYTE_0 || buf[1] != PVCM_SYNC_BYTE_1) {
		fprintf(stderr, "[pvcm-proxy] rpmsg sync mismatch "
			"(got 0x%02x 0x%02x, buflen=%zu)\n",
			buf[0], buf[1], buflen);
		return -1;
	}

	uint16_t len = buf[2] | (buf[3] << 8);
	size_t frame_size = 4 + len + 4;

	if (len > max_len || frame_size > buflen) {
		fprintf(stderr, "[pvcm-proxy] rpmsg frame length mismatch "
			"(len=%u, buflen=%zu)\n", len, buflen);
		return -1;
	}

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
	*consumed = frame_size;
	return (int)len;
}

static int rpmsg_recv_frame(struct pvcm_transport *t, void *payload,
			    size_t max_len, int timeout_ms)
{
	/* First check if we have a complete frame in the residual buffer */
	if (residual_len >= 8) {
		size_t consumed = 0;
		int ret = parse_one_frame(residual, residual_len, payload,
					  max_len, &consumed);
		if (ret >= 0) {
			/* Remove consumed bytes from residual */
			residual_len -= consumed;
			if (residual_len > 0)
				memmove(residual, residual + consumed,
					residual_len);
			return ret;
		}
		/* Parse failed — discard residual and read fresh */
		residual_len = 0;
	}

	/* Read more data from the tty */
	struct pollfd pfd = { .fd = t->fd, .events = POLLIN };
	int ret = poll(&pfd, 1, timeout_ms);
	if (ret <= 0)
		return ret == 0 ? -2 : -1;

	ssize_t n = read(t->fd, residual + residual_len,
			 sizeof(residual) - residual_len);
	if (n <= 0)
		return -1;

	residual_len += n;

	/* Try to parse one frame from the buffer */
	if (residual_len >= 8) {
		size_t consumed = 0;
		ret = parse_one_frame(residual, residual_len, payload,
				      max_len, &consumed);
		if (ret >= 0) {
			residual_len -= consumed;
			if (residual_len > 0)
				memmove(residual, residual + consumed,
					residual_len);
			return ret;
		}
	}

	/* Not enough data for a complete frame yet */
	return -1;
}

/*
 * Non-blocking try_recv — used by the event loop.
 * Does one non-blocking read, then tries to extract a frame.
 * Returns payload length on success, 0 if no complete frame, -1 on error.
 */
static int rpmsg_try_recv_frame(struct pvcm_transport *t, void *payload,
				size_t max_len)
{
	/* check residual buffer first */
	if (residual_len >= 8) {
		size_t consumed = 0;
		int ret = parse_one_frame(residual, residual_len, payload,
					  max_len, &consumed);
		if (ret >= 0) {
			residual_len -= consumed;
			if (residual_len > 0)
				memmove(residual, residual + consumed,
					residual_len);
			return ret;
		}
		/* parse error — discard and read fresh */
		residual_len = 0;
	}

	/* non-blocking read */
	ssize_t n = read(t->fd, residual + residual_len,
			 sizeof(residual) - residual_len);
	if (n > 0) {
		residual_len += n;
		if (residual_len >= 8) {
			size_t consumed = 0;
			int ret = parse_one_frame(residual, residual_len,
						  payload, max_len, &consumed);
			if (ret >= 0) {
				residual_len -= consumed;
				if (residual_len > 0)
					memmove(residual,
						residual + consumed,
						residual_len);
				return ret;
			}
		}
		return 0; /* not enough data yet */
	}

	if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
		return -1;

	return 0;
}

static void rpmsg_close(struct pvcm_transport *t)
{
	if (t->fd >= 0) {
		close(t->fd);
		t->fd = -1;
	}
	residual_len = 0;
}

struct pvcm_transport pvcm_transport_rpmsg = {
	.fd = -1,
	.name = "rpmsg",
	.open = rpmsg_open,
	.send_frame = rpmsg_send_frame,
	.recv_frame = rpmsg_recv_frame,
	.try_recv_frame = rpmsg_try_recv_frame,
	.close = rpmsg_close,
};
