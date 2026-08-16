/*
 * CRC32 -- shared by both UART and RPMsg transports
 * Same implementation as the Linux pvcm-run side.
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>
#include <pantavisor/pvcm_transport.h>

static uint32_t crc32_table[256];
static bool crc32_table_init = false;

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
	crc32_table_init = true;
}

uint32_t pvcm_crc32(const void *data, size_t len)
{
	if (!crc32_table_init)
		crc32_init_table();

	const uint8_t *p = data;
	uint32_t crc = 0xFFFFFFFF;
	for (size_t i = 0; i < len; i++)
		crc = crc32_table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}
