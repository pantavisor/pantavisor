/*
 * Copyright (c) 2025 Pantacor Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "uboot_env_buf.h"

#define ENV_MIN_SIZE 4096
#define ENV_CRC_LEN 4
#define ENV_FLAGS_LEN 1

static uint32_t le32(const unsigned char *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int crc_matches(const unsigned char *blk, size_t skip, size_t size)
{
	return (uint32_t)crc32(0, blk + skip, size - skip) == le32(blk);
}

enum uboot_env_kind uboot_env_detect(const unsigned char *blk, size_t blk_size,
				     size_t *env_size)
{
	for (size_t size = ENV_MIN_SIZE; size <= blk_size; size <<= 1) {
		if (crc_matches(blk, ENV_CRC_LEN, size)) {
			*env_size = size;
			return UBOOT_ENV_STD;
		}
		// the byte after the CRC is the flags byte of a redundant env
		if (crc_matches(blk, ENV_CRC_LEN + ENV_FLAGS_LEN, size)) {
			*env_size = size;
			return UBOOT_ENV_REDUNDANT;
		}
	}

	return UBOOT_ENV_NONE;
}

void uboot_env_seal(unsigned char *env, size_t env_size)
{
	uint32_t crc = crc32(0, env + ENV_CRC_LEN, env_size - ENV_CRC_LEN);

	env[0] = crc & 0xff;
	env[1] = (crc >> 8) & 0xff;
	env[2] = (crc >> 16) & 0xff;
	env[3] = (crc >> 24) & 0xff;
}

// next pair at *pos, or NULL at the end of the list; *len excludes the NUL
static const char *next_pair(const unsigned char *data, size_t size,
			     size_t *pos, size_t *len)
{
	const unsigned char *s = data + *pos;
	const unsigned char *nul;

	// an empty string ends the list; erased flash reads as 0xFF
	if (*pos >= size || *s == '\0' || *s == 0xFF)
		return NULL;

	nul = memchr(s, '\0', size - *pos);
	if (!nul)
		return NULL;

	*len = nul - s;
	*pos += *len + 1;
	return (const char *)s;
}

static int key_matches(const char *pair, const char *key)
{
	size_t klen = strlen(key);

	return !strncmp(pair, key, klen) && pair[klen] == '=';
}

char *uboot_env_get(const unsigned char *data, size_t size, const char *key)
{
	size_t pos = 0, len;
	const char *pair;

	while ((pair = next_pair(data, size, &pos, &len)))
		if (key_matches(pair, key))
			return strdup(pair + strlen(key) + 1);

	return NULL;
}

int uboot_env_edit(unsigned char *data, size_t size, const char *key,
		   const char *value)
{
	size_t pos = 0, len, out = 0;
	int replaced = 0;
	const char *pair;
	unsigned char *tmp;

	// worst case: every old pair kept, one pair added, the final NUL
	tmp = calloc(size + strlen(key) + (value ? strlen(value) : 0) + 3, 1);
	if (!tmp)
		return -1;

	while ((pair = next_pair(data, size, &pos, &len))) {
		if (!key_matches(pair, key)) {
			memcpy(tmp + out, pair, len + 1);
			out += len + 1;
		} else if (value && !replaced) {
			out += sprintf((char *)tmp + out, "%s=%s", key, value) +
			       1;
			replaced = 1;
		}
	}

	if (value && !replaced)
		out += sprintf((char *)tmp + out, "%s=%s", key, value) + 1;

	// room for the empty string that ends the list
	if (out + 1 > size) {
		free(tmp);
		return -1;
	}

	memset(data, 0, size);
	memcpy(data, tmp, out);
	free(tmp);

	return 0;
}
