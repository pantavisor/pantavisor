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
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>

#include "uboot_env_buf.h"

#define BLOCK 131072
#define ENV_SIZE 16384

static unsigned char blk[BLOCK];

// an erase block holding a U-Boot env of env_size made of the given pairs
static void make_env(size_t env_size, int redundant, const char *const *pairs)
{
	unsigned char *data = blk + 4 + (redundant ? 1 : 0);
	size_t pos = 0;

	memset(blk, 0xFF, sizeof(blk));
	memset(blk, 0, env_size);
	if (redundant)
		blk[4] = 1;
	for (; *pairs; pairs++) {
		strcpy((char *)data + pos, *pairs);
		pos += strlen(*pairs) + 1;
	}
	if (redundant) {
		// a redundant env checksums everything after its flags byte
		uint32_t crc = crc32(0, blk + 5, env_size - 5);

		memcpy(blk, &crc, 4);
	} else {
		uboot_env_seal(blk, env_size);
	}
}

static void expect(const unsigned char *data, size_t size, const char *key,
		   const char *want)
{
	char *got = uboot_env_get(data, size, key);

	if (want) {
		assert(got && !strcmp(got, want));
	} else {
		assert(!got);
	}
	free(got);
}

static void test_valid_env_edit(void)
{
	const char *const pairs[] = { "bootcmd=run x",	 "pv_rev=3",
				      "pv_trying=4",	 "pv_try=4",
				      "baudrate=115200", NULL };
	size_t env_size = 0;
	unsigned char *data = blk + 4;

	make_env(ENV_SIZE, 0, pairs);
	assert(uboot_env_detect(blk, BLOCK, &env_size) == UBOOT_ENV_STD);
	assert(env_size == ENV_SIZE);

	assert(!uboot_env_edit(data, env_size - 4, "pv_trying", NULL));
	uboot_env_seal(blk, env_size);

	// the CRC is valid again and every other pair survived, in order
	assert(uboot_env_detect(blk, BLOCK, &env_size) == UBOOT_ENV_STD);
	expect(data, env_size - 4, "pv_trying", NULL);
	expect(data, env_size - 4, "pv_try", "4");
	expect(data, env_size - 4, "pv_rev", "3");
	expect(data, env_size - 4, "bootcmd", "run x");
	assert(!strcmp((char *)data, "bootcmd=run x"));
	assert(!strcmp((char *)data + 14, "pv_rev=3"));
	assert(!strcmp((char *)data + 23, "pv_try=4"));
	assert(!strcmp((char *)data + 32, "baudrate=115200"));
	// padded with zeros up to the end of the env
	assert(data[48] == 0 && data[env_size - 5] == 0);
}

static void test_set_replaces_and_appends(void)
{
	unsigned char data[64];

	memset(data, 0, sizeof(data));
	memcpy(data, "a=1\0pv_trying=4\0b=2\0", 20);

	assert(!uboot_env_edit(data, sizeof(data), "pv_trying", "5"));
	assert(!strcmp((char *)data + 4, "pv_trying=5"));
	assert(!uboot_env_edit(data, sizeof(data), "c", "3"));
	expect(data, sizeof(data), "c", "3");
	expect(data, sizeof(data), "b", "2");
}

static void test_exact_key_match(void)
{
	unsigned char data[64];

	memset(data, 0, sizeof(data));
	memcpy(data, "pv_trying=4\0pv_try=4\0", 21);

	expect(data, sizeof(data), "pv_try", "4");
	expect(data, sizeof(data), "pv_tr", NULL);
	expect(data, sizeof(data), "pv_trying", "4");

	// setting pv_try must not drop pv_trying
	assert(!uboot_env_edit(data, sizeof(data), "pv_try", "7"));
	expect(data, sizeof(data), "pv_trying", "4");
	expect(data, sizeof(data), "pv_try", "7");

	// nor must removing pv_trying drop pv_try
	assert(!uboot_env_edit(data, sizeof(data), "pv_trying", NULL));
	expect(data, sizeof(data), "pv_trying", NULL);
	expect(data, sizeof(data), "pv_try", "7");
}

static void test_edit_does_not_fit(void)
{
	unsigned char data[16];

	memcpy(data, "a=1\0\0\0\0\0\0\0\0\0\0\0\0\0", sizeof(data));
	assert(uboot_env_edit(data, sizeof(data), "long_key", "long_value") ==
	       -1);
	// untouched
	expect(data, sizeof(data), "a", "1");
}

static void test_erased(void)
{
	size_t env_size;

	memset(blk, 0xFF, sizeof(blk));
	assert(uboot_env_detect(blk, BLOCK, &env_size) == UBOOT_ENV_NONE);
	// an erased partition is an empty list
	expect(blk, BLOCK, "pv_trying", NULL);
}

static void test_all_zeros(void)
{
	size_t env_size;

	memset(blk, 0, sizeof(blk));
	assert(uboot_env_detect(blk, BLOCK, &env_size) == UBOOT_ENV_NONE);
	expect(blk, BLOCK, "pv_trying", NULL);
}

static void test_garbage(void)
{
	size_t env_size;

	srand(42);
	for (int round = 0; round < 50; round++) {
		for (size_t i = 0; i < sizeof(blk); i++)
			blk[i] = rand();
		assert(uboot_env_detect(blk, BLOCK, &env_size) ==
		       UBOOT_ENV_NONE);
		// reading must stay inside the buffer whatever it holds
		free(uboot_env_get(blk, BLOCK, "pv_trying"));
	}
}

static void test_crc_mismatch(void)
{
	const char *const pairs[] = { "pv_rev=3", "pv_trying=4", NULL };
	size_t env_size;

	make_env(ENV_SIZE, 0, pairs);
	blk[10] ^= 0x01;
	assert(uboot_env_detect(blk, BLOCK, &env_size) == UBOOT_ENV_NONE);

	make_env(ENV_SIZE, 0, pairs);
	blk[0] ^= 0x80;
	assert(uboot_env_detect(blk, BLOCK, &env_size) == UBOOT_ENV_NONE);
}

static void test_size_detection(void)
{
	const char *const pairs[] = { "pv_rev=3", NULL };
	size_t env_size;

	for (size_t size = 4096; size <= BLOCK; size <<= 1) {
		make_env(size, 0, pairs);
		assert(uboot_env_detect(blk, BLOCK, &env_size) ==
		       UBOOT_ENV_STD);
		assert(env_size == size);
	}
}

static void test_redundant_refused(void)
{
	const char *const pairs[] = { "pv_rev=3", "pv_trying=4", NULL };
	size_t env_size;

	make_env(ENV_SIZE, 1, pairs);
	assert(uboot_env_detect(blk, BLOCK, &env_size) == UBOOT_ENV_REDUNDANT);
	assert(env_size == ENV_SIZE);
}

static void test_raw_format(void)
{
	// legacy pv-env: no CRC, ended by an empty string, then 0xFF or zeros
	unsigned char raw[256];

	memset(raw, 0xFF, sizeof(raw));
	memcpy(raw, "pv_rev=3\0pv_try=4\0pv_trying=4\0\0", 31);

	expect(raw, sizeof(raw), "pv_rev", "3");
	expect(raw, sizeof(raw), "pv_trying", "4");

	// clearing pv_trying keeps pv_rev and pv_try
	assert(!uboot_env_edit(raw, sizeof(raw), "pv_trying", NULL));
	expect(raw, sizeof(raw), "pv_trying", NULL);
	expect(raw, sizeof(raw), "pv_rev", "3");
	expect(raw, sizeof(raw), "pv_try", "4");

	// an erased partition takes its first key
	memset(raw, 0xFF, sizeof(raw));
	assert(!uboot_env_edit(raw, sizeof(raw), "pv_try", "5"));
	expect(raw, sizeof(raw), "pv_try", "5");
}

int main(void)
{
	test_valid_env_edit();
	test_set_replaces_and_appends();
	test_exact_key_match();
	test_edit_does_not_fit();
	test_erased();
	test_all_zeros();
	test_garbage();
	test_crc_mismatch();
	test_size_detection();
	test_redundant_refused();
	test_raw_format();

	printf("uboot env tests passed\n");
	return 0;
}
