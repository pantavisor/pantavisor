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
#ifndef PV_UBOOT_ENV_BUF_H
#define PV_UBOOT_ENV_BUF_H

#include <stddef.h>

/*
 * Edit U-Boot environments held in memory. A U-Boot env is a little endian
 * CRC32 of the data that follows it, then NUL separated key=value strings
 * ended by an empty string, zero padded up to CONFIG_ENV_SIZE. A raw env
 * (the legacy pv-env partition, uboot.txt) is the same list without the CRC.
 */

enum uboot_env_kind {
	UBOOT_ENV_NONE, // no CRC matches: erased, garbage or never saved
	UBOOT_ENV_STD,
	UBOOT_ENV_REDUNDANT, // CRC then a flags byte; not edited
};

/*
 * Look for a U-Boot env at the start of blk, trying the power-of-two sizes
 * from 4 KiB up to blk_size. Sets env_size when one is found.
 */
enum uboot_env_kind uboot_env_detect(const unsigned char *blk, size_t blk_size,
				     size_t *env_size);

/* Store the CRC of env[4..env_size) in env[0..4). */
void uboot_env_seal(unsigned char *env, size_t env_size);

/* Value of the exact key in the list data[0..size), or NULL. Free it. */
char *uboot_env_get(const unsigned char *data, size_t size, const char *key);

/*
 * Set the exact key to value, or remove it when value is NULL. Other pairs
 * keep their order. Returns -1 and leaves data alone when it does not fit.
 */
int uboot_env_edit(unsigned char *data, size_t size, const char *key,
		   const char *value);

#endif
