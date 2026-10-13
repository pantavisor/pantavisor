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
#ifndef PV_UBOOT_MTD_ENV_H
#define PV_UBOOT_MTD_ENV_H

#include <stddef.h>

enum uboot_mtd_format {
	UBOOT_MTD_STD, // U-Boot saveenv: CRC32, then key=value strings
	UBOOT_MTD_RAW, // legacy pv-env partition: key=value strings only
};

/* Device node (/dev/mtdN) of the MTD partition called name; 0 when found. */
int pv_uboot_mtd_find(const char *name, char *dev, size_t size);

/*
 * Value of key in the environment held by the first good erase block of the
 * MTD device, or NULL when the key is unset or there is no usable
 * environment (erased, garbage, read error): that is not an error.
 */
char *pv_uboot_mtd_env_get(const char *dev, enum uboot_mtd_format fmt,
			   const char *key);

/*
 * Set key to value, or remove it when value is NULL, keeping every other
 * key. Returns 0 when done or already so, 1 when there is no usable
 * environment to edit (nothing is written), -1 when the write failed.
 */
int pv_uboot_mtd_env_set(const char *dev, enum uboot_mtd_format fmt,
			 const char *key, const char *value);

#endif
