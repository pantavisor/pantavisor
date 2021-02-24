/*
 * Copyright (c) 2017 Pantacor Ltd.
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
#ifndef PV_BOOTLOADER_H
#define PV_BOOTLOADER_H

#include "pantavisor.h"
#include <stdbool.h>


int pv_bl_set_try(int rev);
int pv_bl_unset_try(void);

int pv_bl_get_rev(void);
int pv_bl_set_rev(int rev);

int pv_bl_clear_update(void);

struct bl_ops {
	int (*init)(void);
	int (*get_env_key)(char *key);
	int (*set_env_key)(char *key, int value);
	int (*unset_env_key)(char *key);
	int (*flush_env)(void);
	int (*install_kernel)(char *path);
};

extern const struct bl_ops uboot_ops;
extern const struct bl_ops uboot_pvk_ops;
extern const struct bl_ops grub_ops;

#endif
