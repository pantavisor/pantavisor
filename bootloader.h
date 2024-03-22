/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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

#include <stdbool.h>

struct bl_ops {
	int (*init)(void);

	/* old primitive semantic */
	int (*set_env_key)(char *key, char *value);
	int (*unset_env_key)(char *key);
	char *(*get_env_key)(char *key);
	int (*flush_env)(void);

	/* new semantic */
	int (*install_update)(char *rev);
	int (*commit_update)();
	int (*fail_update)();
};

void pv_bootloader_print(void);

const char *pv_bootloader_get_rev(void);
const char *pv_bootloader_get_try(void);
const char *pv_bootloader_get_done(void);

bool pv_bootloader_update_in_progress(void);
bool pv_bootloader_trying_update(void);

int pv_bootloader_install_update(char *rev);
int pv_bootloader_pre_commit_update(char *rev);
int pv_bootloader_post_commit_update(void);
int pv_bootloader_fail_update(void);

void pv_bootloader_remove(void);

#endif
