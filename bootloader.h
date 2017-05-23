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

int pv_bl_pvk_get_bank(struct pantavisor *pv);
int pv_bl_install_kernel(struct pantavisor *pv, char *obj);
int pv_bl_pvk_get_rev(struct pantavisor *pv, int bank);
int pv_bl_set_try(struct pantavisor *pv, int rev);
void pv_bl_set_current(struct pantavisor *pv, int rev);
int pv_bl_get_current(struct pantavisor *pv);
int pv_bl_get_update(struct pantavisor *pv, int *update);
int pv_bl_clear_update(struct pantavisor *pv);
int pv_bl_get_try(struct pantavisor *pv);

#endif