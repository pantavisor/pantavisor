/*
 * Copyright (c) 2018 Pantacor Ltd.
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
#ifndef PV_DEVICE_H
#define PV_DEVICE_H

#include <stdbool.h>

#include "pantavisor.h"

#ifdef __arm__
#define PV_ARCH		"arm"
#elif __x86_64__
#define PV_ARCH		"x86_64"
#elif __mips__
#define	PV_ARCH		"mips"
#else
#define PV_ARCH		"unknown"
#endif

#if UINTPTR_MAX == 0xffffffff
#define	PV_BITS		"32"
#else
#define	PV_BITS		"64"
#endif

#define PREFIX_MODEL	"model name\t:"

struct pv_usermeta* pv_usermeta_get_by_key(struct pv_device *d, char *key);
struct pv_usermeta* pv_usermeta_add(struct pv_device *d, char *key, char *value);
struct pv_devinfo* pv_device_info_add(struct pv_device *dev, char *key, char *value);
int pv_usermeta_parse(struct pantavisor *pv, char *buf);
int pv_device_update_usermeta(struct pantavisor *pv, char *buf);
int pv_device_info_upload(struct pantavisor *pv);
int pv_device_init(struct pantavisor *pv);

#endif
