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

struct pv_device {
    char *id;
    char *nick;
    char *owner;
    char *prn;
    struct dl_list usermeta_list; // pv_usermeta
    struct dl_list devmeta_list; // pv_devmeta
};

int pv_device_factory_meta(struct pantavisor *pv);
bool pv_device_factory_meta_done(struct pantavisor *pv);

int pv_device_update_usermeta(struct pantavisor *pv, char *buf);
bool pv_device_push_logs_activated(struct pantavisor *pv);

int pv_device_parse_devmeta(struct pantavisor *pv);
int pv_device_upload_devmeta(struct pantavisor *pv);

void pv_device_remove(struct pantavisor *pv);

#endif
