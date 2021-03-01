/*
 * Copyright (c) 2018-2021 Pantacor Ltd.
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
#ifndef PV_METADATA_H
#define PV_METADATA_H

#include <stdbool.h>

#include "pantavisor.h"

struct pv_metadata {
    struct dl_list usermeta_list; // pv_usermeta
    struct dl_list devmeta_list; // pv_devmeta
};

int pv_metadata_factory_meta(struct pantavisor *pv);
bool pv_metadata_factory_meta_done(struct pantavisor *pv);

int pv_metadata_update_usermeta(struct pantavisor *pv, char *buf);

int pv_metadata_parse_devmeta(struct pantavisor *pv);
int pv_metadata_upload_devmeta(struct pantavisor *pv);

void pv_metadata_remove(struct pantavisor *pv);

#endif
