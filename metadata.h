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

#define PATH_USER_META "/pv/user-meta"

struct pv_metadata {
	struct dl_list usermeta; // pv_meta
	struct dl_list devmeta; // pv_meta
	bool devmeta_uploaded;
};

int pv_metadata_factory_meta(struct pantavisor *pv);
bool pv_metadata_factory_meta_done(struct pantavisor *pv);

void pv_metadata_add_usermeta(const char *key, const char *value);
void pv_metadata_rm_usermeta(const char *key);
int pv_metadata_parse_usermeta(char *buf);

void pv_metadata_parse_devmeta_pair(const char *buf);
int pv_metadata_init_devmeta(struct pantavisor *pv);
int pv_metadata_upload_devmeta(struct pantavisor *pv);

void pv_metadata_remove(void);

char* pv_metadata_get_user_meta_string(void);
char* pv_metadata_get_device_meta_string(void);

#endif
