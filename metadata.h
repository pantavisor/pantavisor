/*
 * Copyright (c) 2018-2023 Pantacor Ltd.
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
#include "utils/timer.h"

#define DEVMETA_KEY_INTERFACES "interfaces"
#define DEVMETA_KEY_PH_CLAIMED "pantahub.claimed"
#define DEVMETA_KEY_PH_ONLINE "pantahub.online"
#define DEVMETA_KEY_PV_CLAIMED "pantavisor.claimed"
#define DEVMETA_KEY_PH_STATE "pantahub.state"
#define DEVMETA_KEY_PV_ARCH "pantavisor.arch"
#define DEVMETA_KEY_PV_DTMODEL "pantavisor.dtmodel"
#define DEVMETA_KEY_PV_CPUMODEL "pantavisor.cpumodel"
#define DEVMETA_KEY_PV_MODE "pantavisor.mode"
#define DEVMETA_KEY_PV_REVISION "pantavisor.revision"
#define DEVMETA_KEY_PV_VERSION "pantavisor.version"
#define DEVMETA_KEY_PH_ADDRESS "pantahub.address"
#define DEVMETA_KEY_PV_UNAME "pantavisor.uname"
#define DEVMETA_KEY_PV_TIME "time"
#define DEVMETA_KEY_PV_SYSINFO "sysinfo"

typedef enum { USER_META, DEVICE_META } pv_metadata_t;

struct pv_metadata {
	struct dl_list usermeta; // pv_meta
	struct dl_list devmeta; // pv_meta
};

void pv_metadata_umount(void);

int pv_metadata_factory_meta(struct pantavisor *pv);
bool pv_metadata_factory_meta_done(struct pantavisor *pv);

int pv_metadata_add_usermeta(const char *key, const char *value);
int pv_metadata_rm_usermeta(const char *key);
char *pv_metadata_get_usermeta(char *key);
void pv_metadata_parse_usermeta(char *buf);

int pv_metadata_init_devmeta(struct pantavisor *pv);
int pv_metadata_add_devmeta(const char *key, const char *value);
int pv_metadata_rm_devmeta(const char *key);
void pv_metadata_parse_devmeta(const char *buf);

int pv_metadata_init(void);
void pv_metadata_remove(void);

char *pv_metadata_get_user_meta_string(void);
char *pv_metadata_get_device_meta_string(void);

#endif
