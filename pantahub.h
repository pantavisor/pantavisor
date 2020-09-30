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
#ifndef PV_PANTAHUB_H
#define PV_PANTAHUB_H

#define DEVICE_TOKEN_FMT	"Pantahub-Devices-Auto-Token-V1: %s"
#include "pantavisor.h"
int pv_ph_is_available(struct pantavisor *pv);
int pv_ph_upload_logs(struct pantavisor *pv, char *logs);
int pv_ph_device_get_meta(struct pantavisor *pv);
int pv_ph_device_exists(struct pantavisor *pv);
int pv_ph_register_self(struct pantavisor *pv);
const char** pv_ph_get_certs(struct pantavisor *pv);
int pv_ph_device_is_owned(struct pantavisor *pv, char **c);
void pv_ph_release_client(struct pantavisor *pv);
void pv_ph_update_hint_file(struct pantavisor *pv, char *c);
uint8_t pv_ph_upload_metadata(struct pantavisor *pv, char *metadata);
struct pv_connection* pv_get_pv_connection(struct pantavisor_config *config);
int connect_try(struct sockaddr *serv);

#endif
