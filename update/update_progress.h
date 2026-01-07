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
#ifndef PV_UPDATE_PROGRESS_H
#define PV_UPDATE_PROGRESS_H

#include "update/update_struct.h"

void pv_update_progress_init(struct pv_update_progress *p, const char *rev,
			     void (*report_cb)(const char *, const char *));

int pv_update_progress_parse(const char *json, struct pv_update_progress *p);

void pv_update_progress_set(struct pv_update_progress *p,
			    pv_update_progress_status_t status,
			    pv_update_progress_msg_t code);
void pv_update_progress_set_str(struct pv_update_progress *p,
				pv_update_progress_status_t status,
				const char *fmt, ...);

void pv_update_progress_start_record(struct pv_update_progress *p);
void pv_update_progress_add_size(struct pv_update_progress *p, off_t size);
off_t pv_update_progress_get_size(struct pv_update_progress *p);

void pv_update_progress_start_download(struct pv_update_progress *p);
void pv_update_progress_add_downloaded(struct pv_update_progress *p,
				       off_t downloaded);

void pv_update_progress_reload_logs(struct pv_update_progress *p);

#endif
