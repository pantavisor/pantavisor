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

char *pv_update_progress_ser(pv_update_progress_t *p);
int pv_update_progress_parse(const char *json, pv_update_progress_t *p);

void pv_update_progress_set_status(pv_update_progress_t *p,
				   pv_update_progress_status_t status);
void pv_update_progress_set_msg_str(pv_update_progress_t *p, const char *fmt,
				    ...);
void pv_update_progress_set_msg_code(pv_update_progress_t *p,
				     pv_update_progress_msg_t code);
void pv_update_progress_set_progress(pv_update_progress_t *p, int progress);
void pv_update_progress_set_logs(pv_update_progress_t *p, const char *logs);

#endif
