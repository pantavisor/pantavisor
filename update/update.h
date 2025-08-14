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
#ifndef PV_UPDATE_H
#define PV_UPDATE_H

#include "update/update_struct.h"

char *pv_update_start_install(const char *rev, const char *msg,
			      const char *progress_hub, const char *state);

char *pv_update_get_unrecorded_objects(char ***objects);
char *pv_update_set_object_metadata(const char *sha256sum, off_t size,
				    const char *geturl);

char *pv_update_get_unavailable_objects(char ***objects);
char *pv_update_get_object_geturl(const char *sha256sum);
char *pv_update_install_object(const char *path);

char *pv_update_finish_install(void);

bool pv_update_is_queued(void);
bool pv_update_is_downloading(void);
bool pv_update_is_inprogress(void);
bool pv_update_is_final(void);

char *pv_update_get_rev(void);
#endif
