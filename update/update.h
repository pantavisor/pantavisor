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

// REMOTE UPDATE

void pv_update_start_install(const char *rev, const char *progress_hub,
			     const char *state,
			     void (*report_cb)(const char *, const char *));
void pv_update_get_unrecorded_objects(char ***objects);
void pv_update_set_object_metadata(const char *sha256sum, off_t size,
				   const char *geturl);
void pv_update_get_unavailable_objects(char ***objects);
char *pv_update_get_object_geturl(const char *sha256sum);
int pv_update_install_object(const char *path);

// LOCAL UPDATE

void pv_update_run(const char *rev);

// ALL UPDATES

int pv_update_resume(void (*report_cb)(const char *, const char *));

void pv_update_set_factory(void);
void pv_update_set_testing(void);
void pv_update_set_error_signature(const char *msg);
void pv_update_set_error_checksum(void);
void pv_update_set_error_platform(void);
void pv_update_set_error_goal(void);
void pv_update_set_error_hub_reach(void);
void pv_update_set_error_hub_unstable(void);
void pv_update_set_final(void);

void pv_update_finish(void);

bool pv_update_is_queued(void);
bool pv_update_is_downloading(void);
bool pv_update_is_inprogress(void);
bool pv_update_is_testing(void);
bool pv_update_is_done(void);
bool pv_update_is_failed(void);
bool pv_update_is_final(void);
bool pv_update_is_local(void);

char *pv_update_get_rev(void);
struct pv_state *pv_update_get_state(void);

#endif
