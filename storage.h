/*
 * Copyright (c) 2017-2021 Pantacor Ltd.
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
#ifndef PV_STORAGE_H
#define PV_STORAGE_H

int pv_storage_gc_run(struct pantavisor *pv);
off_t pv_storage_get_free(struct pantavisor *pv);
bool pv_storage_threshold_reached(struct pantavisor *pv);
void pv_storage_rm_rev(struct pantavisor *pv, int rev);
int pv_storage_validate_file_checksum(char* path, char* checksum);
void pv_storage_set_rev_done(struct pantavisor *pv, int rev);
int *pv_storage_get_revisions(struct pantavisor *pv);
void pv_storage_set_active(struct pantavisor *pv);
int pv_storage_make_config(struct pantavisor *pv);
void pv_storage_meta_set_objdir(struct pantavisor *pv);
int pv_storage_meta_expand_jsons(struct pantavisor *pv, struct pv_state *s);
int pv_storage_meta_link_boot(struct pantavisor *pv, struct pv_state *s);
void pv_storage_meta_set_tryonce(struct pantavisor *pv, int value);
struct pv_state* pv_storage_get_state(struct pantavisor *pv, int current);
char* pv_storage_get_initrd_config_name(int rev);

#endif // PV_STORAGE_H
