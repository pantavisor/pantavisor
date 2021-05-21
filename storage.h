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

struct pv_path {
	char* path;
	struct dl_list list;
};

struct pv_state* pv_storage_get_state(struct pantavisor *pv, const char *rev);
char* pv_storage_get_initrd_config_name(const char *rev);
void pv_storage_set_rev_done(struct pantavisor *pv, const char *rev);
void pv_storage_set_rev_progress(const char *rev, const char *progress);
void pv_storage_rm_rev(struct pantavisor *pv, const char *rev);
void pv_storage_set_active(struct pantavisor *pv);
int pv_storage_make_config(struct pantavisor *pv);
bool pv_storage_is_revision_local(const char* rev);
char* pv_storage_get_revisions_string(void);

int pv_storage_get_subdir(const char* path, const char* prefix, struct dl_list *subdirs);

int pv_storage_validate_file_checksum(char* path, char* checksum);

int pv_storage_gc_run(struct pantavisor *pv);
off_t pv_storage_get_free(struct pantavisor *pv);
bool pv_storage_threshold_reached(struct pantavisor *pv);

void pv_storage_meta_set_objdir(struct pantavisor *pv);
int pv_storage_meta_expand_jsons(struct pantavisor *pv, struct pv_state *s);
int pv_storage_meta_link_boot(struct pantavisor *pv, struct pv_state *s);
void pv_storage_meta_set_tryonce(struct pantavisor *pv, int value);

char *pv_storage_load_file(const char *path_base, const char *name, const unsigned int max_size);
void pv_storage_save_file(const char *path_base, const char *name, const char *content);
void pv_storage_rm_file(const char *path_base, const char *name);
unsigned int pv_storage_get_file_size(const char *path_base, const char *name);

#endif // PV_STORAGE_H
