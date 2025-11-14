/*
 * Copyright (c) 2017-2023 Pantacor Ltd.
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

#include "utils/list.h"
#include "state.h"

#include <stdbool.h>
#include <sys/types.h>

#define PREFIX_LOCAL_REV "locals/"
#define SIZE_LOCAL_REV 64

struct pv_state;

struct pv_path {
	char *path;
	struct dl_list list;
};

int pv_storage_install_state_json(const char *state, const char *rev);
char *pv_storage_get_state_json(const char *rev);
bool pv_storage_verify_state_json(const char *rev, char *msg,
				  unsigned int msg_len);

void pv_storage_set_rev_done(const char *rev);
bool pv_storage_is_rev_done(const char *rev);
void pv_storage_set_rev_progress(const char *rev, const char *progress);
char *pv_storage_get_rev_progress(const char *rev);
void pv_storage_init_trail_pvr(void);
void pv_storage_rm_rev(const char *rev);
void pv_storage_set_active();
int pv_storage_update_factory(const char *rev);
bool pv_storage_is_revision_local(const char *rev);
char *pv_storage_get_revisions_string(void);

int pv_storage_get_subdir(const char *path, const char *prefix,
			  struct dl_list *subdirs);
void pv_storage_free_subdir(struct dl_list *subdirs);

char *pv_storage_calculate_sha256sum(const char *path);
int pv_storage_validate_file_checksum(char *path, char *checksum);
bool pv_storage_validate_trails_object_checksum(const char *rev,
						const char *name,
						char *checksum);
bool pv_storage_validate_trails_json_value(const char *rev, const char *name,
					   char *val);

void pv_storage_set_object_download_path(char *path, size_t size,
					 const char *id);
bool pv_storage_is_object_installed(const char *id);
int pv_storage_install_object(const char *src_path, const char *dst_path);

off_t pv_storage_get_free(void);
int pv_storage_gc_run(void);
off_t pv_storage_gc_run_needed(off_t needed);
void pv_storage_gc_defer_run_threshold(void);
void pv_storage_gc_run_threshold(void);

int pv_storage_link_trail_object(const char *id, const char *rev,
				 const char *name);
int pv_storage_meta_expand_jsons(struct pv_state *s);
int pv_storage_meta_link_boot(struct pv_state *s);

void pv_storage_save_usermeta(const char *key, const char *value);
void pv_storage_rm_usermeta(const char *key);
void pv_storage_save_devmeta(const char *key, const char *value);
void pv_storage_rm_devmeta(const char *key);

void pv_storage_umount(void);

#endif // PV_STORAGE_H
