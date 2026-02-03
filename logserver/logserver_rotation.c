/*
 * Copyright (c) 2026 Pantacor Ltd.
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

#include "logserver_rotation.h"
#include "config.h"
#include "paths.h"
#include "utils/pvzlib.h"
#include "utils/fs.h"
#include "utils/list.h"

#include <zlib.h>

#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

// maximum log files types in the same folder
#define PV_LOG_SERVER_ROT_MAX_FILES 10

struct logserver_rot_dirs {
	off_t size;
	char path[PATH_MAX];
	struct dl_list list;
};

static void pv_logserver_rot_get_comp_name(char *comp, const char *dir,
					   const char *name, int seq)
{
	memset(comp, 0, PATH_MAX);
	snprintf(comp, PATH_MAX, "%s/%s.log.%d.gz", dir, name, seq);
}

static long pv_logserver_rot_get_num(const char *fname)
{
	char fn[NAME_MAX] = { 0 };
	memccpy(fn, fname, 0, NAME_MAX);

	char *ext = strrchr(fn, '.');
	if (!ext || strcmp(ext, ".gz"))
		return -1;

	*ext = 0;

	char *rot_sep = strrchr(fn, '.');
	if (!rot_sep)
		return -1;

	errno = 0;
	long rot = strtol(rot_sep + 1, NULL, 10);
	if (errno != 0)
		return -1;

	return rot;
}

static long pv_logserver_rot_get_next_rot(const char *path)
{
	DIR *dir = opendir(path);
	if (!dir)
		return -1;

	long max_rot = 1;

	struct dirent *entry = NULL;
	while ((entry = readdir(dir))) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		long new = pv_logserver_rot_get_num(entry->d_name);

		if (new > max_rot)
			max_rot = new;
	}
	closedir(dir);

	return max_rot + 1;
}

void pv_logserver_rot_update(struct logserver_rot *rot)
{
	int hyst_gap_factor = pv_config_get_int(PV_LOG_HYSTERESIS_FACTOR);
	int rot_factor = pv_config_get_int(PV_LOG_ROTATE_FACTOR);
	int total_size = pv_config_get_int(PV_LOG_MAXSIZE);
	int hyst_gap = total_size / hyst_gap_factor;

	rot->total_size = total_size;
	rot->rot_size = hyst_gap / rot_factor;
	rot->high_wm = total_size * 0.95;
	rot->low_wm = total_size - hyst_gap;
	rot->cur_size = pv_fs_path_get_size(rot->path);
}

struct logserver_rot pv_logserver_rot_init(const char *rev)
{
	struct logserver_rot rot = { 0 };

	pv_paths_pv_log(rot.path, PATH_MAX, rev);
	pv_logserver_rot_update(&rot);

	return rot;
}

int pv_logserver_rot_log_rot(struct logserver_rot *rot, const char *fname)
{
	if (!fname || fname[0] == 0)
		return 0;

	off_t file_size = pv_fs_path_get_size(fname);
	if (file_size < 0)
		return -1;

	if (file_size < rot->rot_size)
		return 0;

	char parent[PATH_MAX] = { 0 };
	pv_fs_dirname(fname, parent);
	long next = pv_logserver_rot_get_next_rot(parent);

	char bname[NAME_MAX] = { 0 };
	pv_fs_basename(fname, bname);

	char comp[PATH_MAX] = { 0 };
	pv_logserver_rot_get_comp_name(comp, parent, bname, next);

	FILE *src = fopen(fname, "r");
	if (!src)
		return -1;

	int ret = -1;

	FILE *dst = fopen(comp, "w");
	if (!dst)
		goto out;

	ret = pv_zlib_compress(src, dst, 6);
	if (ret != Z_OK) {
		pv_zlib_report_error(ret, src, dst);
		goto out;
	}

	pv_fs_path_remove(fname, false);

	rot->cur_size += pv_fs_path_get_size(comp) - file_size;

	// create the new empty log file
	FILE *new_log = fopen(fname, "w+");
	if (new_log)
		fclose(new_log);

	ret = 0;
out:
	if (src) {
		fflush(src);
		fclose(src);
	}

	if (dst) {
		fflush(dst);
		fclose(dst);
	}

	if (ret == 0)
		pv_fs_path_sync(parent);

	return ret;
}

static off_t pv_logserver_rot_list_biggest_dir(const char *path,
					       struct dl_list *dirs)
{
	DIR *current_dir = opendir(path);
	if (!current_dir)
		return -1;

	off_t total_size = 0;
	struct dirent *entry = NULL;
	while ((entry = readdir(current_dir))) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		char abs_path[PATH_MAX] = { 0 };
		pv_fs_path_concat(abs_path, 2, path, entry->d_name);

		struct stat st = { 0 };
		bool is_dir = false;

		if (entry->d_type == DT_DIR) {
			is_dir = true;
		} else if (entry->d_type == DT_UNKNOWN) {
			if (stat(abs_path, &st) != 0)
				continue;

			if (S_ISDIR(st.st_mode))
				is_dir = true;
		}

		if (!is_dir) {
			if (st.st_ino == 0) {
				if (stat(abs_path, &st) != 0)
					continue;
			}

			total_size += st.st_size;
			continue;
		}

		struct logserver_rot_dirs *dsize =
			calloc(1, sizeof(struct logserver_rot_dirs));

		if (!dsize)
			continue;

		dsize->size =
			pv_logserver_rot_list_biggest_dir(abs_path, dirs) +
			total_size;

		memccpy(dsize->path, abs_path, 0, PATH_MAX);
		dl_list_init(&dsize->list);
		dl_list_add_tail(dirs, &dsize->list);
	}
	closedir(current_dir);
	return total_size;
}

static void pv_logserver_rot_get_oldest_file(const char *path, char *oldest)
{
	struct log_files {
		char logname[NAME_MAX];
		char path[PATH_MAX];
		long n_logs;
		long lower_seq;
	};

	struct log_files files[10] = { { { 0 } } };

	DIR *dir = opendir(path);
	if (!dir)
		return;

	struct dirent *entry = NULL;

	while ((entry = readdir(dir))) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;

		char *ext = strrchr(entry->d_name, '.');
		if (!ext || strcmp(ext, ".gz"))
			continue;

		char logname[NAME_MAX] = { 0 };
		char *end = strchr(entry->d_name, '.');
		memccpy(logname, entry->d_name, 0, end - entry->d_name);

		int i = 0;
		while (files[i].logname[0] != 0 &&
		       i < PV_LOG_SERVER_ROT_MAX_FILES) {
			if (strcmp(files[i].logname, logname)) {
				i++;
				continue;
			}

			long seq = pv_logserver_rot_get_num(entry->d_name);
			if (files[i].lower_seq > seq) {
				files[i].lower_seq = seq;
				pv_fs_path_concat(files[i].path, 2, path,
						  entry->d_name);
			}

			files[i].n_logs++;
			break;
		}

		if (i > PV_LOG_SERVER_ROT_MAX_FILES || files[i].logname[0] != 0)
			continue;

		memccpy(files[i].logname, logname, 0, NAME_MAX);
		pv_fs_path_concat(files[i].path, 2, path, entry->d_name);
		files[i].n_logs = 1;
		files[i].lower_seq = pv_logserver_rot_get_num(entry->d_name);
	}

	struct log_files *old = &files[0];

	for (int i = 1; i < PV_LOG_SERVER_ROT_MAX_FILES; i++) {
		if (old->n_logs < files[i].n_logs)
			old = &files[i];
	}

	memccpy(oldest, old->path, 0, PATH_MAX);
}

int pv_logserver_rot_deletion(struct logserver_rot *rot)
{
	if (rot->cur_size < rot->high_wm)
		return 0;

	struct dl_list dirs;
	dl_list_init(&dirs);

	pv_logserver_rot_list_biggest_dir(rot->path, &dirs);

	while (rot->low_wm > rot->cur_size) {
		off_t max = 0;
		struct logserver_rot_dirs *it, *tmp, *big = NULL;

		dl_list_for_each_safe(it, tmp, &dirs, struct logserver_rot_dirs,
				      list)
		{
			if (max < it->size) {
				max = it->size;
				big = it;
			}
		}

		char to_rm[PATH_MAX] = { 0 };
		pv_logserver_rot_get_oldest_file(big->path, to_rm);
		off_t to_rm_sz = pv_fs_path_get_size(to_rm);
		if (pv_fs_path_remove(to_rm, false) == 0)
			rot->cur_size -= to_rm_sz;
	}

	return 0;
}