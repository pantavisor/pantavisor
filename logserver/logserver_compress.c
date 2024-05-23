/*
 * Copyright (c) 2024 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <glob.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/limits.h>

#include <zlib.h>

#include "logserver_compress.h"
#include "config.h"
#include "utils/fs.h"

struct cfiles {
	size_t beg;
	off_t *file_size;
	off_t total_size;
	glob_t glob;
};

static void free_compressed_file(struct cfiles *cf)
{
	if (!cf)
		return;

	globfree(&cf->glob);
	if (cf->file_size)
		free(cf->file_size);
	free(cf);
}

static int get_compressed_files_data(struct cfiles *cf, const char *path)
{
	char buf[PATH_MAX] = { 0 };
	pv_fs_path_concat(buf, 2, path, "*.gz");

	int r = glob(buf, 0, NULL, &cf->glob);
	if (r != 0 && r != GLOB_NOMATCH)
		return -1;

	cf->file_size = calloc(cf->glob.gl_pathc, sizeof(off_t));
	if (!cf->file_size)
		return -1;

	struct stat st = { 0 };
	cf->file_size = 0;
	for (size_t i = 0; i < cf->glob.gl_pathc; ++i) {
		if (stat(cf->glob.gl_pathv[i], &st) != 0)
			return -1;
		cf->total_size += st.st_size;
		cf->file_size[i] = st.st_size;

		memset(&st, 0, sizeof(struct stat));
	}

	return 0;
}

static struct cfiles *compressed_files_new(const char *path)
{
	struct cfiles *cf = calloc(1, sizeof(struct cfiles));

	if (!cf)
		return NULL;

	if (get_compressed_files_data(cf, path) != 0) {
		free_compressed_file(cf);
		return NULL;
	}

	cf->beg = 0;

	return cf;
}

static int get_compressed_tmp(const char *path)
{
	int memfd = memfd_create("tmpgz", O_RDWR);
	if (memfd < 0)
		return -1;

	int copy_fd = dup(memfd);
	if (copy_fd < 0) {
		close(memfd);
		return -1;
	}

	gzFile gzfd = gzdopen(copy_fd, "wb");
	if (gzfd == NULL) {
		close(memfd);
		close(copy_fd);
		return -1;
	}

	int infd = open(path, O_RDONLY);
	if (infd) {
		close(memfd);
		gzclose(gzfd);
		return -1;
	}

	char buf[4096] = { 0 };
	ssize_t read_bytes = 0;
	off_t size = 0;

	while (read_bytes = read(infd, buf, 4096), read_bytes > 0)
		size += (off_t)gzwrite(gzfd, buf, 4096);

	gzclose(gzfd);
	close(infd);

	return memfd;
}

static int delete_compressed(struct cfiles *cf)
{
	size_t idx = cf->beg;

	if (pv_fs_path_remove(cf->glob.gl_pathv[idx], false) != 0)
		return -1;

	cf->total_size -= cf->file_size[idx];
	cf->file_size[idx] = 0;
	cf->beg++;

	return 0;
}

static int check_and_freeup(struct cfiles *cf, off_t needed_space)
{
	int max_comp = pv_config_get_log_logmax_compressed();

	while ((max_comp - cf->total_size) < needed_space) {
		if (delete_compressed(cf) != 0)
			return -1;
	}

	return 0;
}

static char *get_next_file(const char *last_file)
{
	char num_str[PATH_MAX] = { 0 };

	char *beg = strchr(last_file, '.');
	if (!beg)
		return NULL;

	beg = strchr(beg + 1, '.');
	if (!beg)
		return NULL;

	char *end = strchr(beg + 1, '.');
	if (!end)
		return NULL;
	end--;

	strncpy(num_str, beg + 1, end - beg);
	size_t num = strtoumax(num_str, NULL, 10);

	char *tmpl = NULL;
	if (num < 10)
		tmpl = "pantavisor.log.0%d.gz";
	else
		tmpl = "pantavisor.log.%d.gz";

	char *new_file = NULL;
	asprintf(&new_file, tmpl, num);

	return new_file;
}

static int save_compressed_file(int src, struct cfiles *cf)
{
	char *fname = NULL;
	fname = get_next_file(cf->glob.gl_pathv[cf->glob.gl_pathc - 1]);

	int dst = open(fname, O_CREAT | O_WRONLY, 0644);
	if (dst < 0) {
		free(fname);
		return -1;
	}

	pv_fs_file_copy_fd(src, dst, true);
	free(fname);
	return 0;
}

int logserver_compress_log(const char *path)
{
	int fd = get_compressed_tmp(path);
	if (fd < 0)
		return -1;

	struct stat comp_log_st = { 0 };
	if (fstat(fd, &comp_log_st) != 0) {
		close(fd);
		return -1;
	}


	struct cfiles *cf = compressed_files_new(pv_fs_path_basename(path));

	int ret = check_and_freeup(cf, comp_log_st.st_size);
	if (ret == 0)
		ret = save_compressed_file(fd, cf);

	free_compressed_file(cf);
	close(fd);

	return ret;
}