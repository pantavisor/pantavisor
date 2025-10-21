/*
 * Copyright (c) 2017-2025 Pantacor Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <netdb.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>

#include <linux/limits.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/statfs.h>

#include <jsmn/jsmnutil.h>

#include <mbedtls/sha256.h>

#include "objects.h"
#include "storage.h"
#include "state.h"
#include "bootloader.h"
#include "init.h"
#include "addons.h"
#include "state.h"
#include "jsons.h"
#include "tsh.h"
#include "signature.h"
#include "paths.h"
#include "metadata.h"
#include "pantavisor.h"
#include "parser/parser.h"
#include "update/update_struct.h"
#include "utils/json.h"
#include "utils/str.h"
#include "utils/fs.h"
#include "utils/timer.h"
#include "utils/math.h"

#define MODULE_NAME "storage"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

#define UPDATE_PROGRESS_JSON_SIZE 4096
#define SHA256SUM_HEXA_SIZE 64
#define SHA256SUM_BIN_SIZE 32

static struct timer threshold_timer;

static int pv_storage_gc_objects(struct pantavisor *pv)
{
	int reclaimed = 0;
	char path[PATH_MAX];
	struct stat st;
	struct pv_path *o, *tmp;
	struct dl_list objects;

	dl_list_init(&objects);

	pv_paths_storage_object(path, PATH_MAX, "");
	if (pv_storage_get_subdir(path, "", &objects))
		goto out;

	dl_list_for_each_safe(o, tmp, &objects, struct pv_path, list)
	{
		if (!strncmp(o->path, "..", strlen("..")) ||
		    !strncmp(o->path, ".", strlen(".")))
			continue;

		pv_paths_storage_object(path, PATH_MAX, o->path);
		memset(&st, 0, sizeof(struct stat));
		if (stat(path, &st) < 0)
			continue;

		if (st.st_nlink > 1)
			continue;

		// do not remove objects belonging to an ongoing update
		if (pv->update) {
			if (pv_objects_id_in_step(pv->update->state, o->path))
				continue;
		}

		reclaimed += st.st_size;
		pv_fs_path_remove(path, false);
		pv_log(DEBUG, "removed unused object '%s', reclaimed %jd bytes",
		       path, (intmax_t)st.st_size);
	}

out:
	pv_storage_free_subdir(&objects);
	return reclaimed;
}

void pv_storage_rm_rev(const char *rev)
{
	char path[PATH_MAX] = { 0 };

	pv_log(DEBUG, "removing revision %s from disk", rev);

	pv_paths_storage_trail(path, PATH_MAX, rev);
	pv_fs_path_remove(path, true);

	pv_paths_pv_log(path, PATH_MAX, rev);
	pv_fs_path_remove(path, true);

	pv_paths_storage_disks_rev(path, PATH_MAX, rev);
	pv_fs_path_remove(path, true);
}

int pv_storage_get_subdir(const char *path, const char *prefix,
			  struct dl_list *subdirs)
{
	int n, len, ret = 0;
	char basedir[PATH_MAX];
	struct dirent **dirs = NULL;
	struct pv_path *subdir;

	SNPRINTF_WTRUNC(basedir, sizeof(basedir), "%s%s", path, prefix);

	n = scandir(basedir, &dirs, NULL, alphasort);
	if (n < 0)
		goto out;

	while (n--) {
		char *tmp = dirs[n]->d_name;

		while (*tmp)
			tmp++;

		if (tmp[0] != '\0')
			continue;

		subdir = calloc(1, sizeof(struct pv_path));
		if (!subdir) {
			ret = -1;
			free(dirs[n]);
			goto out;
		}

		len = strlen(prefix) + strlen(dirs[n]->d_name) + 1;
		subdir->path = calloc(len, sizeof(char));
		SNPRINTF_WTRUNC(subdir->path, len, "%s%s", prefix,
				dirs[n]->d_name);
		free(dirs[n]);
		dl_list_init(&subdir->list);
		dl_list_add(subdirs, &subdir->list);
	}

out:
	if (dirs)
		free(dirs);

	return ret;
}

void pv_storage_free_subdir(struct dl_list *subdirs)
{
	struct pv_path *p, *tmp;

	dl_list_for_each_safe(p, tmp, subdirs, struct pv_path, list)
	{
		dl_list_del(&p->list);
		free(p->path);
		free(p);
	}
}

static int pv_storage_get_revisions(struct dl_list *revisions)
{
	char path[PATH_MAX];
	int ret = -1;

	pv_paths_storage_trail(path, PATH_MAX, "");

	if (pv_storage_get_subdir(path, "locals/", revisions) ||
	    pv_storage_get_subdir(path, "", revisions))
		goto out;

	ret = 0;

out:
	return ret;
}

struct pv_storage {
	off_t total;
	off_t free;
	int free_percentage;
	off_t reserved;
	int reserved_percentage;
	off_t real_free;
	int real_free_percentage;
	int threshold;
};

static struct pv_storage *pv_storage_new()
{
	char path[PATH_MAX];
	struct statfs buf;
	struct pv_storage *this;

	pv_paths_storage_file(path, PATH_MAX, PVMOUNTED_FNAME);
	if (statfs(path, &buf) < 0)
		return NULL;

	this = calloc(1, sizeof(struct pv_storage));
	if (this) {
		this->total = buf.f_bsize * buf.f_blocks;
		this->free = buf.f_bsize * buf.f_bfree;
		if (this->total)
			this->free_percentage =
				(this->free * 100) / this->total;
		this->reserved_percentage =
			pv_config_get_int(PV_STORAGE_GC_RESERVED);
		this->reserved =
			(this->total * this->reserved_percentage) / 100;
		if (this->free > this->reserved)
			this->real_free = this->free - this->reserved;
		if (this->total)
			this->real_free_percentage =
				(this->real_free * 100) / this->total;
		this->threshold = pv_config_get_int(PV_STORAGE_GC_THRESHOLD);
		return this;
	}

	return NULL;
}

static void pv_storage_print(struct pv_storage *storage)
{
	pv_log(DEBUG, "total disk space: %jd B", (intmax_t)storage->total);
	pv_log(DEBUG, "free disk space: %jd B (%d%% of total)",
	       (intmax_t)storage->free, storage->free_percentage);
	pv_log(DEBUG, "reserved disk space: %jd B (%d%% of total)",
	       (intmax_t)storage->reserved, storage->reserved_percentage);
	pv_log(INFO, "real free disk space: %jd B (%d%% of total)",
	       (intmax_t)storage->real_free, storage->real_free_percentage);
}

off_t pv_storage_get_free()
{
	off_t real_free = 0;
	struct pv_storage *storage;

	storage = pv_storage_new();
	if (storage) {
		real_free = storage->real_free;
		free(storage);
	}

	return real_free;
}

int pv_storage_gc_run()
{
	int reclaimed = 0, len;
	struct pv_state *s = 0, *u = 0;
	struct dl_list revisions; // pv_path
	struct pv_path *r, *tmp;
	struct pantavisor *pv = pv_get_instance();

	if (pv->state)
		s = pv->state;

	if (pv->update)
		u = pv->update->state;

	dl_list_init(&revisions);

	if (pv_storage_get_revisions(&revisions)) {
		pv_log(ERROR, "error parsings revs on disk for GC");
		return -1;
	}

	// check all revisions in list
	dl_list_for_each_safe(r, tmp, &revisions, struct pv_path, list)
	{
		len = strlen(r->path) + 1;
		// dont reclaim current, locals, update, last booted up revisions or factory if configured
		if (!strncmp(r->path, "..", len) ||
		    !strncmp(r->path, ".", len) ||
		    !strncmp(r->path, "current", len) ||
		    !strncmp(r->path, "locals", len) ||
		    !strncmp(r->path, "locals/..", len) ||
		    !strncmp(r->path, "locals/.", len) ||
		    (s && !strncmp(r->path, s->rev, len)) ||
		    (u && !strncmp(r->path, u->rev, len)) ||
		    !strncmp(r->path, pv_bootloader_get_done(), len) ||
		    (pv_config_get_bool(PV_STORAGE_GC_KEEP_FACTORY) &&
		     !strncmp(r->path, "0", len)))
			continue;

		// unlink the given revision from local storage
		pv_storage_rm_rev(r->path);
	}

	pv_storage_free_subdir(&revisions);

	// get rid of orphaned objects
	reclaimed = pv_storage_gc_objects(pv);

	if (reclaimed)
		pv_log(DEBUG, "total reclaimed: %d bytes", reclaimed);

	return reclaimed;
}

off_t pv_storage_gc_run_needed(off_t needed)
{
	off_t available = pv_storage_get_free();

	if (needed > available) {
		pv_log(WARN,
		       "%jd B needed but only %jd B available. Freeing up space...",
		       (intmax_t)needed, (intmax_t)available);
		pv_storage_gc_run();

		available = pv_storage_get_free();

		if (needed > available)
			pv_log(ERROR,
			       "still %jd B needed but only %jd B available",
			       (intmax_t)needed, (intmax_t)available);
	}

	return available;
}

void pv_storage_gc_defer_run_threshold()
{
	struct pantavisor *pv = pv_get_instance();

	int defertime = pv_config_get_int(PV_STORAGE_GC_THRESHOLD_DEFERTIME);
	timer_start(&threshold_timer, defertime, 0, RELATIV_TIMER);

	if (!pv->loading_objects) {
		pv->loading_objects = true;
		pv_log(INFO,
		       "disabled garbage collector threshold. Will be available again in %d seconds",
		       defertime);
	}
}

static char *pv_storage_get_json(struct pv_storage *storage)
{
	struct pv_json_ser js;

	pv_json_ser_init(&js, 512);

	pv_json_ser_object(&js);
	{
		pv_json_ser_key(&js, "total");
		pv_json_ser_number(&js, storage->total);
		pv_json_ser_key(&js, "free");
		pv_json_ser_number(&js, storage->free);
		pv_json_ser_key(&js, "reserved");
		pv_json_ser_number(&js, storage->reserved);
		pv_json_ser_key(&js, "real_free");
		pv_json_ser_number(&js, storage->real_free);

		pv_json_ser_object_pop(&js);
	}

	return pv_json_ser_str(&js);
}

void pv_storage_gc_run_threshold()
{
	char *json;
	struct pv_storage *storage;
	struct pantavisor *pv = pv_get_instance();
	struct timer_state tstate;

	storage = pv_storage_new();
	if (!storage)
		return;

	json = pv_storage_get_json(storage);
	pv_metadata_add_devmeta("storage", json);
	free(json);

	tstate = timer_current_state(&threshold_timer);
	if (pv->loading_objects && tstate.fin) {
		pv->loading_objects = false;
		pv_log(INFO, "garbage collector enabled again");
	}

	if (!pv_config_get_int(PV_STORAGE_GC_THRESHOLD) || pv->loading_objects)
		goto out;

	if (storage && (storage->real_free_percentage < storage->threshold)) {
		pv_log(INFO,
		       "free disk space is %d%%, which is under the %d%% threshold. Freeing up space",
		       storage->real_free_percentage, storage->threshold);
		pv_storage_gc_run();
	}

out:
	free(storage);
}

char *pv_storage_calculate_sha256sum(const char *path)
{
	int fd, bytes;
	off_t pos = 0, i = 0;
	unsigned char buf[4096];
	unsigned char sha_bin[SHA256SUM_BIN_SIZE];
	unsigned char *ret = NULL;
	mbedtls_sha256_context sha256_ctx;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	ret = calloc(SHA256SUM_HEXA_SIZE + 1, sizeof(char));
	if (!ret)
		goto out;

	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0);

	while ((bytes = read(fd, buf, 4096)) > 0)
		mbedtls_sha256_update(&sha256_ctx, buf, bytes);

	mbedtls_sha256_finish(&sha256_ctx, sha_bin);
	mbedtls_sha256_free(&sha256_ctx);

	while (i < SHA256SUM_BIN_SIZE) {
		pos += snprintf(ret + pos, 3, "%02x", sha_bin[i]);
		i++;
	}

out:
	close(fd);

	return ret;
}

int pv_storage_validate_file_checksum(char *path, char *checksum)
{
	int ret = -1;
	char *path_sha = NULL;

	path_sha = pv_storage_calculate_sha256sum(path);
	if (!path_sha) {
		pv_log(WARN, "could not calculate sha256sum of '%s': %s", path,
		       strerror(errno));
		goto out;
	}

	if (strlen(checksum) != SHA256SUM_HEXA_SIZE) {
		pv_log(WARN, "wrong given checksum len %d '%s'",
		       strlen(checksum), checksum);
		goto out;
	}

	if (strlen(path_sha) != SHA256SUM_HEXA_SIZE) {
		pv_log(WARN, "wrong loaded checksum len %d '%s'",
		       strlen(path_sha), path_sha);
		goto out;
	}

	if (strncmp(checksum, (char *)path_sha, SHA256SUM_HEXA_SIZE)) {
		pv_log(WARN, "sha256 mismatch in %s", path);
		goto out;
	}

	ret = 0;

out:
	if (path_sha)
		free(path_sha);

	return ret;
}

bool pv_storage_validate_trails_object_checksum(const char *rev,
						const char *name,
						char *checksum)
{
	char trail[PATH_MAX] = { 0 };
	char object[PATH_MAX] = { 0 };

	pv_paths_storage_trail_file(trail, PATH_MAX, rev, name);
	pv_paths_storage_object(object, PATH_MAX, checksum);

	if (!pv_fs_file_is_same(trail, object)) {
		pv_log(ERROR, "files '%s' and '%s' are not the same", trail,
		       object);
		return false;
	}

	pv_log(DEBUG, "validating checksum for %s and %s", object, trail);
	return !pv_storage_validate_file_checksum(trail, checksum);
}

bool pv_storage_validate_trails_json_value(const char *rev, const char *name,
					   char *val)
{
	char path[PATH_MAX];
	char *buf;

	pv_paths_storage_trail_file(path, PATH_MAX, rev, name);
	buf = pv_fs_file_load(path, 0);
	if (!buf) {
		pv_log(ERROR, "could not load %s, %s", path, strerror(errno));
		return false;
	}

	pv_log(DEBUG, "validating value for json %s", path);
	bool ret = pv_str_matches(val, strlen(val), buf, strlen(buf));
	free(buf);
	return ret;
}

void pv_storage_set_object_download_path(char *path, size_t size,
					 const char *id)
{
	memset(path, 0, size);

	if (pv_config_get_bool(PV_UPDATER_USE_TMP_OBJECTS) &&
	    (!strcmp(pv_config_get_str(PV_STORAGE_FSTYPE), "jffs2") ||
	     !strcmp(pv_config_get_str(PV_STORAGE_FSTYPE), "ubifs")))
		SNPRINTF_WTRUNC(path, size, "/tmp/%s", id);
	else
		pv_paths_storage_object_tmp(path, size, id);
}

bool pv_storage_is_object_installed(const char *id)
{
	char path[PATH_MAX];

	if (!id)
		return false;

	pv_paths_storage_object(path, PATH_MAX, id);
	return pv_fs_path_exist(path);
}

int pv_storage_install_object(const char *src_path, const char *id)
{
	char dst_path[PATH_MAX];

	pv_paths_storage_object(dst_path, PATH_MAX, id);
	if (pv_fs_path_rename(src_path, dst_path)) {
		pv_log(WARN, "could not rename '%s' to '%s': %s", src_path,
		       dst_path, strerror(errno));
		return -1;
	}

	return 0;
}

void pv_storage_set_active()
{
	char path[PATH_MAX];
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return;

	// path to current revision - relative and dir for fd
	pv_paths_storage_trail(path, PATH_MAX, "current");
	unlink(path);
	symlink(pv->state->rev, path);

	// path to current logs - relative and fd for dir
	pv_paths_pv_log(path, PATH_MAX, "current");
	unlink(path);
	symlink(pv->state->rev, path);
}

int pv_storage_update_factory(const char *rev)
{
	int res = -1, fd_c = -1, fd_f = -1;
	char dst_path[PATH_MAX], src_path[PATH_MAX];

	// first, remove revision 0 that is going to be substituted
	pv_storage_rm_rev("0");

	// now, create revision 0
	pv_paths_storage_trail_pvr_file(dst_path, PATH_MAX, "0", "");
	pv_fs_mkdir_p(dst_path, 0755);

	// finally, copy revision json to revision 0
	pv_paths_storage_trail_pvr_file(src_path, PATH_MAX, rev, JSON_FNAME);
	pv_paths_storage_trail_pvr_file(dst_path, PATH_MAX, "0", JSON_FNAME);
	pv_log(DEBUG, "copying %s to %s", src_path, dst_path);
	if (pv_fs_file_copy(src_path, dst_path, 0644) < 0) {
		pv_log(ERROR, "cannot copy %s into %s: %s", src_path, dst_path,
		       strerror(errno));
		goto out;
	}

	res = 0;
out:
	close(fd_c);
	close(fd_f);

	return res;
}

bool pv_storage_is_revision_local(const char *rev)
{
	bool ret = false;
	char *first = strchr(rev, '/');
	char *last = strrchr(rev, '/');

	size_t pre_len = strlen(PREFIX_LOCAL_REV);
	size_t len = strlen(rev);

	if ((len > pre_len) && (len - pre_len > SIZE_LOCAL_REV)) {
		pv_log(WARN, "revision name longer than %d", SIZE_LOCAL_REV);
		goto out;
	}

	if (strncmp(rev, PREFIX_LOCAL_REV, pre_len)) {
		pv_log(INFO, "revision name does not start with %s",
		       PREFIX_LOCAL_REV);
		goto out;
	}

	if (!first || (first != last)) {
		pv_log(WARN, "revision name contains more than one '/'");
		goto out;
	}

	ret = true;
out:
	return ret;
}

static char *pv_storage_get_file_date(const char *path)
{
	struct stat st;
	struct tm *nowtm;
	char *date = calloc(32, sizeof(char));

	stat(path, &st);

	nowtm = localtime(&st.st_mtim.tv_sec);
	strftime(date, 32, "%Y-%m-%dT%H:%M:%SZ", nowtm);

	return date;
}

char *pv_storage_get_revisions_string()
{
	int len = 1, line_len;
	char path[PATH_MAX];
	char *json = calloc(len, sizeof(char)), *progress = NULL, *date = NULL,
	     *commitmsg = NULL, *esc_commitmsg = NULL;
	struct dl_list revisions; // pv_path
	struct pv_path *r, *tmp;

	dl_list_init(&revisions);
	if (pv_storage_get_revisions(&revisions)) {
		pv_log(ERROR, "error parsings revs on disk for ctrl");
		goto out;
	}

	// open json
	json[0] = '[';

	if (dl_list_empty(&revisions)) {
		len++;
		goto out;
	}

	// fill up revision list in json
	dl_list_for_each_safe(r, tmp, &revisions, struct pv_path, list)
	{
		// dont list current or locals dir
		if (!strncmp(r->path, "..", strlen("..") + 1) ||
		    !strncmp(r->path, ".", strlen(".") + 1) ||
		    !strncmp(r->path, "current", strlen("current") + 1) ||
		    !strncmp(r->path, "locals", strlen("locals") + 1) ||
		    !strncmp(r->path, "locals/..", strlen("locals/..") + 1) ||
		    !strncmp(r->path, "locals/.", strlen("locals/.") + 1))
			continue;

		// get revision progress
		pv_paths_storage_trail_pv_file(path, PATH_MAX, r->path,
					       PROGRESS_FNAME);
		progress = pv_fs_file_load(path, 512);
		if (!progress || !strlen(progress)) {
			progress = calloc(3, sizeof(char));
			sprintf(progress, "{}");
		}

		// get revision date
		pv_paths_storage_trail(path, PATH_MAX, r->path);
		date = pv_storage_get_file_date(path);

		// get revision commit message
		pv_paths_storage_trail_pv_file(path, PATH_MAX, r->path,
					       COMMITMSG_FNAME);
		commitmsg = pv_fs_file_load(path, 512);
		if (commitmsg)
			esc_commitmsg =
				pv_json_format(commitmsg, strlen(commitmsg));

		if (!commitmsg || !esc_commitmsg) {
			esc_commitmsg = calloc(1, sizeof(char));
			esc_commitmsg[0] = '\0';
		}
		if (commitmsg) {
			free(commitmsg);
			commitmsg = NULL;
		}

		// add new revision line to json
		line_len = strlen(r->path) + strlen(esc_commitmsg) +
			   strlen(date) + strlen(progress) + 52;
		json = realloc(json, len + line_len + 1);
		SNPRINTF_WTRUNC(
			&json[len], line_len + 1,
			"{\"name\":\"%s\", \"date\":\"%s\", \"commitmsg\":\"%s\", \"progress\":%s},",
			r->path, date, esc_commitmsg, progress);
		len += line_len;

		if (progress) {
			free(progress);
			progress = NULL;
		}
		if (esc_commitmsg) {
			free(esc_commitmsg);
			esc_commitmsg = NULL;
		}
		if (date) {
			free(date);
			date = NULL;
		}
	}

out:
	len += 1;
	json = realloc(json, len);
	// close json
	json[len - 2] = ']';
	json[len - 1] = '\0';

	// free temporary revision list
	dl_list_for_each_safe(r, tmp, &revisions, struct pv_path, list)
	{
		free(r->path);
		dl_list_del(&r->list);
		free(r);
	}

	if (progress)
		free(progress);
	if (commitmsg)
		free(commitmsg);

	return json;
}

void pv_storage_set_rev_done(const char *rev)
{
	char path[PATH_MAX];

	pv_paths_storage_trail_pv_file(path, PATH_MAX, rev, DONE_FNAME);

	pv_log(DEBUG, "saving done file for rev %s in %s", rev, path);
	if (pv_fs_file_save(path, "", 0644) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));
}

bool pv_storage_is_rev_done(const char *rev)
{
	char path[PATH_MAX];

	pv_paths_storage_trail_pv_file(path, PATH_MAX, rev, DONE_FNAME);

	return pv_fs_path_exist(path);
}

void pv_storage_set_rev_progress(const char *rev, const char *progress)
{
	if (!rev)
		return;

	char path[PATH_MAX];

	pv_paths_storage_trail_pv_file(path, PATH_MAX, rev, "");
	pv_fs_mkdir_p(path, 644);

	pv_paths_storage_trail_pv_file(path, PATH_MAX, rev, PROGRESS_FNAME);
	pv_log(DEBUG, "saving progress at '%s'", path);
	if (pv_fs_file_save(path, progress, 0644) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));
}

char *pv_storage_get_rev_progress(const char *rev)
{
	if (!rev)
		return NULL;

	char path[PATH_MAX];
	pv_paths_storage_trail_pv_file(path, PATH_MAX, rev, PROGRESS_FNAME);

	pv_log(DEBUG, "loading progress file for rev %s from %s", rev, path);
	return pv_fs_file_load(path, UPDATE_PROGRESS_JSON_SIZE);
}

#define PVR_CONFIGF "{\"ObjectsDir\": \"%s/objects\"}"

void pv_storage_init_trail_pvr()
{
	struct pantavisor *pv = pv_get_instance();
	char path[PATH_MAX], config[PATH_MAX];
	struct stat st;

	if (!pv || !pv->state)
		return;

	// check .pvr/config exists
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, pv->state->rev,
					CONFIG_FNAME);
	if (!stat(path, &st))
		return;

	// save .pvr/config with that links trail contents and system paths
	SNPRINTF_WTRUNC(config, PATH_MAX, PVR_CONFIGF,
			pv_config_get_str(PV_STORAGE_MNTPOINT));
	if (pv_fs_file_save(path, config, 0644) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));
}

int pv_storage_link_trail_object(const char *id, const char *rev,
				 const char *name)
{
	char relpath[PATH_MAX], objpath[PATH_MAX];
	char *ext;

	pv_paths_storage_object(objpath, PATH_MAX, id);
	pv_paths_storage_trail_file(relpath, PATH_MAX, rev, name);

	pv_log(DEBUG, "linking '%s' to '%s'", objpath, relpath);

	pv_fs_mkbasedir_p(relpath, 0775);
	ext = strrchr(relpath, '.');
	if (ext && (strcmp(ext, ".bind") == 0)) {
		pv_log(INFO, "copying bind volume");
		if (pv_fs_file_copy(objpath, relpath, 0644) < 0) {
			pv_log(WARN, "could not copy objects: %s",
			       strerror(errno));
			return -1;
		}
	} else if (link(objpath, relpath) < 0) {
		if (errno != EEXIST) {
			pv_log(WARN, "unable to link: %s", strerror(errno));
			return -1;
		}
	}

	pv_fs_path_sync(relpath);

	return 0;
}

int pv_storage_meta_expand_jsons(struct pv_state *s)
{
	int ret = 0;
	struct stat st;
	char path[PATH_MAX];
	char *file = 0, *dir = 0;
	struct pantavisor *pv = pv_get_instance();

	if (!pv || !s)
		goto out;

	struct pv_json *j, *j_tmp;
	dl_list_for_each_safe(j, j_tmp, &s->jsons, struct pv_json, list)
	{
		pv_paths_storage_trail_file(path, PATH_MAX, s->rev, j->name);
		// we skip saving the file if it already exists
		if (stat(path, &st) == 0)
			continue;

		file = strdup(path);
		dir = dirname(file);
		if (stat(dir, &st))
			pv_fs_mkdir_p(dir, 0755);
		free(file);

		pv_log(DEBUG, "saving json %s", j->name);
		if (pv_fs_file_save(path, j->value, 0644) < 0)
			pv_log(ERROR, "could not save file %s: %s", path,
			       strerror(errno));
	}

	ret = 1;
out:
	return ret;
}

int pv_storage_meta_link_boot(struct pv_state *s)
{
	int i;
	char src[PATH_MAX], dst[PATH_MAX], fname[PATH_MAX], prefix[PATH_MAX];
	struct pv_addon *a, *tmp;
	struct dl_list *addons = NULL;
	struct pantavisor *pv = pv_get_instance();
	if (!pv)
		return -1;

	if (!s)
		s = pv->state;

	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		return 0;

	/*
	 * Toggle directory depth with null prefix
	 */
	switch (pv_state_spec(s)) {
	case SPEC_SYSTEM1:
		SNPRINTF_WTRUNC(prefix, sizeof(prefix), "bsp/");
		break;
	case SPEC_MULTI1:
	default:
		prefix[0] = '\0';
		break;
	}

	pv_paths_storage_trail_pv_file(dst, PATH_MAX, s->rev, "");
	pv_fs_mkdir_p(dst, 0755);

	// addons
	i = 0;
	addons = &s->addons;
	dl_list_for_each_safe(a, tmp, addons, struct pv_addon, list)
	{
		SNPRINTF_WTRUNC(fname, sizeof(fname), "pv-initrd.img.%d", i++);
		pv_paths_storage_trail_pv_file(dst, PATH_MAX, s->rev, fname);
		pv_paths_storage_trail_plat_file(src, PATH_MAX, s->rev, prefix,
						 a->name);

		pv_fs_path_remove(dst, false);
		if (link(src, dst) < 0)
			goto err;
	}

	if (s->bsp.img.std.initrd) {
		// initrd
		pv_paths_storage_trail_pv_file(dst, PATH_MAX, s->rev,
					       "pv-initrd.img");
		pv_paths_storage_trail_plat_file(src, PATH_MAX, s->rev, prefix,
						 s->bsp.img.std.initrd);

		pv_fs_path_remove(dst, false);
		if (link(src, dst) < 0)
			goto err;

		// kernel
		pv_paths_storage_trail_pv_file(dst, PATH_MAX, s->rev,
					       "pv-kernel.img");
		pv_paths_storage_trail_plat_file(src, PATH_MAX, s->rev, prefix,
						 s->bsp.img.std.kernel);

		pv_fs_path_remove(dst, false);
		if (link(src, dst) < 0)
			goto err;

		// fdt
		if (s->bsp.img.std.fdt) {
			pv_paths_storage_trail_pv_file(dst, PATH_MAX, s->rev,
						       "pv-fdt.dtb");
			pv_paths_storage_trail_plat_file(src, PATH_MAX, s->rev,
							 prefix,
							 s->bsp.img.std.fdt);

			pv_fs_path_remove(dst, false);
			if (link(src, dst) < 0)
				goto err;
		}
	} else if (s->bsp.img.ut.fit) {
		// pantavisor.fit
		pv_paths_storage_trail_pv_file(dst, PATH_MAX, s->rev,
					       "pantavisor.fit");
		pv_paths_storage_trail_plat_file(src, PATH_MAX, s->rev, prefix,
						 s->bsp.img.ut.fit);

		pv_fs_path_remove(dst, false);
		if (link(src, dst) < 0)
			goto err;
	} else if (s->bsp.img.rpiab.bootimg) {
		// rpiboot.img[.gz]
		if (!strcmp(s->bsp.img.rpiab.bootimg +
				    (strlen(s->bsp.img.rpiab.bootimg) - 3),
			    ".gz")) {
			pv_paths_storage_trail_pv_file(dst, PATH_MAX, s->rev,
						       "rpiboot.img.gz");
		} else {
			pv_paths_storage_trail_pv_file(dst, PATH_MAX, s->rev,
						       "rpiboot.img");
		}
		pv_paths_storage_trail_plat_file(src, PATH_MAX, s->rev, prefix,
						 s->bsp.img.rpiab.bootimg);
		pv_log(DEBUG, "installing hardlink of platform file %s to %s",
		       src, dst);

		pv_fs_path_remove(dst, false);
		if (link(src, dst) < 0)
			goto err;
	} else {
		pv_log(ERROR,
		       "bsp type not supported. no std,fit or rpiab boot assets found for rev=%s",
		       s->rev);
		return -1;
	}

	pv_log(DEBUG, "linked boot assets for rev=%s", s->rev);

	return 0;
err:
	pv_log(ERROR, "unable to link '%s' to '%s', errno %d", src, dst, errno);
	return -1;
}

int pv_storage_install_state_json(const char *state, const char *rev)
{
	char path[PATH_MAX];
	pv_paths_storage_trail_pv_file(path, PATH_MAX, rev, "");
	pv_fs_mkdir_p(path, 0755);
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, rev, "");
	pv_fs_mkdir_p(path, 0755);
	pv_paths_storage_trail_pvr_file(path, PATH_MAX, rev, JSON_FNAME);
	if (pv_fs_file_save(path, state, 0644) < 0) {
		pv_log(ERROR, "could not save %s: %s", path, strerror(errno));
		return -1;
	}

	return 0;
}

char *pv_storage_get_state_json(const char *rev)
{
	char path[PATH_MAX];

	pv_paths_storage_trail_pvr_file(path, PATH_MAX, rev, JSON_FNAME);
	pv_log(DEBUG, "reading state from: '%s'", path);

	return pv_fs_file_load(path, 0);
}

bool pv_storage_verify_state_json(const char *rev, char *msg,
				  unsigned int msg_len)
{
	bool ret = false;
	char *json = NULL;
	struct pv_state *state = NULL;

	json = pv_storage_get_state_json(rev);
	if (!json) {
		SNPRINTF_WTRUNC(msg, msg_len,
				"Storage: Cannot read state JSON");
		pv_log(ERROR, "Could not read state json");
		goto out;
	}

	sign_state_res_t sres;
	sres = pv_signature_verify(json);
	if (sres != SIGN_STATE_OK) {
		SNPRINTF_WTRUNC(msg, msg_len, "Secureboot: %s",
				pv_signature_sign_state_str(sres));
		pv_log(ERROR, "Could not verify state json signatures");
		goto out;
	}

	state = pv_parser_get_state(json, rev);
	if (!state) {
		SNPRINTF_WTRUNC(msg, msg_len,
				"Parser: State JSON has bad format");
		pv_log(ERROR, "Could not verify state json format");
		goto out;
	}

	ret = true;

out:
	if (json)
		free(json);
	if (state)
		pv_state_free(state);

	return ret;
}

void pv_storage_save_usermeta(const char *key, const char *value)
{
	char path[PATH_MAX];
	char *pname, *pkey;

	pv_log(DEBUG, "saving usermeta file with key '%s' and value '%s'", key,
	       value);

	pv_paths_pv_usrmeta_key(path, PATH_MAX, key);
	if (pv_fs_file_save(path, value, 0644) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	pname = strdup(key);
	pkey = strchr(pname, '.');
	if (pkey) {
		*pkey = '\0';
		pkey++;
		pv_paths_pv_usrmeta_plat_key(path, PATH_MAX, pname, "");
		if (!pv_fs_path_exist(path))
			pv_fs_mkdir_p(path, 0755);
		pv_paths_pv_usrmeta_plat_key(path, PATH_MAX, pname, pkey);
		if (pv_fs_file_save(path, value, 0644) < 0)
			pv_log(WARN, "could not save file %s: %s", path,
			       strerror(errno));
	}

	free(pname);
}

void pv_storage_rm_usermeta(const char *key)
{
	char path[PATH_MAX];
	char *pname, *pkey;

	pv_paths_pv_usrmeta_key(path, PATH_MAX, key);
	pv_fs_path_remove(path, false);
	pv_log(DEBUG, "removed usermeta in %s", path);

	pname = strdup(key);
	pkey = strchr(pname, '.');
	if (pkey) {
		*pkey = '\0';
		pkey++;
		pv_paths_pv_usrmeta_plat_key(path, PATH_MAX, pname, pkey);
		pv_fs_path_remove(path, false);
		pv_log(DEBUG, "removed usermeta in %s", path);
	}

	free(pname);
}

void pv_storage_save_devmeta(const char *key, const char *value)
{
	char path[PATH_MAX];
	char *pname, *pkey;

	pv_log(DEBUG, "saving devmeta file with key %s and value %s", key,
	       value);

	pv_paths_pv_devmeta_key(path, PATH_MAX, key);
	if (pv_fs_file_save(path, value, 0644) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	pname = strdup(key);
	pkey = strchr(pname, '.');
	if (pkey) {
		*pkey = '\0';
		pkey++;
		pv_paths_pv_devmeta_plat_key(path, PATH_MAX, pname, "");
		if (!pv_fs_path_exist(path))
			pv_fs_mkdir_p(path, 0755);
		pv_paths_pv_devmeta_plat_key(path, PATH_MAX, pname, pkey);
		if (pv_fs_file_save(path, value, 0644) < 0)
			pv_log(WARN, "could not save file %s: %s", path,
			       strerror(errno));
	}

	free(pname);
}

void pv_storage_rm_devmeta(const char *key)
{
	char path[PATH_MAX];
	char *pname, *pkey;

	pv_paths_pv_devmeta_key(path, PATH_MAX, key);
	pv_fs_path_remove(path, false);
	pv_log(DEBUG, "removed devmeta in %s", path);

	pname = strdup(key);
	pkey = strchr(pname, '.');
	if (pkey) {
		*pkey = '\0';
		pkey++;
		pv_paths_pv_devmeta_plat_key(path, PATH_MAX, pname, pkey);
		pv_fs_path_remove(path, false);
		pv_log(DEBUG, "removed devmeta in %s", path);
	}

	free(pname);
}

void pv_storage_umount()
{
	char path[PATH_MAX];

	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		return;

	pv_paths_storage(path, PATH_MAX);
	if (umount(path))
		pv_log(ERROR, "could not umount '%s': %s", path,
		       strerror(errno));
	pv_fs_path_sync(path);
}

static int pv_storage_init(struct pv_init *this)
{
	char path[PATH_MAX];

	// create hints
	pv_paths_pv_file(path, PATH_MAX, CHALLENGE_FNAME);
	if (pv_fs_file_save(path, "", 0444) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	pv_paths_pv_file(path, PATH_MAX, DEVICE_ID_FNAME);
	if (pv_fs_file_save(path, "", 0444) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	pv_paths_pv_file(path, PATH_MAX, PHHOST_FNAME);
	if (pv_fs_file_save(path, "", 0444) < 0)
		pv_log(WARN, "could not save file %s: %s", path,
		       strerror(errno));

	pv_paths_storage_file(path, PATH_MAX, PVMOUNTED_FNAME);
	if (pv_fs_file_save(path, "", 0444) < 0)
		pv_log(WARN, "could not save %s: %s", path, strerror(errno));

	return 0;
}

struct pv_init pv_init_storage = {
	.init_fn = pv_storage_init,
	.flags = 0,
};
