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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/statfs.h>

#include <mbedtls/sha256.h>

#include <jsmn/jsmnutil.h>

#include "updater.h"
#include "objects.h"
#include "storage.h"
#include "state.h"
#include "bootloader.h"
#include "init.h"
#include "file.h"
#include "addons.h"
#include "state.h"
#include "tsh.h"
#include "signature.h"
#include "paths.h"
#include "parser/parser.h"
#include "utils/json.h"
#include "utils/str.h"
#include "utils/fs.h"
#include "utils/timer.h"
#include "utils/math.h"

#define MODULE_NAME             "storage"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

static struct timer threshold_timer;

static int pv_storage_gc_objects(struct pantavisor *pv)
{
	int reclaimed = 0, len;
	char path[PATH_MAX];
	struct stat st;
	struct pv_path *o, *tmp;
	struct dl_list objects;

	dl_list_init(&objects);

	len = strlen("%s/objects/") + strlen(pv_config_get_storage_mntpoint()) + 1;
	SNPRINTF_WTRUNC(path, len, "%s/objects/", pv_config_get_storage_mntpoint());
	if (pv_storage_get_subdir(path, "", &objects))
		goto out;

	dl_list_for_each_safe(o, tmp, &objects, struct pv_path, list) {
		if (!strncmp(o->path, "..", len) ||
			!strncmp(o->path, ".", len))
			continue;

		len = strlen("%s/objects") + strlen(pv_config_get_storage_mntpoint()) + strlen(o->path) +1;
		SNPRINTF_WTRUNC(path, len, "%s/objects/%s", pv_config_get_storage_mntpoint(), o->path);
		memset(&st, 0, sizeof(struct stat));
		if (stat(path, &st) < 0)
			continue;

		if (st.st_nlink > 1)
			continue;

		// do not remove objects belonging to an ongoing update
		if (pv->update) {
			if (pv_objects_id_in_step(pv->update->pending, o->path))
				continue;
		}

		// remove,unlink object and sync fs
		reclaimed += st.st_size;
		remove(path);
		sync();
		pv_log(DEBUG, "removed unused object '%s', reclaimed %lu bytes", path, st.st_size);
	}

out:
	pv_storage_free_subdir(&objects);
	return reclaimed;
}

void pv_storage_rm_rev(const char *rev)
{
	char path[PATH_MAX];
	char revision[PATH_MAX];

	pv_log(DEBUG, "removing revision %s from disk", rev);

	SNPRINTF_WTRUNC(revision, sizeof (revision), "%s", rev);

	SNPRINTF_WTRUNC(path, sizeof (path), "%s/trails", pv_config_get_storage_mntpoint());
	remove_in(path, revision);

	SNPRINTF_WTRUNC(path, sizeof (path), "%s/logs", pv_config_get_storage_mntpoint());
	remove_in(path, revision);

	SNPRINTF_WTRUNC(path, sizeof (path), "%s/disks/rev", pv_config_get_storage_mntpoint());
	remove_in(path, revision);

	sync();
}

int pv_storage_get_subdir(const char* path, const char* prefix, struct dl_list *subdirs)
{
	int n, len, ret = 0;
	char basedir[PATH_MAX];
	struct dirent **dirs = NULL;
	struct pv_path *subdir;

	len = strlen(path) + strlen(prefix) + 1;
	SNPRINTF_WTRUNC(basedir, sizeof (basedir), "%s%s", path, prefix);

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
			goto out;
		}

		len = strlen(prefix) + strlen(dirs[n]->d_name) + 1;
		subdir->path = calloc(1, len );
		SNPRINTF_WTRUNC(subdir->path, len, "%s%s", prefix, dirs[n]->d_name);
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

	dl_list_for_each_safe(p, tmp, subdirs, struct pv_path, list) {
		dl_list_del(&p->list);
		free(p->path);
		free(p);
	}
}

static int pv_storage_get_revisions(struct dl_list *revisions)
{
	int ret = -1, len;
	char *basedir;

	len = strlen("%s/trails/") + strlen(pv_config_get_storage_mntpoint()) + 1;
	basedir = calloc(1, len);
	SNPRINTF_WTRUNC(basedir, len, "%s/trails/", pv_config_get_storage_mntpoint());

	if (pv_storage_get_subdir(basedir, "locals/", revisions) ||
		pv_storage_get_subdir(basedir, "", revisions))
		goto out;

	ret = 0;

out:
	if (basedir)
		free(basedir);

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

static struct pv_storage* pv_storage_new()
{
	struct statfs buf;
	struct pv_storage* this;

	if (statfs(pv_mount_get_path_storage("/config/pantahub.config"), &buf) < 0)
		return NULL;


	this = calloc(1, sizeof(struct pv_storage));
	if (this) {
		this->total = (off_t) buf.f_bsize * (off_t) buf.f_blocks;
		this->free = (off_t) buf.f_bsize * (off_t) buf.f_bfree;
		if (this->total)
			this->free_percentage = (this->free * 100) / this->total;
		this->reserved_percentage = pv_config_get_storage_gc_reserved();
		this->reserved = (this->total * this->reserved_percentage) / 100;
		if (this->free > this->reserved)
			this->real_free = this->free - this->reserved;
		if (this->total)
			this->real_free_percentage = (this->real_free * 100) / this->total;
		this->threshold = pv_config_get_storage_gc_threshold();
		return this;
	}

	return NULL;
}

static void pv_storage_print(struct pv_storage* storage)
{
	pv_log(DEBUG, "total disk space: %"PRIu64" B", storage->total);
	pv_log(DEBUG, "free disk space: %"PRIu64" B (%d%% of total)", storage->free, storage->free_percentage);
	pv_log(DEBUG, "reserved disk space: %"PRIu64" B (%d%% of total)", storage->reserved, storage->reserved_percentage);
	pv_log(INFO, "real free disk space: %"PRIu64" B (%d%% of total)", storage->real_free, storage->real_free_percentage);
}

static off_t pv_storage_get_free()
{
	off_t real_free = 0;
	struct pv_storage* storage;

	storage = pv_storage_new();
	if (storage) {
		pv_storage_print(storage);
		real_free = storage->real_free;
	}

	free(storage);

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
		u = pv->update->pending;

	dl_list_init(&revisions);

	if (pv_storage_get_revisions(&revisions)) {
		pv_log(ERROR, "error parsings revs on disk for GC");
		return -1;
	}

	// check all revisions in list
	dl_list_for_each_safe(r, tmp, &revisions, struct pv_path, list) {
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
			(pv_config_get_storage_gc_keep_factory() && !strncmp(r->path, "0", len)))
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
		pv_log(WARN, "not enough space for the %"PRIu64" B needed. Freeing up space...",
			available);
		pv_storage_gc_run();

		available = pv_storage_get_free();

		if (needed > available)
			pv_log(ERROR, "not enough space after running garbage collector");
	}

	return available;
}

void pv_storage_gc_defer_run_threshold()
{
	struct pantavisor *pv = pv_get_instance();

	timer_start(&threshold_timer, pv_config_get_storage_gc_threshold_defertime(), 0, RELATIV_TIMER);

	if (!pv->loading_objects) {
		pv->loading_objects = true;
		pv_log(INFO, "disabled garbage collector threshold. Will be available again in %d seconds",
			 pv_config_get_storage_gc_threshold_defertime());
	}
}

void pv_storage_gc_run_threshold()
{
	struct pv_storage* storage;
	struct pantavisor *pv = pv_get_instance();
	struct timer_state tstate;

	tstate = timer_current_state(&threshold_timer);
	if (pv->loading_objects && tstate.fin) {
		pv->loading_objects = false;
		pv_log(INFO, "garbage collector enabled again");
	}

	if (!pv_config_get_storage_gc_threshold() ||
		pv->loading_objects)
		return;

	storage = pv_storage_new();
	if (storage &&
		(storage->real_free_percentage < storage->threshold)) {
		pv_log(INFO, "free disk space is %d%%, which is under the %d%% threshold. Freeing up space", storage->real_free_percentage, storage->threshold);
		pv_storage_gc_run();
	}

	free(storage);
}

int pv_storage_validate_file_checksum(char* path, char* checksum)
{
	int fd, ret = -1, bytes;
	mbedtls_sha256_context sha256_ctx;
	unsigned char buf[4096];
	unsigned char cloud_sha[32];
	unsigned char local_sha[32];
	char *tmp_sha;
	char byte[3];

	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto out;

	mbedtls_sha256_init(&sha256_ctx);
	mbedtls_sha256_starts(&sha256_ctx, 0);

	while ((bytes = read(fd, buf, 4096)) > 0)
		mbedtls_sha256_update(&sha256_ctx, buf, bytes);

	mbedtls_sha256_finish(&sha256_ctx, local_sha);
	mbedtls_sha256_free(&sha256_ctx);

	// signed to unsigned
	tmp_sha = checksum;
	for (int i = 0, j = 0; j < 32; i=i+2, j++) {
		strncpy(byte, &tmp_sha[i], 2);
		byte[2] = 0;
		cloud_sha[j] = strtoul(byte, NULL, 16);
	}

	if(strncmp((char*)cloud_sha, (char*)local_sha, 32)) {
		pv_log(WARN, "sha256 mismatch in %s", path);
		goto out;
	}

	ret = 0;

out:
	close (fd);

	return ret;
}


static bool pv_storage_validate_objects_object_checksum(char *checksum)
{
	int len;
	char path[PATH_MAX];

	len = strlen("%s/objects/%s") +
		strlen(pv_config_get_storage_mntpoint()) +
		strlen(checksum);
	SNPRINTF_WTRUNC(path, len, "%s/objects/%s",
		 pv_config_get_storage_mntpoint(),
		 checksum);

	pv_log(DEBUG, "validating checksum for object %s", path);
	return !pv_storage_validate_file_checksum(path, checksum);
}


bool pv_storage_validate_trails_object_checksum(const char *rev, const char *name, char *checksum)
{
	int len;
	char path[PATH_MAX];


	len = strlen("%s/trails/%s/%s") +
		strlen(pv_config_get_storage_mntpoint()) +
		strlen(rev) +
		strlen(name);
	SNPRINTF_WTRUNC(path, len, "%s/trails/%s/%s",
		pv_config_get_storage_mntpoint(),
		rev,
		name);

	/* validate object in pool to match */
	if (!pv_storage_validate_objects_object_checksum(checksum)) {
		pv_log(ERROR, "object %s with checksum %s failed", name, checksum);
		return false;
	}

	pv_log(DEBUG, "validating checksum for object in trail %s", path);
	return !pv_storage_validate_file_checksum(path, checksum);
}

bool pv_storage_validate_trails_json_value(const char *rev, const char *name, char *val)
{
	int len;
	char path[PATH_MAX];
	char *buf;

	len = strlen("%s/trails/%s/%s") +
		strlen(pv_config_get_storage_mntpoint()) +
		strlen(rev) +
		strlen(name);
	SNPRINTF_WTRUNC(path, len, "%s/trails/%s/%s",
		pv_config_get_storage_mntpoint(),
		rev,
		name);

	buf = pv_file_load(path, 0);
	if (!buf) {
		pv_log(ERROR, "could not load %s, %s", path, strerror(errno));
		return false;
	}

	pv_log(DEBUG, "validating value for json %s", path);
	return pv_str_matches(val, strlen(val), buf, strlen(buf));

}

void pv_storage_set_active(struct pantavisor *pv)
{
	char path[PATH_MAX], cur[PATH_MAX], pdir[PATH_MAX];

	// path to current revision - relative and dir for fd
	SNPRINTF_WTRUNC(pdir, sizeof (pdir), "%s/trails/", pv_config_get_storage_mntpoint());
	SNPRINTF_WTRUNC(path, sizeof (path), "%s%s", pdir, pv->state->rev);
	SNPRINTF_WTRUNC(cur, sizeof (cur), "%s" "current", pdir);
	unlink(cur);
	symlink(path + strlen(pdir), cur);

	// path to current logs - relative and fd for dir
	SNPRINTF_WTRUNC(pdir, sizeof (pdir), "%s/logs/", pv_config_get_storage_mntpoint());
	SNPRINTF_WTRUNC(path, sizeof (path), "%s%s", pdir, pv->state->rev);
	SNPRINTF_WTRUNC(cur, sizeof (cur), "%scurrent", pdir);
	unlink(cur);
	symlink(path + strlen(pdir), cur);
}

int pv_storage_update_factory(const char* rev)
{
	int res = -1, fd_c = -1, fd_f = -1;
	char revision[PATH_MAX], factory[PATH_MAX], factory_parent[PATH_MAX];

	// init paths
	SNPRINTF_WTRUNC(factory_parent, sizeof (factory_parent), PATH_TRAILS_PVR_PARENT, pv_config_get_storage_mntpoint(), "0");
	SNPRINTF_WTRUNC(factory, sizeof (factory), PATH_TRAILS, pv_config_get_storage_mntpoint(), "0");
	SNPRINTF_WTRUNC(revision, sizeof (revision), PATH_TRAILS, pv_config_get_storage_mntpoint(), rev);

	// first, remove revision 0 that is going to be substituted
	pv_storage_rm_rev("0");

	// now, create revision 0
	mkdir_p(factory_parent, 0755);

	// finally, copy revision json to revision 0
	fd_f = open(factory, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd_f < 0) {
		pv_log(ERROR, "cannot open %s revision json: %s", factory, strerror(errno));
		goto out;
	}

	fd_c = open(revision, O_RDONLY, 0);
	if (fd_c < 0) {
		pv_log(ERROR, "cannot open %s revision json: %s", revision, strerror(errno));
		goto out;
	}

	if (pv_file_copy_and_close(fd_c, fd_f) < 0) {
		pv_log(ERROR, "cannot copy %s into %s: %s", revision, factory, strerror(errno));
		goto out;
	}

	res = 0;
out:
	close(fd_c);
	close(fd_f);

	return res;
}

int pv_storage_make_config(struct pantavisor *pv)
{
	struct stat st;
	char targetpath[PATH_MAX];
	char srcpath[PATH_MAX];
	char cmd[PATH_MAX];
	int rv;

	SNPRINTF_WTRUNC(srcpath, sizeof (srcpath), "%s/trails/%s/_config/", pv_config_get_storage_mntpoint(), pv->state->rev);
	SNPRINTF_WTRUNC(targetpath, sizeof (targetpath), "/configs/");

	if (!stat(targetpath, &st)) {
		SNPRINTF_WTRUNC(cmd, sizeof (cmd), "/bin/rm -rf %s/*", targetpath);
	}
	mkdir_p(targetpath, 0755);

	memset(&st, '\0', sizeof(st));

	// we allow overloading behaviour via plugin from initrd addon
	if (!stat("/usr/local/bin/pvext_sysconfig", &st) &&
			st.st_mode & S_IXUSR ) {
		SNPRINTF_WTRUNC(cmd, sizeof (cmd), "/usr/local/bin/pvext_sysconfig %s %s", srcpath, targetpath);
	} else {
		SNPRINTF_WTRUNC(cmd, sizeof (cmd), "/bin/cp -aL %s/* %s/", srcpath, targetpath);
	}
	pv_log(INFO, "processing trail _config: %s", cmd);

	/*
	 * [PKS]
	 * Should we do a tsh_run and wait
	 * for command to finish?
	 */
	rv = system(cmd);
	return rv;
}

bool pv_storage_is_revision_local(const char *rev)
{
	bool ret = false;
	char *first = strchr(rev, '/');
	char *last = strrchr(rev, '/');

	int pre_len = strlen(PREFIX_LOCAL_REV);
	if ((strlen(rev) - pre_len) > SIZE_LOCAL_REV) {
		pv_log(WARN, "revision name longer than %d", SIZE_LOCAL_REV);
		goto out;
	}

	if (strncmp(rev, PREFIX_LOCAL_REV, pre_len)) {
		pv_log(WARN, "revision name does not start with %s",
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

static char* pv_storage_get_file_date(const char *path)
{
	struct stat st;
	struct tm *nowtm;
	char *date = calloc(1, 32);

	stat(path, &st);

	nowtm = localtime(&st.st_mtim.tv_sec);
	strftime(date, 32, "%Y-%m-%dT%H:%M:%SZ", nowtm);

	return date;
}

char* pv_storage_get_revisions_string()
{
	int len = 1, line_len;
	char path[PATH_MAX];
	char *json = calloc(1, len), *progress = NULL, *date = NULL, *commitmsg = NULL, *esc_commitmsg = NULL;
	struct dl_list revisions; // pv_path
	struct pv_path *r, *tmp;

	dl_list_init(&revisions);
	if (pv_storage_get_revisions(&revisions)) {
		pv_log(ERROR, "error parsings revs on disk for ctrl");
		goto out;
	}

	// open json
	json[0]='[';

	if (dl_list_empty(&revisions)) {
		len++;
		goto out;
	}

	// fill up revision list in json
	dl_list_for_each_safe(r, tmp, &revisions, struct pv_path, list) {
		// dont list current or locals dir
		if (!strncmp(r->path, "..", strlen("..") + 1) ||
			!strncmp(r->path, ".", strlen(".") + 1) ||
			!strncmp(r->path, "current", strlen("current") + 1) ||
			!strncmp(r->path, "locals", strlen("locals") + 1) ||
			!strncmp(r->path, "locals/..", strlen("locals/..") + 1) ||
			!strncmp(r->path, "locals/.", strlen("locals/.") + 1))
			continue;

		// get revision progress
		line_len = strlen(PATH_TRAILS_PROGRESS) + strlen(pv_config_get_storage_mntpoint()) + strlen(r->path) + 1;
		SNPRINTF_WTRUNC(path, line_len, PATH_TRAILS_PROGRESS, pv_config_get_storage_mntpoint(), r->path);
		progress = pv_file_load(path, 512);
		if (!progress || !strlen(progress)) {
			progress = calloc(1, 3);
			sprintf (progress, "{}");
		}

		// get revision date
		line_len = strlen(PATH_TRAILS) + strlen(pv_config_get_storage_mntpoint()) + strlen(r->path) + 1;
		SNPRINTF_WTRUNC(path, line_len, PATH_TRAILS, pv_config_get_storage_mntpoint(), r->path);
		date = pv_storage_get_file_date(path);

		// get revision commit message
		line_len = strlen(PATH_TRAILS_COMMITMSG) + strlen(pv_config_get_storage_mntpoint()) + strlen(r->path) + 1;
		SNPRINTF_WTRUNC(path, line_len, PATH_TRAILS_COMMITMSG, pv_config_get_storage_mntpoint(), r->path);
		commitmsg = pv_file_load(path, 512);
		if (commitmsg)
			esc_commitmsg = pv_json_format(commitmsg, strlen(commitmsg));

		if (!commitmsg || !esc_commitmsg) {
			esc_commitmsg = calloc(1, 1);
			esc_commitmsg[0] = '\0';
		}
		if (commitmsg) {
			free (commitmsg);
			commitmsg = NULL;
		}

		// add new revision line to json
		line_len = strlen(r->path) + strlen(esc_commitmsg) + strlen(date) + strlen(progress) + 52;
		json = realloc(json, len + line_len + 1);
		SNPRINTF_WTRUNC(&json[len], line_len + 1, "{\"name\":\"%s\", \"date\":\"%s\", \"commitmsg\":\"%s\", \"progress\":%s},", r->path, date, esc_commitmsg, progress);
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
	json[len-2] = ']';
	json[len-1] = '\0';

	// free temporary revision list
	dl_list_for_each_safe(r, tmp, &revisions, struct pv_path, list) {
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

void pv_storage_set_rev_done(struct pantavisor *pv, const char *rev)
{
	// DEPRECATED: this done files are not used anymore for rollback and bootloader env
	// are used insted. We keep it here to serve old versions in case a device needs to
	// be downgraded

	int fd;
	char path[PATH_MAX];

	SNPRINTF_WTRUNC(path, sizeof (path), "%s/trails/%s/.pv/done", pv_config_get_storage_mntpoint(), rev);

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		pv_log(WARN, "unable to set current(done) flag for revision %s", rev);
		return;
	}

	// commit to disk
	fsync(fd);
	close(fd);
}

void pv_storage_set_rev_progress(const char *rev, const char *progress)
{
	int fd;
	char path[PATH_MAX];

	pv_log(DEBUG, "saving progress for rev %s: %s", rev, progress);

	SNPRINTF_WTRUNC(path, sizeof (path), "%s/trails/%s/.pv/progress", pv_config_get_storage_mntpoint(), rev);

	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC , 0644);
	if (fd < 0) {
		pv_log(DEBUG, "unable to open progress file %s for revision %s"
				" (err=%s)", path, rev, strerror(errno));
		return;
	}

	if (write(fd, progress, strlen(progress)) < 0) {
		pv_log(DEBUG, "unable to write progress  (%s) to file (%s) for revision %s (err=%s)", progress, path, rev, strerror(errno));
		return;
	}

	// commit to disk
	fsync(fd);
	close(fd);
}

void pv_storage_meta_set_objdir(struct pantavisor *pv)
{
	int fd = 0;
	char path[PATH_MAX];
	struct stat st;

	if (!pv)
		return;

	SNPRINTF_WTRUNC(path, sizeof (path),
		"%s/trails/%s/.pvr/config", pv_config_get_storage_mntpoint(), pv->state->rev);
	if (stat(path, &st) == 0)
		return;

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	/*
	 * [PKS]
	 * check for
	 * fd < 0
	 */
	if (fd < 0)
		goto err;

	SNPRINTF_WTRUNC(path, sizeof (path),
			"{\"ObjectsDir\": \"%s/objects\"}", pv_config_get_storage_mntpoint());
	/*
	 * [PKS]
	 * Use pv_file_write_nointr
	 */
	if (write(fd, path, strlen(path)) < 0)
		goto err;

	close(fd);
	pv_log(DEBUG, "wrote '%s' to .pvr/config @rev=%s", path, pv->state->rev);

	return;
err:
	pv_log(WARN, "unable to set ObjectsDir pvr config key");
	if (fd)
		close(fd);
}

int pv_storage_meta_expand_jsons(struct pantavisor *pv, struct pv_state *s)
{
	int fd = -1, n, bytes, tokc;
	int ret = 0;
	char *buf = 0, *key = 0, *ext = 0;
	char *value = 0, *file = 0, *dir = 0;
	char path[PATH_MAX];
	struct stat st;
	jsmntok_t *tokv = 0;
	jsmntok_t **k, **keys;

	if (!pv || !s)
		goto out;

	buf = strdup(s->json);
	ret = jsmnutil_parse_json(buf, &tokv, &tokc);
	if (ret < 0)
		goto out;

	keys = jsmnutil_get_object_keys(buf, tokv);
	k = keys;

	while (*k) {
		n = (*k)->end - (*k)->start + 1;

		// copy key
		key = malloc(n+1);
		key[n] = 0;
		snprintf(key, n, "%s", buf+(*k)->start);
		ext = strrchr(key, '.');
		if (!ext || strcmp(ext, ".json")) {
			free(key);
			k++;
			continue;
		}

		// copy value
		n = (*k+1)->end - (*k+1)->start + 1;
		value = malloc(n+1);
		value[n] = 0;
		snprintf(value, n, "%s", buf+(*k+1)->start);

		SNPRINTF_WTRUNC(path, sizeof (path), "%s/trails/%s/%s",
				pv_config_get_storage_mntpoint(), s->rev, key);


		if (stat(path, &st) == 0)
			goto out;

		file = strdup(path);
		dir = dirname(file);
		if (stat(dir, &st))
			mkdir_p(dir, 0755);
		free(file);

		fd = open(path, O_CREAT | O_SYNC | O_WRONLY, 0644);
		if (fd < 0)
			goto out;

		bytes = write(fd, value, strlen(value));
		if (bytes)
			pv_log(DEBUG, "%s: written %d bytes", path, bytes);

		close(fd);
		k++;
	}
	jsmnutil_tokv_free(keys);

	ret = 1;

out:
	if (buf)
		free(buf);
	if (tokv)
		free(tokv);
	if (fd > 0)
		close(fd);

	return ret;
}

void pv_storage_meta_set_tryonce(struct pantavisor *pv, int value)
{
	int fd;
	char path[PATH_MAX];

	SNPRINTF_WTRUNC(path, sizeof (path), "%s/trails/%s/.pv/.tryonce",
			pv_config_get_storage_mntpoint(), pv->state->rev);


	if (value) {
		fd = open(path, O_WRONLY | O_CREAT | O_SYNC, 0444);
		if (fd >= 0)
			close(fd);
	} else {
		remove(path);
		sync();
	}
}

int pv_storage_meta_link_boot(struct pantavisor *pv, struct pv_state *s)
{
	int i;
	char src[PATH_MAX], dst[PATH_MAX], fname[PATH_MAX], prefix[PATH_MAX];
	struct pv_addon *a, *tmp;
	struct dl_list *addons = NULL;

	if (!s)
		s = pv->state;

	/*
	 * Toggle directory depth with null prefix
	 */
	switch (pv_state_spec(s)) {
	case SPEC_SYSTEM1:
		SNPRINTF_WTRUNC(prefix, sizeof (prefix), "bsp/");
		break;
	case SPEC_MULTI1:
	default:
		prefix[0] = '\0';
		break;
	}

	// addons
	i = 0;
	addons = &s->addons;
	dl_list_for_each_safe(a, tmp, addons,
			struct pv_addon, list) {
		SNPRINTF_WTRUNC(dst, sizeof (dst),
				"%s/trails/%s/.pv/", pv_config_get_storage_mntpoint(), s->rev);
		SNPRINTF_WTRUNC(src, sizeof (src), "%s/trails/%s/%s%s",
				pv_config_get_storage_mntpoint(),
				s->rev, prefix, a->name);
		SNPRINTF_WTRUNC(fname, sizeof (fname), "pv-initrd.img.%d", i++);
		strcat(dst, fname);
		remove(dst);
		if (link(src, dst) < 0)
			goto err;
	}

	SNPRINTF_WTRUNC(dst, sizeof (dst),
			"%s/trails/%s/.pv/", pv_config_get_storage_mntpoint(), s->rev);
	mkdir_p(dst, 0755);
	if (s->bsp.img.std.initrd) {
		// initrd
		SNPRINTF_WTRUNC(src, sizeof (src),
			"%s/trails/%s/%s%s", pv_config_get_storage_mntpoint(), s->rev,
			prefix, s->bsp.img.std.initrd);
		strcat(dst, "pv-initrd.img");

		remove(dst);
		if (link(src, dst) < 0)
			goto err;

		// kernel
		SNPRINTF_WTRUNC(dst, sizeof (dst),
				"%s/trails/%s/.pv/pv-kernel.img",
				pv_config_get_storage_mntpoint(), s->rev);
		SNPRINTF_WTRUNC(src, sizeof (src),
				"%s/trails/%s/%s%s", pv_config_get_storage_mntpoint(),
				s->rev, prefix, s->bsp.img.std.kernel);

		remove(dst);
		if (link(src, dst) < 0)
			goto err;

		// fdt
		if (s->bsp.img.std.fdt) {
			SNPRINTF_WTRUNC(dst, sizeof (dst), "%s/trails/%s/.pv/pv-fdt.dtb", pv_config_get_storage_mntpoint(), s->rev);
			SNPRINTF_WTRUNC(src, sizeof (src), "%s/trails/%s/%s%s", pv_config_get_storage_mntpoint(), s->rev, prefix, s->bsp.img.std.fdt);

			remove(dst);
			if (link(src, dst) < 0)
				goto err;
		}
	} else {
		// pantavisor.fit
		SNPRINTF_WTRUNC(dst, sizeof (dst), "%s/trails/%s/.pv/pantavisor.fit",
				pv_config_get_storage_mntpoint(), s->rev);
		SNPRINTF_WTRUNC(src, sizeof (dst), "%s/trails/%s/%s%s",
				pv_config_get_storage_mntpoint(), s->rev, prefix,
				s->bsp.img.ut.fit);

		remove(dst);
		if (link(src, dst) < 0)
			goto err;
	}

	pv_log(DEBUG, "linked boot assets for rev=%s", s->rev);

	return 0;
err:
	pv_log(ERROR, "unable to link '%s' to '%s', errno %d", src, dst, errno);
	return -1;
}

char* pv_storage_get_rev_path(const char *rev)
{
	char *path;
	int len = ARRAY_LEN("%s/trails/%s") + strlen(pv_config_get_storage_mntpoint()) + strlen(rev) + 1;
	path = malloc(sizeof(char) * len);
	snprintf(path, len, "%s/trails/%s", pv_config_get_storage_mntpoint(), rev);
	return path;
}

char* pv_storage_get_state_json_path(const char *rev)
{
	char *path;
	int len = ARRAY_LEN("%s/trails/%s/.pvr/json") + strlen(pv_config_get_storage_mntpoint()) + strlen(rev) + 1;
	path = malloc(sizeof(char) * len);
	snprintf(path, len, "%s/trails/%s/.pvr/json", pv_config_get_storage_mntpoint(), rev);
	return path;
}

char* pv_storage_get_state_json(const char *rev)
{
	char *res;
	char *path;

	path = pv_storage_get_state_json_path(rev);
	pv_log(DEBUG, "reading state from: '%s'", path);

	res = pv_file_load(path, 0);

	free(path);
	return res;
}

bool pv_storage_verify_state_json(const char *rev)
{
	bool ret = false;
	char *json = NULL;
	struct pv_state *state = NULL;

	json = pv_storage_get_state_json(rev);
	if (!json) {
		pv_log(ERROR, "Could not read state json");
		goto out;
	}

	if (!pv_signature_verify(json)) {
		pv_log(ERROR, "Could not verify state json signatures");
		goto out;
	}

	state = pv_parser_get_state(json, rev);
	if (!state) {
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

void pv_storage_init_plat_usermeta(const char *name)
{
	char path[PATH_MAX];

	SNPRINTF_WTRUNC(path, sizeof (path), PV_USER_META_PLAT_PATHF, name);
	if (!dir_exist(path))
		mkdir_p(path, 0755);
}

static void pv_storage_save_file(const char *path, const char *content)
{
	int fd;

	if (!path || !content)
		return;

	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
		pv_log(WARN, "cannot create file: %s", strerror(errno));
		goto out;
	}

	write(fd, content, strlen(content));
	close(fd);

out:
	return;
}

void pv_storage_save_usermeta(const char *key, const char *value)
{
	char path[PATH_MAX];
	char *pname, *pkey;
	int len;

	len = strlen(PV_USER_META_KEY_PATHF) + strlen(key) + 1;
	SNPRINTF_WTRUNC(path, len, PV_USER_META_KEY_PATHF, key);
	pv_storage_save_file(path, value);
	pv_log(DEBUG, "saved usermeta in %s", path);

	pname = strdup(key);
	pkey = strchr(pname, '.');
	if (pkey) {
		*pkey = '\0';
		pkey++;
		pv_storage_init_plat_usermeta(pname);
		len = strlen(PV_USER_META_PLAT_KEY_PATHF) + strlen(pname) + strlen(pkey) + 1;
		SNPRINTF_WTRUNC(path, len, PV_USER_META_PLAT_KEY_PATHF, pname, pkey);
		pv_storage_save_file(path, value);
		pv_log(DEBUG, "saved usermeta in %s", path);
	}

	free(pname);
}

void pv_storage_rm_usermeta(const char *key)
{
	char path[PATH_MAX];
	char *pname, *pkey;
	int len;

	len = strlen(PV_USER_META_KEY_PATHF) + strlen(key) + 1;
	SNPRINTF_WTRUNC(path, len, PV_USER_META_KEY_PATHF, key);
	remove(path);
	pv_log(DEBUG, "removed usermeta in %s", path);

	pname = strdup(key);
	pkey = strchr(pname, '.');
	if (pkey) {
		*pkey = '\0';
		pkey++;
		len = strlen(PV_USER_META_PLAT_KEY_PATHF) + strlen(pname) + strlen(pkey) + 1;
		SNPRINTF_WTRUNC(path, len, PV_USER_META_PLAT_KEY_PATHF, pname, pkey);
		remove(path);
		pv_log(DEBUG, "removed usermeta in %s", path);
	}

	free(pname);
}

static int pv_storage_init(struct pv_init *this)
{
	struct pantavisor *pv = pv_get_instance();
	char tmp[256];
	int fd = -1;

	// create hints
	fd = open(pv_mount_get_path_rundir(PV_CHALLENGE_PATH), O_CREAT | O_SYNC | O_WRONLY, 0444);
	close(fd);
	fd = open(pv_mount_get_path_rundir(PV_DEVICE_ID_PATH), O_CREAT | O_SYNC | O_WRONLY, 0444);
	if (!pv_config_get_creds_prn() ||
		(!strcmp(pv_config_get_creds_prn(), ""))) {
		pv->unclaimed = true;
	} else {
		pv->unclaimed = false;
		SNPRINTF_WTRUNC(tmp, sizeof (tmp), "%s\n", pv_config_get_creds_id());
		write(fd, tmp, strlen(tmp));
	}
	close(fd);
	fd = open(pv_mount_get_path_rundir(PV_PATH"/pantahub-host"), O_CREAT | O_SYNC | O_WRONLY, 0444);
	SNPRINTF_WTRUNC(tmp, sizeof (tmp), "https://%s:%d\n", pv_config_get_creds_host(), pv_config_get_creds_port());
	write(fd, tmp, strlen(tmp));
	close(fd);

	return 0;
}

struct pv_init pv_init_storage = {
	.init_fn = pv_storage_init,
	.flags = 0,
};
