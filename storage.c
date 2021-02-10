/*
 * Copyright (c) 2017 Pantacor Ltd.
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

#include <linux/limits.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/statfs.h>

#define MODULE_NAME             "storage"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "objects.h"
#include "storage.h"
#include "updater.h"
#include "state.h"
#include "revision.h"

static int remove_at(char *path, char *filename)
{
	char full_path[PATH_MAX];

	sprintf(full_path, "%s/%s", path, filename);
	return remove(full_path);
}

static int remove_in(char *path, char *dirname)
{
	int n = 0;
	struct dirent **d;
	char full_path[PATH_MAX];

	sprintf(full_path, "%s/%s/", path, dirname);
	n = scandir(full_path, &d, NULL, alphasort);

	if (n < 0) {
		pv_log(ERROR, "attempted to remove %s", full_path);
		goto out;
	}

	while (n--) {
		// discard . and .. from scandir
		if (!strcmp(d[n]->d_name, ".") || !strcmp(d[n]->d_name, ".."))
			continue;
		// first try to remove it as a file
		if (!remove_at(full_path, d[n]->d_name))
			pv_log(DEBUG, "remove '%s'", d[n]->d_name)
		// remove it as a dir if not a file
		else
			remove_in(full_path, d[n]->d_name);
		free(d[n]);
	}
	free(d);

	if (!remove(full_path))
		pv_log(DEBUG, "remove '%s'", full_path)
	else
		pv_log(ERROR, "attempted to remove %s", full_path);

out:
	return n;
}

static int pv_storage_gc_objects(struct pantavisor *pv)
{
	int reclaimed = 0;
	struct stat st;
	struct pv_state *u;
	char path[PATH_MAX];
	char **obj, **obj_i;

	if (!pv->update)
		goto out;

	u = pv->update->pending;

	obj = pv_objects_get_all_ids(pv);
	for (obj_i = obj; *obj_i; obj_i++) {
		sprintf(path, "%s/objects/%s", pv->config->storage.mntpoint, *obj_i);
		memset(&st, 0, sizeof(struct stat));
		if (stat(path, &st) < 0)
			continue;

		if (st.st_nlink > 1)
			continue;

		if (pv_objects_id_in_step(u, *obj_i))
			continue;

		// remove,unlink object and sync fs
		reclaimed += st.st_size;
		remove(path);
		sync();
		pv_log(DEBUG, "removed unused '%s', reclaimed %lu bytes", path, st.st_size);
	}

	if (obj) {
		obj_i = obj;
		while (*obj_i) {
			free(*obj_i);
			obj_i++;
		}
		free(obj);
	}

out:
	return reclaimed;
}

void pv_storage_rm_rev(struct pantavisor *pv, int rev)
{
	char path[PATH_MAX];
	char revision[PATH_MAX];

	pv_log(DEBUG, "Removing rev=%d", rev);

	sprintf(revision, "%d", rev);

	sprintf(path, "%s/trails", pv->config->storage.mntpoint);
	remove_in(path, revision);

	sprintf(path, "%s/logs", pv->config->storage.mntpoint);
	remove_in(path, revision);

	sprintf(path, "%s/disks/rev", pv->config->storage.mntpoint);
	remove_in(path, revision);

	sync();
}

int pv_storage_gc_run(struct pantavisor *pv)
{
	int reclaimed = 0;
	int *rev, *rev_i;
	struct pv_state *s = 0, *u = 0;

	// FIXME: global GC disable check

	if (pv->state)
		s = pv->state;

	if (pv->update)
		u = pv->update->pending;

	rev = pv_get_revisions(pv);
	if (!rev) {
		pv_log(ERROR, "error parsings revs on disk for GC");
		return -1;
	}

	rev_i = rev;
	for (rev_i = rev; *rev_i != -1; rev_i++) {
		// dont reclaim current, update or last booted up revisions
		if ((s && (*rev_i == s->rev)) ||
			(u && (*rev_i == u->rev)) ||
			(*rev_i == pv_revision_get_rev()))
			continue;

		// if configured, keep factory too
		if (pv->config->storage.gc.keep_factory && *rev_i == 0)
			continue;

		// unlink the given revision from local storage
		pv_storage_rm_rev(pv, *rev_i);
	}

	// get rid of orphaned objects
	reclaimed = pv_storage_gc_objects(pv);

	pv_log(DEBUG, "total reclaimed: %d bytes", reclaimed);

	if (rev)
		free(rev);

	return reclaimed;
}

off_t pv_storage_get_free(struct pantavisor *pv)
{
	off_t fs_total, fs_free, fs_reserved, fs_real_free = 0;
	struct statfs buf;

	if (!pv || !pv->config)
		return 0;

	pv_log(INFO, "calculating free disk space...");

	if (statfs("/storage/config/pantahub.config", &buf) < 0)
		return -1;

	// free disk space
	fs_free = (off_t) buf.f_bsize * (off_t) buf.f_bfree;

	// total disk space
	fs_total = (off_t) buf.f_bsize * (off_t) buf.f_blocks;

	// reserved percentage of total disk space
	fs_reserved = (fs_total * pv->config->storage.gc.reserved) / 100;

	// real free space, not counting with reserved space
	if (fs_free > fs_reserved)
		fs_real_free = fs_free - fs_reserved;

	pv_log(INFO, "total disk space: %"PRIu64" B", fs_total);
	pv_log(INFO, "free disk space: %"PRIu64" B", fs_free);
	pv_log(INFO, "reserved disk space: %"PRIu64" B (%d%% of total)", fs_reserved, pv->config->storage.gc.reserved);
	pv_log(INFO, "real free disk space: %"PRIu64" B", fs_real_free);

	return fs_real_free;
}
