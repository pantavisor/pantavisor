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
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>

#include <linux/limits.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/statfs.h>

#include "updater.h"
#include "objects.h"
#include "storage.h"
#include "state.h"
#include "revision.h"
#include "init.h"

#define MODULE_NAME             "storage"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

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
	char full_path[512];

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
		sprintf(path, "%s/objects/%s", pv_config_get_storage_mntpoint(), *obj_i);
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

	sprintf(path, "%s/trails", pv_config_get_storage_mntpoint());
	remove_in(path, revision);

	sprintf(path, "%s/logs", pv_config_get_storage_mntpoint());
	remove_in(path, revision);

	sprintf(path, "%s/disks/rev", pv_config_get_storage_mntpoint());
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
		if (pv_config_get_storage_gc_keep_factory() && *rev_i == 0)
			continue;

		// unlink the given revision from local storage
		pv_storage_rm_rev(pv, *rev_i);
	}

	// get rid of orphaned objects
	reclaimed = pv_storage_gc_objects(pv);

	if (reclaimed)
		pv_log(DEBUG, "total reclaimed: %d bytes", reclaimed);

	if (rev)
		free(rev);

	return reclaimed;
}

struct pv_storage {
	off_t total;
	off_t free;
	int free_percentage;
	off_t reserved;
	int reserved_percentage;
	off_t real_free;
	int real_free_percentage;
	off_t threshold;
	int threshold_percentage;
};

static struct pv_storage* pv_storage_new(struct pantavisor *pv)
{
	struct statfs buf;
	struct pv_storage* this;

	if (!pv)
		return NULL;

	if (statfs("/storage/config/pantahub.config", &buf) < 0)
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
		if (this->total)
			this->threshold = (this->threshold * 100) / this->total;
		return this;
	}

	return NULL;
}

static void pv_storage_print(struct pv_storage* storage)
{
	pv_log(DEBUG, "total disk space: %"PRIu64" B", storage->total);
	pv_log(DEBUG, "free disk space: %"PRIu64" B (%d%% of total)", storage->free, storage->free_percentage);
	pv_log(DEBUG, "reserved disk space: %"PRIu64" B (%d%% of total)", storage->reserved, storage->reserved_percentage);
	pv_log(DEBUG, "real free disk space: %"PRIu64" B (%d%% of total)", storage->real_free, storage->real_free_percentage);
}

off_t pv_storage_get_free(struct pantavisor *pv)
{
	off_t real_free = 0;
	struct pv_storage* storage;

	storage = pv_storage_new(pv);
	if (storage) {
		pv_storage_print(storage);
		real_free = storage->real_free;
	}

	free(storage);

	return real_free;
}

bool pv_storage_threshold_reached(struct pantavisor *pv)
{
	bool threshold_reached = false;
	struct pv_storage* storage;

	storage = pv_storage_new(pv);
	if (storage &&
		(storage->real_free < storage->threshold)) {
		threshold_reached = true;
		pv_storage_print(storage);
		pv_log(INFO, "free disk space is %"PRIu64" B, which is under the %"PRIu64" threshold. Freeing up space", storage->real_free, storage->threshold);
	}

	free(storage);

	return threshold_reached;
}

static int pv_storage_init(struct pv_init *this)
{
	struct pantavisor *pv = get_pv_instance();
	char tmp[256];
	int fd = -1;

	// create hints
	fd = open("/pv/challenge", O_CREAT | O_SYNC | O_WRONLY, 0444);
	close(fd);
	fd = open("/pv/device-id", O_CREAT | O_SYNC | O_WRONLY, 0444);
	if (strcmp(pv_config_get_creds_prn(), "") == 0) {
		pv->flags |= DEVICE_UNCLAIMED;
	} else {
		sprintf(tmp, "%s\n", pv_config_get_creds_id());
		write(fd, tmp, strlen(tmp));
	}
	close(fd);
	fd = open("/pv/pantahub-host", O_CREAT | O_SYNC | O_WRONLY, 0444);
	sprintf(tmp, "https://%s:%d\n", pv_config_get_creds_host(), pv_config_get_creds_port());
	write(fd, tmp, strlen(tmp));
	close(fd);

	return 0;
}

struct pv_init pv_init_storage = {
	.init_fn = pv_storage_init,
	.flags = 0,
};
