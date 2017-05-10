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
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "objects.h"
#include "storage.h"

static void remove_at(char *path, char *filename)
{
	char full_path[PATH_MAX];

	sprintf(full_path, "%s%s", path, filename);
	remove(full_path);
}

int sc_storage_gc_run(struct systemc *sc)
{
	int reclaimed = 0;
	int *rev, *rev_i;
	int n = 0;
	struct stat st;
	struct sc_state *s = 0, *u = 0;
	struct dirent **d;
	char path[PATH_MAX];
	char **obj, **obj_i;


	// FIXME: global GC disable check

	if (sc->state)
		s = sc->state;


	if (sc->update)
		u = sc->update->pending;


	// make sure our current is marked done
	if (!sc_rev_is_done(sc, s->rev))
		return -1;

	rev = sc_trail_get_revs(sc);

	if (!rev) {
		sc_log(ERROR, "error parsings revs on disk for GC");
		return -1;
	}

	rev_i = rev;
	for (rev_i = rev; *rev_i != -1; rev_i++) {
		// dont reclaim update or current
		if ((*rev_i == s->rev) || (u && (*rev_i == u->rev)))
			continue;

		// if configured, keep factory too
		if (sc->config->updater.keep_factory &&	*rev_i == 0)
			continue;

		// neither, remove
		sprintf(path, "%s/trails/%d.json", sc->config->storage.mntpoint, *rev_i);
		sc_log(DEBUG, "removing '%s'", path);
		remove(path);
		sprintf(path, "%s/trails/%d/", sc->config->storage.mntpoint, *rev_i);

		n = scandir(path, &d, NULL, alphasort);
		while (n--) {
			if (!strcmp(d[n]->d_name, ".") || !strcmp(d[n]->d_name, ".."))
				continue;
			sc_log(DEBUG, "unlink '%s'", d[n]->d_name);
			remove_at(path, d[n]->d_name);
		}
		sc_log(DEBUG, "removing '%s'", path);
		remove(path);
		sync();
	}

	obj = sc_objects_get_all_ids(sc);
	for (obj_i = obj; *obj_i; obj_i++) {
		sprintf(path, "%s/objects/%s", sc->config->storage.mntpoint, *obj_i);
		memset(&st, 0, sizeof(struct stat));
		if (stat(path, &st) < 0)
			continue;

		if (st.st_nlink > 1)
			continue;

		if (sc_objects_id_in_step(sc, u, *obj_i))
			continue;

		// remove,unlink obj_iect and sync fs
		reclaimed += st.st_size;
		remove(path);
		sync();
		sc_log(DEBUG, "removed unused '%s', reclaimed %lu bytes", path, st.st_size);
	}

	sc_log(DEBUG, "total reclaimed: %d bytes", reclaimed);

	if (rev)
		free(rev);

	if (obj) {
		obj_i = obj;
		while (*obj_i) {
			free(*obj_i);
			obj_i++;
		}
		free(obj);
	}

	return reclaimed;
}

int sc_storage_get_free(struct systemc *sc)
{
	int fs_free, fs_min;
	struct statfs buf;

	if (statfs("/storage/trails/0.json", &buf) < 0)
		return -1;

	fs_free = (int) buf.f_bsize * (int) buf.f_bfree;
	fs_min = (int) buf.f_bsize * (int) buf.f_blocks;

	// Always leave 5%
	fs_min -= (fs_min * 95) / 100;

	sc_log(DEBUG, "fs_free: %d, fs_min: %d", fs_free, fs_min); 

	if (fs_free < fs_min)
		return 0;

	return fs_free;
}
