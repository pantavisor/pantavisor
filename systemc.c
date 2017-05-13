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
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <netdb.h>

#include <linux/limits.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>

#define MODULE_NAME             "core"
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "loop.h"
#include "controller.h"
#include "bootloader.h"

#include "systemc.h"

pid_t sc_pid;

void sc_destroy(struct systemc *sc)
{
        sc_release_state(sc);
        free(sc->config);
        free(sc);
}

void sc_set_current(struct systemc *sc, int rev)
{
	int fd;
	char path[256];

	sprintf(path, "%s/trails/%d/.done", sc->config->storage.mntpoint, rev);

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (!fd) {
		sc_log(WARN, "unable to set current(done) flag for revision %d", rev);
		return;
	}

	// commit to disk
	fsync(fd);
	close(fd);

	// commit to bootloader
	sc_bl_set_current(sc, rev);
}

#define REV_BUF_SIZE	5
int *sc_trail_get_revs(struct systemc *sc)
{
	int n, i = 0;
	int bufsize = 1;
	int *revs = calloc(1, bufsize * sizeof (int));
	struct dirent **dirs;
	char basedir[PATH_MAX];

	sprintf(basedir, "%s/trails/", sc->config->storage.mntpoint);
	n = scandir(basedir, &dirs, NULL, alphasort);
	while (n--) {
		char *tmp = dirs[n]->d_name;

		while (*tmp && isdigit(*tmp))
			tmp++;

		if (tmp[0] != '\0')
			continue;

		if (i >= bufsize) {
			revs = realloc(revs, bufsize+1);
			if (!revs)
				return NULL;
			bufsize++;
		}

		revs[i] = atoi(dirs[n]->d_name);
		i++;
	}

	revs = realloc(revs, bufsize+1);

	if (!i)
		revs[0] = -1;

	// terminate with -1
	revs[bufsize] = -1;

	return revs;
}

int sc_rev_is_done(struct systemc *sc, int rev)
{
	struct stat st;
	char path[256];

	if (!rev)
		return 1;

	sprintf(path, "%s/trails/%d/.done", sc->config->storage.mntpoint, rev);
	if (stat(path, &st) == 0)
		return 1;

	return 0;
}

int sc_get_rollback_rev(struct systemc *sc)
{
	int rev = sc->state->rev;
	struct stat st;
	char path[256];

	while (rev) {
		sprintf(path, "%s/trails/%d/.done", sc->config->storage.mntpoint, rev);
		if (stat(path, &st) == 0)
			return rev;
		rev--;
	}

	return rev;
}

struct sc_state* sc_get_state(struct systemc *sc, int rev)
{
        int fd;
        int size;
        char path[256];
        char *buf;
	struct stat st;
	struct sc_state *s;

	if (rev < 0)
		sprintf(path, "%s/trails/current/state.json", sc->config->storage.mntpoint);
	else
	        sprintf(path, "%s/trails/%d.json", sc->config->storage.mntpoint, rev);

        sc_log(INFO, "reading state from: '%s'", path);

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                sc_log(WARN, "unable to find state JSON for current step");
                return NULL;
        }

	stat(path, &st);
	size = st.st_size;

	buf = calloc(1, size+1);
        size = read(fd, buf, size);
	buf[size] = '\0';

        if (size < 0) {
                sc_log(ERROR, "unable to read device state");
                return NULL;
        }

	sc->step = buf;

	// libtrail
	//s = trail_parse_state(buf, size);
	s = sc_parse_state(sc, buf, size, rev);
	close(fd);

	return s;
}

void sc_release_state(struct systemc *sc)
{
	if (sc->state)
		sc_state_free(sc->state);
}

struct sc_state* sc_get_current_state(struct systemc *sc)
{
	int step_rev = 0;
	struct dirent **dirs;
	char basedir[PATH_MAX];

	sprintf(basedir, "%s/trails/", sc->config->storage.mntpoint);

	int n = scandir(basedir, &dirs, NULL, alphasort);
	while (n--) {
		char *tmp = dirs[n]->d_name;

		while (*tmp && isdigit(*tmp))
			tmp++;

		if(tmp[0] != '\0')
			continue;

		sc_log(INFO, "default to newest step_rev: '%s'", dirs[n]->d_name);
		step_rev = atoi(dirs[n]->d_name);
		break;
	}

	return sc_get_state(sc, step_rev);

	return NULL;
}

int systemc_init()
{
	struct systemc *sc;

        pid_t pid = fork();

        if (pid < 0)
                goto out;

        if (pid > 0) {
                // Let init continue
                sc_pid = pid;
                goto out;
        } else {
		int ret;
                prctl(PR_SET_NAME, "systemc");
		sc = calloc(1, sizeof(struct systemc));

		// Enter state machine
		ret = sc_controller_start(sc);

		// Clean exit -> reboot
                exit(ret);
        }

out:
	return pid;
}
