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
#include <sys/time.h>
#include <sys/resource.h>

#define MODULE_NAME             "core"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "loop.h"
#include "controller.h"
#include "bootloader.h"

#include "pantavisor.h"

pid_t pv_pid;

void pv_destroy(struct pantavisor *pv)
{
        pv_release_state(pv);
        free(pv->config);
        free(pv);
}

void pv_set_current(struct pantavisor *pv, int rev)
{
	int fd;
	char path[256];

	sprintf(path, "%s/trails/%d/.done", pv->config->storage.mntpoint, rev);

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (!fd) {
		pv_log(WARN, "unable to set current(done) flag for revision %d", rev);
		return;
	}

	// commit to disk
	fsync(fd);
	close(fd);

	// commit to bootloader
	pv_bl_set_current(pv, rev);
}

#define REV_BUF_SIZE	5
int *pv_get_revisions(struct pantavisor *pv)
{
	int n, i = 0;
	int bufsize = 1;
	int *revs = calloc(1, bufsize * sizeof (int));
	struct dirent **dirs;
	char basedir[PATH_MAX];

	sprintf(basedir, "%s/trails/", pv->config->storage.mntpoint);
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

int pv_rev_is_done(struct pantavisor *pv, int rev)
{
	struct stat st;
	char path[256];

	if (!rev)
		return 1;

	sprintf(path, "%s/trails/%d/.done", pv->config->storage.mntpoint, rev);
	if (stat(path, &st) == 0)
		return 1;

	return 0;
}

int pv_get_rollback_rev(struct pantavisor *pv)
{
	unsigned long rev = pv->state->rev;
	struct stat st;
	char path[256];

	while (rev--) {
		sprintf(path, "%s/trails/%lu/.done", pv->config->storage.mntpoint, rev);
		if (stat(path, &st) == 0)
			return rev;
	}

	return rev;
}

struct pv_state* pv_get_state(struct pantavisor *pv, int rev)
{
        int fd;
        int size;
        char path[256];
        char *buf;
	struct stat st;
	struct pv_state *s;

	if (rev < 0)
		sprintf(path, "%s/trails/current/state.json", pv->config->storage.mntpoint);
	else
	        sprintf(path, "%s/trails/%d.json", pv->config->storage.mntpoint, rev);

        pv_log(INFO, "reading state from: '%s'", path);

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                pv_log(WARN, "unable to find state JSON for current step");
                return NULL;
        }

	stat(path, &st);
	size = st.st_size;

	buf = calloc(1, size+1);
        size = read(fd, buf, size);
	buf[size] = '\0';

        if (size < 0) {
                pv_log(ERROR, "unable to read device state");
                return NULL;
        }

	pv->step = buf;

	// libtrail
	//s = trail_parse_state(buf, size);
	s = pv_parse_state(pv, buf, size, rev);
	close(fd);

	return s;
}

void pv_release_state(struct pantavisor *pv)
{
	if (pv->state)
		pv_state_free(pv->state);
}

struct pv_state* pv_get_current_state(struct pantavisor *pv)
{
	int step_rev = 0;
	struct dirent **dirs;
	char basedir[PATH_MAX];

	sprintf(basedir, "%s/trails/", pv->config->storage.mntpoint);

	int n = scandir(basedir, &dirs, NULL, alphasort);
	while (n--) {
		char *tmp = dirs[n]->d_name;

		while (*tmp && isdigit(*tmp))
			tmp++;

		if(tmp[0] != '\0')
			continue;

		pv_log(INFO, "default to newest step_rev: '%s'", dirs[n]->d_name);
		step_rev = atoi(dirs[n]->d_name);
		break;
	}

	return pv_get_state(pv, step_rev);

	return NULL;
}

int pantavisor_init()
{
	struct pantavisor *pv;

        pid_t pid = fork();

        if (pid < 0)
                goto out;

        if (pid > 0) {
                // Let init continue
                pv_pid = pid;
                goto out;
        } else {
		int ret;
                prctl(PR_SET_NAME, "pantavisor");
		pv = calloc(1, sizeof(struct pantavisor));

		struct rlimit core_limit;
		core_limit.rlim_cur = RLIM_INFINITY;
		core_limit.rlim_max = RLIM_INFINITY;

		setrlimit(RLIMIT_CORE, &core_limit);

		char *core = "/storage/corepv";
		int fd = open("/proc/sys/kernel/core_pattern", O_WRONLY | O_SYNC);
		if (fd)
			write(fd, core, strlen(core));

		// Enter state machine
		ret = pv_controller_start(pv);

		// Clean exit -> reboot
                exit(ret);
        }

out:
	return pid;
}
