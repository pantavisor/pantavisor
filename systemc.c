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

#include "lxc.h"
#include "loop.h"
#include "controller.h"

#include "systemc.h"

pid_t sc_pid;

void sc_destroy(struct systemc *sc)
{
        sc_release_state(sc);
        free(sc->config);
        free(sc);
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
