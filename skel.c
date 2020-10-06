/*
 * Copyright (c) 2020 Pantacor Ltd.
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


#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include "init.h"
#include "pantavisor.h"

#define MODULE_NAME		"skel-init"
#define pv_log(level, msg, ...)		vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#define STATE_EMBED_DEFAULT "{ \"#spec\": \"pantavisor-service-embed@1\" }"

static int pv_skel_init(struct pv_init *this)
{
	struct pantavisor *pv = NULL;
	struct pv_system *system = NULL;
	struct stat st;

	char _path[PATH_MAX];
	char _dir[PATH_MAX];
	int ret = -1;

	pv = get_pv_instance();
	if (!pv || !pv->system)
		goto out;
	system = pv->system;

	snprintf(_dir, PATH_MAX, "%s/trails/0/.pv", system->vardir);
	if (stat(_dir, &st) != 0)
		mkdir_p(_dir, 0500);

	snprintf(_dir, PATH_MAX, "%s/trails/0/.pvr", system->vardir);
	if (stat(_dir, &st) != 0)
		mkdir_p(_dir, 0500);

	snprintf(_path, PATH_MAX, "%s/json", _dir);
	if (stat(_path, &st) != 0) {
		int fd = open(_path, O_CREAT | O_WRONLY, 0644);
		if (!fd)
			goto out;

		/*
		 * [PKS]
		 * Use write_nointr
		 */
		if (write(fd, STATE_EMBED_DEFAULT , strlen(STATE_EMBED_DEFAULT)) < 0) {
			close(fd);
			goto out;
		}

		close(fd);
	}

	snprintf(_dir, PATH_MAX, "%s/config", system->vardir);
	if (stat(_dir, &st) != 0)
		mkdir_p(_dir, 0500);

	snprintf(_dir, PATH_MAX, "%s/boot", system->vardir);
	if (stat(_dir, &st) != 0)
		mkdir_p(_dir, 0500);

	snprintf(_dir, PATH_MAX, "%s/vendor", system->vardir);
	if (stat(_dir, &st) != 0)
		mkdir_p(_dir, 0500);

	snprintf(_dir, PATH_MAX, "%s/objects", system->vardir);
	if (stat(_dir, &st) != 0)
		mkdir_p(_dir, 0500);

	ret = 0;
 out:
	return ret;
}


struct pv_init pv_init_skel = {
	.init_fn = pv_skel_init,
	.flags = 0,
};
