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

#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#define MODULE_NAME             "volumes"
#define pv_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "loop.h"

#include "utils.h"
#include "pantavisor.h"
#include "volumes.h"

#define FW_PATH		"/lib/firmware"

struct pv_volume* pv_volume_get_by_name(struct pv_state *s, char *name)
{
	struct pv_volume* v = s->volumes;

	while (v) {
		if (!strcmp(name, v->name))
			return v;
		v = v->next;
	}

	return NULL;
}

void pv_volume_remove(struct pv_state *s, char *name)
{
	struct pv_volume *v = s->volumes;
	struct pv_volume *prev = NULL;

	while (v) {
		if (!strcmp(v->name, name)) {
			if (v->name)
				free(v->name);
			if (v->mode)
				free(v->mode);
			if (v->src)
				free(v->src);
			if (v->dest)
				free(v->dest);
			
			if (v == s->volumes)
				s->volumes = v->next;
			else
				prev->next = v->next;
			free(v);
			return;
		}
		prev = v;
	}
}

struct pv_volume* pv_volume_add(struct pv_state *s, char *name)
{
	struct pv_volume *this = calloc(1, sizeof(struct pv_volume));
	struct pv_volume *add = s->volumes;

	while (add && add->next) {
		add = add->next;
	}

	if (!add) {
		s->volumes = add = this;
	} else {
		add->next = this;
	}

	this->name = name;

	return this;
}

int pv_volumes_mount(struct pantavisor *pv)
{
        int ret = -1;
	struct stat st;
	struct pv_state *s = pv->state;
	struct pv_volume *v = s->volumes;

        // Create volumes if non-existant
        mkdir("/volumes", 0644);

	while (v) {
		int loop_fd = -1, file_fd = -1;
                char path[256];
                char mntpoint[256];

                sprintf(path, "%s/trails/%d/%s", pv->config->storage.mntpoint,
			s->rev, v->name);
                sprintf(mntpoint, "/volumes/%s", v->name);

                char *fstype = strrchr(v->name, '.');
                fstype++;

                pv_log(INFO, "mounting volume '%s' to '%s' with type '%s'", path, mntpoint, fstype);

		if (strcmp(fstype, "bind") == 0) {
			struct stat buf;
			if (stat(mntpoint, &buf) != 0) {
				int fd = open(mntpoint, O_CREAT | O_EXCL | O_RDWR | O_SYNC);
				close(fd);
			}
			ret = mount(path, mntpoint, "none", MS_BIND, "ro");
		} else {
			ret = mount_loop(path, mntpoint, fstype, &loop_fd, &file_fd);
		}

                if (ret < 0)
                        exit_error(errno, "Could not mount loop device");

		// register mount state
		v->src = strdup(path);
		v->dest = strdup(mntpoint);
		v->loop_fd = loop_fd;
		v->file_fd = file_fd;

                v = v->next;
	}

	if (!pv->state->firmware)
		goto out;

	if (stat(pv->state->firmware, &st))
		goto out;

	if ((stat(FW_PATH, &st) < 0) && errno == ENOENT)
		mkdir_p(FW_PATH, 0644);

	ret = mount_bind(pv->state->firmware, FW_PATH);

out:
        return ret;
}

int pv_volumes_unmount(struct pantavisor *pv)
{
	int ret;
	int count = 0;
	struct pv_state *s = pv->state;
	struct pv_volume *v = s->volumes;

        while(v) {
		if (v->loop_fd == -1) {
			ret = umount(v->dest);
		} else {
			ret = unmount_loop(v->dest, v->loop_fd, v->file_fd);
		}

		if (ret < 0) {
			pv_log(ERROR, "error umounting volumes");
			return -1;
		} else {
			pv_log(INFO, "unmounted '%s' successfully", v->dest);
			pv_volume_remove(s, v->name);
			count++;
		}
		v = v->next;
	}

	pv_log(INFO, "unmounted '%d' volumes", count);

	return count;
}
