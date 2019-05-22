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

#include <sys/utsname.h>
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
#include "parser/parser.h"

#define FW_PATH		"/lib/firmware"

const char* pv_volume_type_str(pv_volume_t vt)
{
	switch(vt) {
	case VOL_LOOPIMG: return "LOOP_IMG";
	case VOL_PERMANENT: return "PERMANENT";
	case VOL_REVISION: return "REVISION";
	case VOL_BOOT: return "TMPFS";
	default: return "UNKNOWN";
	}

	return "UNKNOWN";
}

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

	this->name = strdup(name);

	return this;
}

int pv_volumes_mount(struct pantavisor *pv)
{
        int ret = -1;
	char *fstype;
	char path[PATH_MAX], base[PATH_MAX], mntpoint[PATH_MAX];
	struct stat st;
	struct utsname uts;
	struct pv_state *s = pv->state;
	struct pv_volume *v = s->volumes;

        // Create volumes if non-existant
        mkdir("/volumes", 0644);
	sprintf(base, "%s/disks", pv->config->storage.mntpoint);
	mkdir_p(base, 0644);

	while (v) {
		int loop_fd = -1, file_fd = -1;

		switch (pv_state_spec(s)) {
		case SPEC_SYSTEM1:
			if (v->plat) {
				sprintf(path, "%s/trails/%d/%s/%s", pv->config->storage.mntpoint,
					s->rev, v->plat->name, v->name);
				sprintf(mntpoint, "/volumes/%s/%s", v->plat->name, v->name);
			} else {
				sprintf(path, "%s/trails/%d/bsp/%s", pv->config->storage.mntpoint,
					s->rev, v->name);
				sprintf(mntpoint, "/volumes/%s", v->name);
			}
			break;
		case SPEC_MULTI1:
			sprintf(path, "%s/trails/%d/%s", pv->config->storage.mntpoint,
				s->rev, v->name);
			sprintf(mntpoint, "/volumes/%s", v->name);
			break;
		default:
			pv_log(WARN, "cannot mount volumes for unknown state spec");
			goto out;
		}

		pv_log(INFO, "mounting '%s' of platform '%s'", v->name, v->plat ? v->plat->name : "NONE");

		switch (v->type) {
		case VOL_LOOPIMG:
			fstype = strrchr(v->name, '.');
			fstype++;
			if (strcmp(fstype, "bind") == 0) {
				struct stat buf;
				if (stat(mntpoint, &buf) != 0) {
					int fd = open(mntpoint, O_CREAT | O_EXCL | O_RDWR | O_SYNC, 0644);
					close(fd);
				}
				ret = mount(path, mntpoint, "none", MS_BIND, "ro");
			} else {
				ret = mount_loop(path, mntpoint, fstype, &loop_fd, &file_fd);
			}
			break;
		case VOL_PERMANENT:
			sprintf(path, "%s/perm/%s/%s", base, v->plat->name, v->name);
			mkdir_p(path, 0644);
			mkdir_p(mntpoint, 0644);
			ret = mount(path, mntpoint, "none", MS_BIND, "rw");
			break;
		case VOL_REVISION:
			sprintf(path, "%s/rev/%d/%s/%s", base, s->rev, v->plat->name, v->name);
			mkdir_p(path, 0644);
			mkdir_p(mntpoint, 0644);
			ret = mount(path, mntpoint, "none", MS_BIND, "rw");
			break;
		case VOL_BOOT:
			mkdir_p(mntpoint, 0644);
			ret = mount("none", mntpoint, "tmpfs", 0, NULL);
			break;
		default:
			pv_log(WARN, "unknown volume type %d", v->type);
			break;
		}

                if (ret < 0)
                        goto out;

		pv_log(INFO, "mounted '%s' (%s) at '%s'", path, pv_volume_type_str(v->type), mntpoint);

		// register mount state
		v->src = strdup(path);
		v->dest = strdup(mntpoint);
		v->loop_fd = loop_fd;
		v->file_fd = file_fd;

                v = v->next;
	}

	if (!pv->state->firmware)
		goto modules;

	if ((stat(FW_PATH, &st) < 0) && errno == ENOENT)
		mkdir_p(FW_PATH, 0644);

	if (strchr(pv->state->firmware, '/'))
		sprintf(path, "%s", pv->state->firmware);
	else
		sprintf(path, "/volumes/%s", pv->state->firmware);

	if (stat(path, &st))
		goto modules;

	ret = mount_bind(path, FW_PATH);

	if (ret < 0)
		goto out;

	pv_log(DEBUG, "bind mounted firmware to %s", FW_PATH);

modules:
	if (!uname(&uts) && (stat("/volumes/modules.squashfs", &st) == 0)) {
		sprintf(path, "/lib/modules/%s", uts.release);
		mkdir_p(path, 0644);
		ret = mount_bind("/volumes/modules.squashfs", path);
		pv_log(DEBUG, "bind mounted modules to %s", path);
	}

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

	if (pv->state->firmware)
		umount(FW_PATH);

	pv_log(INFO, "unmounted '%d' volumes", count);

	return count;
}
