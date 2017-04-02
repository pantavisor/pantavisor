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
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

#include "loop.h"

#include "utils.h"
#include "systemc.h"
#include "volumes.h"

struct sc_volume* sc_volume_get_by_name(struct sc_state *s, char *name)
{
	struct sc_volume* v = s->volumes;

	while (v) {
		if (!strcmp(name, v->name))
			return v;
		v = v->next;
	}

	return NULL;
}

void sc_volume_remove(struct sc_state *s, char *name)
{
	struct sc_volume *v = s->volumes;
	struct sc_volume *prev = NULL;

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

struct sc_volume* sc_volume_add(struct sc_state *s, char *name)
{
	struct sc_volume *this = calloc(1, sizeof(struct sc_volume));
	struct sc_volume *add = s->volumes;

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

int sc_volumes_mount(struct systemc *sc)
{
        int ret = -1;
	struct sc_state *s = sc->state;
	struct sc_volume *v = s->volumes;

        // Create volumes if non-existant
        mkdir("/volumes", 0644);

	while (v) {
		int loop_fd = -1, file_fd = -1;
                char path[256];
                char mntpoint[256];

                sprintf(path, "%s/trails/%d/%s", sc->config->storage.mntpoint,
			s->rev, v->name);
                sprintf(mntpoint, "/volumes/%s", v->name);

                char *fstype = strrchr(v->name, '.');
                fstype++;

                sc_log(INFO, "mounting volume '%s' to '%s' with type '%s'", path, mntpoint, fstype);

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

        return ret;
}

int sc_volumes_unmount(struct systemc *sc)
{
	int ret;
	int count = 0;
	struct sc_state *s = sc->state;
	struct sc_volume *v = s->volumes;

        while(v) {
		if (v->loop_fd == -1) {
			ret = umount(v->dest);
		} else {
			ret = unmount_loop(v->dest, v->loop_fd, v->file_fd);
		}

		if (ret < 0) {
			sc_log(ERROR, "error umounting volumes");
			return -1;
		} else {
			sc_log(INFO, "unmounted '%s' successfully", v->dest);
			sc_volume_remove(s, v->name);
			count++;
		}
		v = v->next;
	}

	sc_log(INFO, "unmounted '%d' volumes", count);

	return count;
}
