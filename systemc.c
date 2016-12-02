#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

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

struct sc_volume {
	char *src;
	char *dest;
	int loop_fd;
	int file_fd;

	struct sc_volume *next;
};

struct sc_volume *head = NULL;
struct sc_volume *last;

static struct sc_volume* _sc_volume_add(char *src, char *dest, int loop_fd, int file_fd)
{
	struct sc_volume *this = malloc(sizeof(struct sc_volume));

	if (head == NULL)
		head = this;
	else
		last->next = this;

	this->src = strdup(src);
	this->dest = strdup(dest);
	this->loop_fd = loop_fd;
	this->file_fd = file_fd;
	this->next = NULL;
	last = this;

	return this;
}

static struct sc_volume* _sc_volume_get(char *src)
{
	struct sc_volume *curr = head;

	while (curr) {
		if (strcmp(curr->src, src) == 0)
			return curr;
		curr = curr->next;
	}

	return NULL;
}

static void _sc_volume_remove(char *src)
{
	struct sc_volume *curr = head;
	struct sc_volume *prev = head;

	for (curr = prev = head; curr != NULL; curr = curr->next) {
		if (strcmp(curr->src, src) == 0) {
			free(curr->src);
			free(curr->dest);
			if (curr == head)
				head = curr->next;
			else
				prev->next = curr->next;
			free(curr);
			return;
		}
		prev = curr;
	}
	
	last = prev;
}

int sc_volumes_unmount(struct systemc *sc)
{
	int count = 0;
	systemc_volobject **volumes = sc->state->volumesv;

        while(*volumes) {
                char src[PATH_MAX];
		struct sc_volume *v;

                sprintf(src, "%s/trails/%d/volumes/%s", sc->config->storage.mntpoint,
			sc->state->rev, (*volumes)->filename);

		v = _sc_volume_get(src);
		if (unmount_loop(v->dest, v->loop_fd, v->file_fd) < 0) {
			sc_log(ERROR, "error umounting volumes");
			return -1;
		} else {
			_sc_volume_remove(src);
			count++;
		}
		volumes++;
	}
	
	sc_log(INFO, "unmounted '%d' volumes", count);
	
	return count;
}

systemc_state *sc_get_state(struct systemc *sc, int rev)
{
        int fd;
        int size;;
        char path[256];
        char *buf;
	struct stat st;
	systemc_state *s;

	if (rev < 0)
		sprintf(path, "%s/trails/current/state.json", sc->config->storage.mntpoint);
	else
	        sprintf(path, "%s/trails/%d/state.json", sc->config->storage.mntpoint, rev);

        sc_log(INFO, "reading state from: '%s'", path);

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                sc_log(WARN, "unable to find state JSON for current step");
                return NULL;
        }

	stat(path, &st);
	size = st.st_size;

	buf = calloc(1, size);
        size = read(fd, buf, size);

        if (size < 0) {
                sc_log(ERROR, "unable to read device state");
                return NULL;
        }

	sc->step = buf;

	// libtrail
	s = trail_parse_state(buf, size);
	close(fd);

	return s;
}

void sc_release_state(struct systemc *sc)
{
	if (sc->step)
		free(sc->step);
	
	if (sc->state)
		trail_state_free(sc->state);
}

systemc_state *sc_get_current_state(struct systemc *sc)
{
	struct stat buf;
	char basedir[PATH_MAX];

	sprintf(basedir, "%s/trails/current", sc->config->storage.mntpoint);
	if (stat(basedir, &buf) != 0)
		return sc_get_state(sc, -1);

	return NULL;
}

int sc_volumes_mount(struct systemc *sc)
{
        int ret;
        systemc_volobject **volumes = sc->state->volumesv;

        // Create volumes if non-existant
        mkdir("/volumes", 0644);

        while(*volumes) {
		int loop_fd, file_fd;
                char path[256];
                char mntpoint[256];

                sprintf(path, "%s/trails/%d/volumes/%s", sc->config->storage.mntpoint,
			sc->state->rev, (*volumes)->filename);
                sprintf(mntpoint, "/volumes/%s", (*volumes)->filename);

                char *fstype = strrchr((*volumes)->filename, '.');
                fstype++;

                sc_log(INFO, "mounting volume '%s' to '%s' with type '%s'", path, mntpoint, fstype);

                ret = mount_loop(path, mntpoint, fstype, &loop_fd, &file_fd);
                if (ret < 0)
                        exit_error(errno, "Could not mount loop device");
		
		_sc_volume_add(path, mntpoint, loop_fd, file_fd);

                volumes++;
        }

        return 0;
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
		sc = malloc(sizeof(struct systemc));

		// Enter state machine
		ret = sc_controller_start(sc);

		// Clean exit -> reboot
                exit(ret);
        }

out:
	return pid;	
}
