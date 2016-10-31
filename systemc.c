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

#include "log.h"
#include "lxc.h"
#include "loop.h"
#include "controller.h"

#include "systemc.h"

pid_t sc_pid;

void sc_destroy(struct systemc *sc)
{
        trail_state_free(sc->state);
        free(sc->config);
        free(sc);
}

systemc_state *sc_get_state(struct systemc *sc, int rev)
{
        int fd;
        int bytes;
        char path[256];
        char buf[4096];

	if (rev < 0)
		sprintf(path, "%s/trails/current/state.json", sc->config->storage.mntpoint);
	else
	        sprintf(path, "%s/trails/%d/state.json", sc->config->storage.mntpoint, rev);

        printf("Reading state from: '%s'\n", path);

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                printf("Unable to find state JSON for current step\n");
                return NULL;
        }

        bytes = read(fd, &buf, sizeof(buf));
        if (bytes < 0) {
                printf("Unable to read device state\n");
                return NULL;
        }

	// libtrail
        return trail_parse_state (buf, bytes);
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

int sc_mount_volumes(struct systemc *sc)
{
        int ret;
        systemc_volobject **volumes = sc->state->volumesv;

        // Create volumes if non-existant
        mkdir("/volumes", 0644);

        while(*volumes) {
                char path[256];
                char mntpoint[256];

                sprintf(path, "%s/trails/%d/volumes/%s", sc->config->storage.mntpoint,
			sc->state->rev, (*volumes)->filename);
                sprintf(mntpoint, "/volumes/%s", (*volumes)->filename);

                char *fstype = strrchr((*volumes)->filename, '.');
                fstype++;

                printf("Mounting volume '%s' to '%s' with type '%s'\n", path, mntpoint, fstype);

                ret = mount_loop(path, mntpoint, fstype);
                if (ret < 0)
                        exit_error(errno, "Could not mount loop device");

                volumes++;
        }

        return 0;
}

/*
int sc_start_platforms(struct systemc *sc)
{
	systemc_platform **platforms;

	if (sc->state->platformsv) {
		platforms = sc->state->platformsv;
	} else {
        	printf("No platforms to start\n");
		return -1;
	}

	while(*platforms) {
		char conf_path[512];
		systemc_object **configs;
		
		// Take first config, might be NULL
		configs = (*platforms)->configs;
		sprintf(conf_path, "%s/trails/%d/platforms/%s/configs/%s",
		        sc->config->storage.mntpoint, sc->state->rev,
		        (*platforms)->name, (*configs)->filename);
		
		start_lxc_container((*platforms)->name, conf_path);
		
		platforms++;
	}
	
	return 0;
}
*/

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
                prctl(PR_SET_NAME, "systemc");
		sc = malloc(sizeof(struct systemc));

		// Enter state machine
		sc_controller_start(sc);

		// Clean exit -> reboot
                exit(0);
        }

out:
	return pid;	
}
