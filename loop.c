#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <linux/loop.h>

#include "utils.h"
#include "init.h"
#include "loop.h"

#define MODULE_NAME             "loop"
#define sc_log(level, msg, ...)         vlog(MODULE_NAME, level, msg, ## __VA_ARGS__)
#include "log.h"

int get_free_loop(char *devname)
{
	int lctlfd, dev;

	lctlfd = open("/dev/loop-control", O_RDWR);
	if (lctlfd < 0)
		return -1;

	dev = ioctl(lctlfd, LOOP_CTL_GET_FREE);
	if (dev < 0)
               return -1;

	sprintf(devname, "/dev/loop%d", dev);

	return 0;
}

int bind_loop_dev(char *devname, char *file, int *loop_fd, int *file_fd)
{
	int loopfd = *loop_fd;
	int filefd = *file_fd;

	loopfd = open(devname, O_RDWR);
	if (loopfd < 0)
		return -1;

	filefd = open(file, O_RDWR);
	if (filefd < 0)
		return -1;

	if (ioctl(loopfd, LOOP_SET_FD, filefd) < 0)
		return -1;

	*loop_fd = loopfd;
	*file_fd = filefd;

	return 0;	
}

int mount_loop(char *src, char *dest, char *fstype, int *loop_fd, int *file_fd)
{
	int ret = 0;
	char devname[128];
	char *opts = NULL;

	if (get_free_loop(devname) < 0)
		return -1;

	if (bind_loop_dev(devname, src, loop_fd, file_fd) < 0)
		return -1;

	// Make dest if it doesn't exist
	if (mkdir_p(dest, 0644) < 0)
		return -1;	

	// if ext4 make sure we mount journaled
	if (strcmp(fstype, "ext4") == 0)
		opts = strdup("data=journal");

	ret = mount(devname, dest, fstype, 0, opts);
	if (ret < 0) {
		sc_log(ERROR, "could not mount \"%s\" (\"%s\")", src, fstype);
		goto out;
	}

out:
	if (opts)
		free(opts);

	return ret;
}

int unmount_loop(char *dest, int loop_fd, int file_fd)
{
	int ret;

	ret = umount(dest);
	if (ret < 0)
		goto out;

	ret = ioctl(loop_fd, LOOP_CLR_FD, 0);
	if (ret < 0)
		goto out;

	ret = close(loop_fd);
	if (ret < 0)
		goto out;

	fsync(file_fd);
	ret = close(file_fd);
	if (ret < 0)
		goto out;

	sc_log(INFO, "umounted '%s' volume", dest);

out:
	return ret;
}
