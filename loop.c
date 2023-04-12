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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/sysmacros.h>

#include <linux/loop.h>
#include <linux/limits.h>

#include "utils/fs.h"
#include "utils/str.h"
#include "init.h"
#include "loop.h"

#define MODULE_NAME "loop"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

static int mount_ext4(char *dev, char *dest)
{
	int ret;
	char *opts[] = { "data=journal", "data=ordered" };

	ret = mount(dev, dest, "ext4", 0, opts[0]);
	if (!ret)
		return ret;

	pv_log(WARN, "unable to mount ext4 with data=journal");

	// try ordered
	ret = mount(dev, dest, "ext4", 0, opts[1]);
	if (!ret)
		return ret;

	// let the kernel try default opts
	return mount(dev, dest, "ext4", 0, 0);
}

static int get_free_loop(char *devname)
{
	int ret = -1;
	int lctlfd, dev;

	lctlfd = open("/dev/loop-control", O_RDWR);
	if (lctlfd < 0)
		goto out;

	dev = ioctl(lctlfd, LOOP_CTL_GET_FREE);
	if (dev < 0)
		goto out;

	SNPRINTF_WTRUNC(devname, PATH_MAX, "/dev/loop%d", dev);
	ret = 0;

	// in case we are inside container where loop devices are not
	// auto created we try out best to set this up ourselves
	mknod(devname, S_IFBLK | 0600, makedev (7, dev));

out:
	if (lctlfd > 0)
		close(lctlfd);

	return ret;
}

static int bind_loop_dev(char *devname, char *file, int *loop_fd, int *file_fd)
{
	int loopfd = open(devname, O_RDWR);
	if (loopfd < 0)
		return -1;

	int filefd = open(file, O_RDWR);
	if (filefd < 0)
		return -1;

	if (ioctl(loopfd, LOOP_SET_FD, filefd) < 0)
		return -1;

	*loop_fd = loopfd;
	*file_fd = filefd;

	return 0;
}

int mount_bind(char *src, char *dest)
{
	int ret;

	ret = mount(src, dest, "none", MS_BIND, 0);
	if (ret < 0)
		pv_log(WARN, "unable to bind mount from %s to %s", src, dest);

	return ret;
}

int mount_loop(char *src, char *dest, char *fstype, int *loop_fd, int *file_fd)
{
	int ret = 0;
	char devname[PATH_MAX];
	char *opts = NULL;

	if (get_free_loop(devname) < 0)
		return -1;

	if (bind_loop_dev(devname, src, loop_fd, file_fd) < 0)
		return -1;

	// Make dest if it doesn't exist
	if (pv_fs_mkdir_p(dest, 0755) < 0)
		return -1;

	// if ext4 make sure we mount journaled
	if (strcmp(fstype, "ext4") == 0)
		ret = mount_ext4(devname, dest);
	else
		ret = mount(devname, dest, fstype, 0, opts);

	if (ret < 0) {
		pv_log(ERROR, "could not mount \"%s\" (\"%s\")", src, fstype);
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

out:
	return ret;
}
