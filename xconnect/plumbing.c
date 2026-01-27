/*
 * Copyright (c) 2026 Pantacor Ltd.
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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/limits.h>
#include <libgen.h>
#include <stddef.h>

#include "include/xconnect.h"

static int mkdir_p(const char *path, mode_t mode)
{
	char tmp[1024];
	char *p = NULL;
	size_t len;

	if (!path || !path[0] || strlen(path) >= sizeof(tmp))
		return 0;

	strncpy(tmp, path, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';

	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(tmp, mode);
			*p = '/';
		}
	}
	mkdir(tmp, mode);
	return 0;
}

int pvx_helper_inject_unix_socket(const char *path, int pid)
{
	int old_ns_fd = -1;
	int target_ns_fd = -1;
	int fd = -1;
	char ns_path[PATH_MAX];
	struct sockaddr_un sun;

	if (!path)
		return -1;

	// 1. Save current namespace
	old_ns_fd = open("/proc/self/ns/mnt", O_RDONLY);
	if (old_ns_fd < 0) {
		perror("open current ns");
		return -1;
	}

	// 2. Open target namespace
	snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", pid);
	target_ns_fd = open(ns_path, O_RDONLY);
	if (target_ns_fd < 0) {
		perror("open target ns");
		close(old_ns_fd);
		return -1;
	}

	// 3. Enter target namespace
	if (setns(target_ns_fd, CLONE_NEWNS) < 0) {
		perror("setns");
		goto out;
	}

	// 4. Prepare path inside namespace
	char *path_copy = strdup(path);
	if (path_copy) {
		char *dir = dirname(path_copy);
		if (dir) {
			mkdir_p(dir, 0755);
		}
		free(path_copy);
	}

	unlink(path);

	// 5. Create and bind socket
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto out;
	}

	evutil_make_socket_nonblocking(fd);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		perror("bind");
		close(fd);
		fd = -1;
		goto out;
	}

	if (listen(fd, 10) < 0) {
		perror("listen");
		close(fd);
		fd = -1;
		goto out;
	}

out:
	// 7. Always switch back to host namespace
	if (setns(old_ns_fd, CLONE_NEWNS) < 0) {
		perror("setns back");
		// This is fatal for the process if it fails
		exit(1);
	}

	if (old_ns_fd >= 0)
		close(old_ns_fd);
	if (target_ns_fd >= 0)
		close(target_ns_fd);

	return fd;
}
int pvx_helper_inject_devnode(const char *target_path, int consumer_pid,
			      const char *source_path, int provider_pid)
{
	struct stat st;
	char provider_root_path[PATH_MAX];
	int old_ns_fd = -1;
	int target_ns_fd = -1;
	int ret = -1;
	char ns_path[PATH_MAX];

	// 1. Get devnode info from provider namespace
	snprintf(provider_root_path, sizeof(provider_root_path),
		 "/proc/%d/root/%s", provider_pid,
		 source_path[0] == '/' ? source_path + 1 : source_path);

	printf("pvx-helper: Statting provider node %s\n", provider_root_path);
	if (stat(provider_root_path, &st) < 0) {
		perror("stat provider devnode");
		return -1;
	}

	if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {
		fprintf(stderr, "Source %s is not a device node\n",
			provider_root_path);
		return -1;
	}
	printf("pvx-helper: Found device 0x%lx (mode 0x%x)\n",
	       (unsigned long)st.st_rdev, st.st_mode);

	// 2. Save current namespace
	old_ns_fd = open("/proc/self/ns/mnt", O_RDONLY);
	if (old_ns_fd < 0) {
		perror("open current ns");
		return -1;
	}

	// 3. Open target namespace
	snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", consumer_pid);
	printf("pvx-helper: Entering consumer namespace %s\n", ns_path);
	target_ns_fd = open(ns_path, O_RDONLY);
	if (target_ns_fd < 0) {
		perror("open target ns");
		close(old_ns_fd);
		return -1;
	}

	// 4. Enter target namespace
	if (setns(target_ns_fd, CLONE_NEWNS) < 0) {
		perror("setns");
		goto out;
	}

	// 5. Prepare path inside namespace
	char *path_copy = strdup(target_path);
	if (path_copy) {
		char *dir = dirname(path_copy);
		if (dir) {
			printf("pvx-helper: Creating directory %s\n", dir);
			mkdir_p(dir, 0755);
		}
		free(path_copy);
	}

	printf("pvx-helper: Mknod %s\n", target_path);
	unlink(target_path);

	// 6. Create devnode
	if (mknod(target_path, st.st_mode, st.st_rdev) < 0) {
		perror("mknod");
		goto out;
	}

	// 7. Set ownership (optional, but good for consistency)
	chown(target_path, st.st_uid, st.st_gid);
	chmod(target_path, st.st_mode & 0777);

	ret = 0;

out:
	// 8. Always switch back to host namespace
	if (setns(old_ns_fd, CLONE_NEWNS) < 0) {
		perror("setns back");
		exit(1);
	}

	if (old_ns_fd >= 0)
		close(old_ns_fd);
	if (target_ns_fd >= 0)
		close(target_ns_fd);

	return ret;
}