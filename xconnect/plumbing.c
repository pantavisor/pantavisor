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
#include <libgen.h>

#include "include/xconnect.h"

static int mkdir_p(char *path, mode_t mode)
{
    char *sub, *p;
    for (p = path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(path, mode);
            *p = '/';
        }
    }
    mkdir(path, mode);
    return 0;
}

int pvx_helper_inject_unix_socket(const char *path, int pid)
{
    int old_ns_fd = -1;
    int target_ns_fd = -1;
    int fd = -1;
    char ns_path[PATH_MAX];

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
    char *dir = dirname(path_copy);
    mkdir_p(dir, 0755);
    free(path_copy);

    unlink(path);

    // 5. Create and bind socket
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        goto out;
    }

    struct sockaddr_un sun;
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

    // 6. Set non-blocking for libevent
    evutil_make_socket_nonblocking(fd);

out:
    // 7. Always switch back to host namespace
    if (setns(old_ns_fd, CLONE_NEWNS) < 0) {
        perror("setns back");
        // This is fatal for the process if it fails
        exit(1);
    }

    if (old_ns_fd >= 0) close(old_ns_fd);
    if (target_ns_fd >= 0) close(target_ns_fd);

    return fd;
}
