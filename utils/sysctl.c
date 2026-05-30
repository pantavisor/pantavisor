/*
 * Copyright (c) 2026 Pantacor Ltd.
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "sysctl.h"

int pv_sysctl_write(const char *path, const char *value)
{
	if (!path || !value)
		return -1;

	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	size_t len = strlen(value);
	ssize_t n;
	int saved_errno = 0;
	do {
		n = write(fd, value, len);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		saved_errno = errno;
	close(fd);

	if (n < 0) {
		errno = saved_errno;
		return -1;
	}
	return 0;
}
