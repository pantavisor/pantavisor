/*
 * Copyright (c) 2021 Pantacor Ltd.
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
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/vfs.h>

#include <linux/magic.h>

#include "system.h"
#include "fs.h"

#define PREFIX_MODEL "model name\t:"

int get_endian(void)
{
	unsigned long t = 0x00102040;
	return ((((char *)(&t))[0]) == 0x40);
}

int get_dt_model(char *buf, int buflen)
{
	int fd = -1;
	int ret = -1;

	fd = pv_fs_file_check_and_open("/proc/device-tree/model", O_RDONLY, 0);
	if (fd >= 0) {
		ret = pv_fs_file_read_nointr(fd, buf, buflen);
		close(fd);
	}
	return ret >= 0 ? 0 : ret;
}

int get_cpu_model(char *buf, int buflen)
{
	int fd = -1;
	int ret = -1;
	char *cur = NULL, *value = NULL;
	int bytes_read = 0;

	if (!buf || buflen <= 0)
		goto out;

	fd = pv_fs_file_check_and_open("/proc/cpuinfo", O_RDONLY, 0);
	if (fd >= 0) {
		bytes_read = pv_fs_file_read_nointr(fd, buf, buflen);
		close(fd);
	}
	if (bytes_read > 0)
		buf[bytes_read - 1] = '\0';
	else
		goto out;

	cur = strstr(buf, PREFIX_MODEL);
	if (cur) {
		int len = 0;
		/*
		 * sizeof gets us past the space after
		 * colon as well if present. For example
		 * model name	: XXX Processor rev YY (ZZZ)
		 */
		value = cur + sizeof(PREFIX_MODEL);
		cur = strchr(value, '\n');
		if (cur) {
			char *__value = NULL;
			/*
			 * don't copy the newline
			 */
			len = cur - value;
			__value = calloc(len + 1, sizeof(char));
			if (__value) {
				memcpy(__value, value, len);
				snprintf(buf, buflen, "%s", __value);
				free(__value);
				ret = 0;
			}
		}
	}
out:
	return ret;
}

cgroup_version_t pv_system_get_cgroup_version(void)
{
	struct statfs fs;

	if (!statfs("/sys/fs/cgroup/", &fs)) {
		if (fs.f_type == CGROUP2_SUPER_MAGIC) {
			return CGROUP_UNIFIED;
		} else if (fs.f_type == TMPFS_MAGIC) {
			if (!statfs("/sys/fs/cgroup/unified/", &fs))
				return CGROUP_HYBRID;
			else
				return CGROUP_LEGACY;
		}
	}

	return CGROUP_UNKNOWN;
}

const char *pv_system_cgroupv_string(cgroup_version_t cgroupv)
{
	switch (cgroupv) {
	case CGROUP_LEGACY:
		return "CGROUP_LEGACY";
	case CGROUP_HYBRID:
		return "CGROUP_HYBRID";
	case CGROUP_UNIFIED:
		return "CGROUP_UNIFIED";
	default:
		return "CGROUP_UNKNOWN";
	}
	return "CGROUP_UNKNOWN";
}

void pv_system_kill_lenient(pid_t pid)
{
	if (pid <= 0)
		return;

	kill(pid, SIGTERM);
}

void pv_system_kill_force(pid_t pid)
{
	bool exited = false;

	if (pid <= 0)
		return;

	// check process has end
	for (int i = 0; i < 5; i++) {
		if (kill(pid, 0))
			exited = true;
		if (exited)
			break;
		sleep(1);
	}

	// force kill if process could not finish
	if (!exited)
		kill(pid, SIGKILL);
}
