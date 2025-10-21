/*
 * Copyright (c) 2023-2025 Pantacor Ltd.
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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <linux/limits.h>
#include <linux/magic.h>

#include "cgroup.h"
#include "pantavisor.h"
#include "utils/str.h"
#include "utils/math.h"
#include "utils/fs.h"

#define MODULE_NAME "cgroup"
#define pv_log(level, msg, ...)                                                \
	vlog(MODULE_NAME, level, "(%s:%d) " msg, __FUNCTION__, __LINE__,       \
	     ##__VA_ARGS__)
#include "log.h"

static const char *pv_cgroup_version_string(cgroup_version_t cgroupv)
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

void pv_cgroup_print()
{
	struct pantavisor *pv = pv_get_instance();
	pv_log(DEBUG, "cgroup version detected '%s'",
	       pv_cgroup_version_string(pv->cgroupv));
}

static cgroup_version_t pv_cgroup_get_version(void)
{
	struct statfs fs;
	cgroup_version_t cgroupv = CGROUP_UNKNOWN;

	if (!statfs("/sys/fs/cgroup/", &fs)) {
		if (fs.f_type == CGROUP2_SUPER_MAGIC) {
			cgroupv = CGROUP_UNIFIED;
		} else if (fs.f_type == TMPFS_MAGIC) {
			if (!statfs("/sys/fs/cgroup/unified/", &fs))
				cgroupv = CGROUP_HYBRID;
			else
				cgroupv = CGROUP_LEGACY;
		}
	}

	return cgroupv;
}

static int pv_cgroup_mkcgroup_root()
{
	int ret;

	mkdir("/sys/fs/cgroup", 0755);
	ret = mount("none", "/sys/fs/cgroup", "tmpfs", 0, NULL);
	if (ret < 0) {
		pv_log(ERROR, "Could not mount main cgroup: %s",
		       strerror(errno));
	}

	return ret;
}

static int pv_cgroup_mkcgroup_init(const char *init)
{
	char path[PATH_MAX];
	SNPRINTF_WTRUNC(path, sizeof(path), "/sys/fs/cgroup/%s", init);

	char data[PATH_MAX];
	SNPRINTF_WTRUNC(data, sizeof(data), "none,name=%s", init);

	int ret;

	mkdir(path, 0555);
	ret = mount("cgroup", path, "cgroup", 0, data);
	if (ret < 0)
		pv_log(ERROR, "Could not mount %s cgroup: %s", init,
		       strerror(errno));

	return ret;
}

static int pv_cgroup_mkcgroup_resource(const char *resource)
{
	char path[PATH_MAX];
	SNPRINTF_WTRUNC(path, sizeof(path), "/sys/fs/cgroup/%s", resource);

	int ret;

	mkdir(path, 0555);
	ret = mount("cgroup", path, "cgroup", 0, resource);
	if (ret < 0)
		pv_log(WARN, "Could not mount %s cgroup: %s", resource,
		       strerror(errno));

	return ret;
}

static int pv_cgroup_mkcgroup_unified()
{
	int ret;

	mkdir("/sys/fs/cgroup/unified", 0555);
	ret = mount("cgroup2", "/sys/fs/cgroup/unified", "cgroup2",
		    MS_NOSUID | MS_NOEXEC | MS_NODEV, "nsdelegate");
	if (ret < 0)
		pv_log(WARN, "Could not mount unified cgroup: %s",
		       strerror(errno));

	return ret;
}

static int pv_cgroup_init_appengine()
{
	struct pantavisor *pv = pv_get_instance();
	pv->cgroupv = pv_cgroup_get_version();

	if ((pv->cgroupv == CGROUP_LEGACY) || (pv->cgroupv == CGROUP_HYBRID))
		pv_cgroup_mkcgroup_init("pantavisor");

	return 0;
}

int pv_cgroup_init()
{
	// IM_APPENGINE supports all cgroup versions
	// IM_EMBEDDED and IM_STANDALONE supports HYBRID cgroup only
	if (pv_config_get_system_init_mode() == IM_APPENGINE)
		return pv_cgroup_init_appengine();

	if (pv_cgroup_mkcgroup_root())
		return -1;

	struct pantavisor *pv = pv_get_instance();
	pv->cgroupv = pv_cgroup_get_version();

	if (pv_cgroup_mkcgroup_init("systemd"))
		return -1;
	if (pv_cgroup_mkcgroup_init("pantavisor"))
		return -1;

	pv_cgroup_mkcgroup_resource("blkio");
	pv_cgroup_mkcgroup_resource("cpu,cpuacct");
	pv_cgroup_mkcgroup_resource("cpu");
	pv_cgroup_mkcgroup_resource("cpuset");
	pv_cgroup_mkcgroup_resource("devices");
	pv_cgroup_mkcgroup_resource("freezer");
	pv_cgroup_mkcgroup_resource("hugetlb");
	pv_cgroup_mkcgroup_resource("memory");
	pv_cgroup_mkcgroup_resource("net_cls,net_prio");
	pv_cgroup_mkcgroup_resource("net_cls");
	pv_cgroup_mkcgroup_resource("net_prio");
	pv_cgroup_mkcgroup_resource("perf_event");
	pv_cgroup_mkcgroup_resource("pids");
	pv_cgroup_mkcgroup_resource("rdma");

	pv_cgroup_mkcgroup_unified();

	return 0;
}

void pv_cgroup_umount(void)
{
	pv_fs_path_remove("/sys/fs/cgroup/pantavisor", false);
}

static char *pv_cgroup_parse_proc_legacy(FILE *fd)
{
	char *pvcg, *pname = NULL;
	char buf[128];
	while (fgets(buf, 128, fd)) {
		int l = strlen(buf) - 1;
		if (buf[l] == '\n')
			buf[l] = 0;
		pvcg = strstr(buf, ":name=pantavisor:/");
		if (pvcg) {
			pvcg += strlen(":name=pantavisor:/");
			if (!strncmp(pvcg, "lxc/", 4))
				pvcg += 4;
			if (!strlen(pvcg))
				pname = strdup("_pv_");
			else
				pname = strdup(pvcg);
			break;
		}
	}

	return pname;
}

static char *pv_cgroup_parse_proc_unified(FILE *fd)
{
	char *pvcg, *pname = NULL;
	char buf[128];
	while (fgets(buf, 128, fd)) {
		pvcg = strstr(buf, "/lxc/");
		if (pvcg) {
			pvcg += strlen("/lxc/");
			pvcg[strlen(pvcg) - 1] = '\0';
			pname = strdup(pvcg);
			break;
		}
	}

	return pname;
}

char *pv_cgroup_get_process_name(pid_t pid)
{
	int len;
	char path[PATH_MAX];
	len = strlen("/proc/%d/cgroup") + get_digit_count(pid) + 1;
	snprintf(path, len, "/proc/%d/cgroup", pid);

	FILE *fd;
	fd = fopen(path, "r");
	if (!fd) {
		pv_log(WARN, "could not open %s: %s", path, strerror(errno));
		return NULL;
	}

	struct pantavisor *pv = pv_get_instance();
	char *pname = NULL;
	if ((pv->cgroupv == CGROUP_LEGACY) || (pv->cgroupv == CGROUP_HYBRID))
		pname = pv_cgroup_parse_proc_legacy(fd);
	else if (pv->cgroupv == CGROUP_UNIFIED)
		pname = pv_cgroup_parse_proc_unified(fd);
	else
		pv_log(WARN, "unknown cgroup version");

	fclose(fd);

	return pname;
}

#define CGROUP_PATH "/sys/fs/cgroup/lxc/%s/"

void pv_cgroup_destroy(const char *name)
{
	// keep this only for appengine for now
	if (pv_config_get_system_init_mode() != IM_APPENGINE)
		return;

	// hanging cgroup has not been seen out of cgroup v2
	struct pantavisor *pv = pv_get_instance();
	if (pv->cgroupv != CGROUP_UNIFIED)
		return;

	int i;
	struct stat st;
	char path[PATH_MAX];
	snprintf(path, strlen(name) + strlen(CGROUP_PATH), CGROUP_PATH, name);

	for (i = 0; i < 5; i++) {
		if (stat(path, &st))
			return;

		pv_log(WARN, "/sys/fs/cgroup/lxc/%s/ still exists. Removing...",
		       name);
		pv_fs_path_remove(path, false);
		sleep(1);
	}

	pv_log(ERROR, "/sys/fs/cgroup/lxc/%s/ still exists", name);
}
