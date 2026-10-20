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

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <lxc/lxccontainer.h>

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

const char *pv_cgroup_get_layout_str(void)
{
	switch (pv_get_instance()->cgroupv) {
	case CGROUP_LEGACY:
		return "legacy";
	case CGROUP_HYBRID:
		return "hybrid";
	case CGROUP_UNIFIED:
		return "unified";
	default:
		return "unknown";
	}
}

// 1 for hybrid and legacy, the same lines the container cgroup filter keeps
const char *pv_cgroup_get_version_str(void)
{
	switch (pv_get_instance()->cgroupv) {
	case CGROUP_LEGACY:
	case CGROUP_HYBRID:
		return "1";
	case CGROUP_UNIFIED:
		return "2";
	default:
		return "unknown";
	}
}

void pv_cgroup_print()
{
	struct pantavisor *pv = pv_get_instance();
	pv_log(INFO,
	       "cgroup layout %s, using cgroup version %s (PV_SYSTEM_CGROUP_VERSION=%s)",
	       pv_cgroup_get_layout_str(), pv_cgroup_get_version_str(),
	       pv_config_get_system_cgroup_version_str());

	// logged here because the log server is not up yet in pv_cgroup_init()
	if (pv->cgroupv != CGROUP_UNIFIED)
		pv_log(WARN,
		       "cgroup v1 is deprecated, set PV_SYSTEM_CGROUP_VERSION=2 and use lxc.cgroup2 lines in containers");
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

#define PV_CGROUP_NAME "pantavisor"
// LXC builds container paths from the cgroup of PID 1 minus a trailing
// init.scope, and the dir keys are relative to that, so this leaf must be
// named init.scope for containers to land in <base>/lxc/<name>
#define PV_CGROUP2_INIT "init.scope"

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

static int pv_cgroup_lxc_major_version(void)
{
	const char *version = lxc_get_version();

	return version ? atoi(version) : 0;
}

// LXC 7 dropped cgroup v1
static bool pv_cgroup_lxc_supports_v1(void)
{
	return pv_cgroup_lxc_major_version() < 7;
}

static bool pv_cgroup_kernel_has_cgroup2(void)
{
	char line[128];
	bool found = false;
	FILE *fp = fopen("/proc/filesystems", "r");

	if (!fp)
		return false;

	while (fgets(line, sizeof(line), fp)) {
		char *name = strrchr(line, '\t');
		name = name ? name + 1 : line;
		name[strcspn(name, "\n")] = '\0';
		if (!strcmp(name, "cgroup2")) {
			found = true;
			break;
		}
	}
	fclose(fp);

	return found;
}

// without cgroup BPF, LXC silently skips v2 device rules
static bool pv_cgroup_kernel_has_bpf_devices(void)
{
	struct bpf_insn insns[2] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K,
		  .dst_reg = BPF_REG_0,
		  .imm = 1 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	union bpf_attr attr;
	int fd;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
	attr.insns = (__u64)(unsigned long)insns;
	attr.insn_cnt = 2;
	attr.license = (__u64)(unsigned long)"GPL";

	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0)
		return false;
	close(fd);

	return true;
}

static int pv_cgroup_mkcgroup2_root(void)
{
	int ret;

	mkdir("/sys/fs/cgroup", 0755);
	ret = mount("cgroup2", "/sys/fs/cgroup", "cgroup2",
		    MS_NOSUID | MS_NOEXEC | MS_NODEV, "nsdelegate");
	if (ret < 0)
		pv_log(ERROR, "Could not mount cgroup2: %s", strerror(errno));

	return ret;
}

// the base cgroup: the one pantavisor starts in, as seen from its cgroup namespace
static char pv_cgroup2_base_rel[PATH_MAX] = "/";
static char pv_cgroup2_base_fs[PATH_MAX] = "/sys/fs/cgroup";

static int pv_cgroup2_read_base(void)
{
	char line[PATH_MAX];
	FILE *fp = fopen("/proc/self/cgroup", "r");

	if (!fp) {
		pv_log(ERROR, "could not read /proc/self/cgroup: %s",
		       strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "0::/", 4))
			continue;
		line[strcspn(line, "\n")] = '\0';
		SNPRINTF_WTRUNC(pv_cgroup2_base_rel,
				sizeof(pv_cgroup2_base_rel), "%s", line + 3);
		break;
	}
	fclose(fp);

	if (!strcmp(pv_cgroup2_base_rel, "/"))
		SNPRINTF_WTRUNC(pv_cgroup2_base_fs, sizeof(pv_cgroup2_base_fs),
				"/sys/fs/cgroup");
	else
		SNPRINTF_WTRUNC(pv_cgroup2_base_fs, sizeof(pv_cgroup2_base_fs),
				"/sys/fs/cgroup%s", pv_cgroup2_base_rel);

	return 0;
}

// a cgroup with processes cannot pass controllers on to its children (EBUSY),
// so the base cgroup must be emptied before the controllers are enabled in it
static void pv_cgroup2_move_procs(void)
{
	char from[PATH_MAX], to[PATH_MAX];

	SNPRINTF_WTRUNC(from, sizeof(from), "%s/cgroup.procs",
			pv_cgroup2_base_fs);
	SNPRINTF_WTRUNC(to, sizeof(to), "%s/" PV_CGROUP2_INIT "/cgroup.procs",
			pv_cgroup2_base_fs);

	for (int round = 0; round < 5; round++) {
		int moved = 0;
		char pid[32];
		FILE *fp = fopen(from, "r");

		if (!fp) {
			pv_log(WARN, "could not read %s: %s", from,
			       strerror(errno));
			return;
		}
		while (fgets(pid, sizeof(pid), fp)) {
			int fd = open(to, O_WRONLY);

			if (fd < 0) {
				pv_log(WARN, "could not open %s: %s", to,
				       strerror(errno));
				fclose(fp);
				return;
			}
			pid[strcspn(pid, "\n")] = '\0';
			// EINVAL: kernel thread at the real root, ESRCH: process exited
			if (write(fd, pid, strlen(pid)) > 0)
				moved++;
			else if (errno != EINVAL && errno != ESRCH)
				pv_log(WARN, "could not move pid %s to %s: %s",
				       pid, to, strerror(errno));
			close(fd);
		}
		fclose(fp);
		if (!moved)
			return;
	}
}

static void pv_cgroup2_enable_controllers(void)
{
	char path[PATH_MAX], controllers[256] = { 0 };
	char *ctrl, *save = NULL;
	FILE *fp;

	SNPRINTF_WTRUNC(path, sizeof(path), "%s/cgroup.controllers",
			pv_cgroup2_base_fs);
	fp = fopen(path, "r");
	if (!fp) {
		pv_log(WARN, "could not read %s: %s", path, strerror(errno));
		return;
	}
	if (!fgets(controllers, sizeof(controllers), fp)) {
		fclose(fp);
		return;
	}
	fclose(fp);

	controllers[strcspn(controllers, "\n")] = '\0';

	SNPRINTF_WTRUNC(path, sizeof(path), "%s/cgroup.subtree_control",
			pv_cgroup2_base_fs);
	for (ctrl = strtok_r(controllers, " ", &save); ctrl;
	     ctrl = strtok_r(NULL, " ", &save)) {
		char value[64];
		int fd = open(path, O_WRONLY);

		if (fd < 0) {
			pv_log(WARN, "could not open %s: %s", path,
			       strerror(errno));
			return;
		}
		snprintf(value, sizeof(value), "+%s", ctrl);
		if (write(fd, value, strlen(value)) < 0)
			pv_log(WARN, "could not enable controller %s: %s", ctrl,
			       strerror(errno));
		close(fd);
	}
}

static int pv_cgroup2_setup(void)
{
	char path[PATH_MAX];

	if (pv_cgroup2_read_base())
		return -1;

	SNPRINTF_WTRUNC(path, sizeof(path), "%s/" PV_CGROUP2_INIT,
			pv_cgroup2_base_fs);
	if (mkdir(path, 0755) && errno != EEXIST) {
		pv_log(ERROR, "could not create %s: %s", path, strerror(errno));
		return -1;
	}

	pv_cgroup2_move_procs();
	pv_cgroup2_enable_controllers();

	return 0;
}

int pv_cgroup_v2_lxc_dirs(const char *name, char *container_dir,
			  char *monitor_dir, size_t len)
{
	char line[PATH_MAX], base[PATH_MAX] = "";
	const char *prefix;
	size_t base_len;
	FILE *fp = fopen("/proc/1/cgroup", "r");

	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "0::/", 4))
			continue;
		line[strcspn(line, "\n")] = '\0';
		SNPRINTF_WTRUNC(base, sizeof(base), "%s", line + 3);
		break;
	}
	fclose(fp);

	base_len = strlen(base);
	if (base_len >= strlen("/" PV_CGROUP2_INIT) &&
	    !strcmp(base + base_len - strlen("/" PV_CGROUP2_INIT),
		    "/" PV_CGROUP2_INIT)) {
		base_len -= strlen("/" PV_CGROUP2_INIT);
		base[base_len] = '\0';
	}
	if (!strcmp(base, "/")) {
		base[0] = '\0';
		base_len = 0;
	}

	if (!strcmp(pv_cgroup2_base_rel, base) ||
	    (!base_len && !strcmp(pv_cgroup2_base_rel, "/")))
		return 0;

	if (strncmp(pv_cgroup2_base_rel, base, base_len) ||
	    pv_cgroup2_base_rel[base_len] != '/')
		return -1;

	prefix = pv_cgroup2_base_rel + base_len + 1;
	if (snprintf(container_dir, len, "%s/lxc/%s", prefix, name) >=
		    (int)len ||
	    snprintf(monitor_dir, len, "%s/lxc.monitor.%s", prefix, name) >=
		    (int)len)
		return -1;

	return 1;
}

static int pv_cgroup_mount_v1(void)
{
	if (!pv_cgroup_lxc_supports_v1()) {
		pv_log(ERROR,
		       "cgroup v1 requested but LXC %s does not support it",
		       lxc_get_version());
		return -1;
	}

	if (pv_cgroup_mkcgroup_root())
		return -1;

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

static int pv_cgroup_mount_v2(void)
{
	if (!pv_cgroup_kernel_has_cgroup2()) {
		pv_log(ERROR,
		       "cgroup v2 requested but the kernel has no cgroup2");
		return -1;
	}
	if (!pv_cgroup_kernel_has_bpf_devices()) {
		pv_log(ERROR,
		       "cgroup v2 requested but the kernel has no cgroup BPF device programs");
		return -1;
	}

	if (pv_cgroup_mkcgroup2_root())
		return -1;

	if (pv_cgroup2_setup())
		return -1;

	return 0;
}

// the default depends on the init mode
static cgroup_conf_t pv_cgroup_requested_version(void)
{
	cgroup_conf_t req = pv_config_get_system_cgroup_version();

	if (req != CGV_DEFAULT)
		return req;

	return (pv_config_get_system_init_mode() == IM_APPENGINE) ? CGV_AUTO :
								    CGV_1;
}

// embedded and standalone: pantavisor mounts the cgroup tree itself
static int pv_cgroup_init_mount(cgroup_conf_t req)
{
	bool use_v2;

	switch (req) {
	case CGV_1:
		use_v2 = false;
		break;
	case CGV_2:
		use_v2 = true;
		break;
	default:
		use_v2 = pv_cgroup_kernel_has_cgroup2() &&
			 pv_cgroup_kernel_has_bpf_devices();
		if (!use_v2 && !pv_cgroup_lxc_supports_v1()) {
			pv_log(ERROR,
			       "no usable cgroup version: the kernel has no cgroup v2 support and LXC %s has no cgroup v1 support",
			       lxc_get_version());
			return -1;
		}
		break;
	}

	return use_v2 ? pv_cgroup_mount_v2() : pv_cgroup_mount_v1();
}

// appengine: the host decides the layout, pantavisor mounts nothing
static int pv_cgroup_init_appengine(cgroup_conf_t req)
{
	struct pantavisor *pv = pv_get_instance();
	pv->cgroupv = pv_cgroup_get_version();

	if (pv->cgroupv == CGROUP_UNKNOWN) {
		pv_log(ERROR, "could not detect the cgroup layout of the host");
		return -1;
	}

	bool host_v2 = (pv->cgroupv == CGROUP_UNIFIED);

	if ((req == CGV_1 && host_v2) || (req == CGV_2 && !host_v2)) {
		pv_log(ERROR,
		       "PV_SYSTEM_CGROUP_VERSION is %s but the host runs cgroup %s",
		       req == CGV_1 ? "1" : "2", host_v2 ? "v2" : "v1");
		return -1;
	}

	if (!host_v2 && !pv_cgroup_lxc_supports_v1()) {
		pv_log(ERROR,
		       "the host runs cgroup v1 but LXC %s does not support it",
		       lxc_get_version());
		return -1;
	}

	if (!host_v2) {
		if (pv_cgroup_mkcgroup_init(PV_CGROUP_NAME)) {
			pv_log(WARN,
			       "Pantavisor cgroup could not be initialized. It might be left over from previous runs. Continuing ...");
		}
	} else if (pv_cgroup2_setup()) {
		pv_log(ERROR, "could not set up the cgroup v2 layout");
		return -1;
	}

	return 0;
}

int pv_cgroup_init()
{
	cgroup_conf_t req = pv_cgroup_requested_version();
	struct pantavisor *pv = pv_get_instance();

	if (pv_config_get_system_init_mode() == IM_APPENGINE) {
		if (pv_cgroup_init_appengine(req))
			return -1;
	} else {
		if (pv_cgroup_init_mount(req))
			return -1;

		// Detect after all mounts are in place so HYBRID is recognised
		// via the presence of /sys/fs/cgroup/unified/. Running this before
		// the unified mount misreports HYBRID setups as LEGACY.
		pv->cgroupv = pv_cgroup_get_version();
	}

	return 0;
}

void pv_cgroup_umount(void)
{
	char path[PATH_MAX];

	if (pv_get_instance()->cgroupv == CGROUP_UNIFIED)
		SNPRINTF_WTRUNC(path, sizeof(path), "%s/" PV_CGROUP2_INIT,
				pv_cgroup2_base_fs);
	else
		SNPRINTF_WTRUNC(path, sizeof(path), "/sys/fs/cgroup/%s",
				PV_CGROUP_NAME);
	pv_fs_path_remove(path, false);
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
	char buf[PATH_MAX];
	size_t base_len = 0;

	if (strcmp(pv_cgroup2_base_rel, "/"))
		base_len = strlen(pv_cgroup2_base_rel);

	while (fgets(buf, sizeof(buf), fd)) {
		char *path, *name;

		buf[strcspn(buf, "\n")] = '\0';
		if (strncmp(buf, "0::", 3))
			continue;

		// paths are relative to the base cgroup
		path = buf + 3;
		if (base_len) {
			if (strncmp(path, pv_cgroup2_base_rel, base_len) ||
			    (path[base_len] != '\0' && path[base_len] != '/'))
				return NULL;
			path += base_len;
		}

		if (!*path || !strcmp(path, "/") ||
		    !strcmp(path, "/" PV_CGROUP2_INIT))
			return strdup("_pv_");

		if (!strncmp(path, "/lxc/", 5) && path[5]) {
			name = path + 5;
			name[strcspn(name, "/")] = '\0';
			return strdup(name);
		}

		// the LXC monitor of a container is not the container
		return NULL;
	}

	return NULL;
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

static void pv_cgroup_remove_retry(const char *path)
{
	struct stat st;

	if (stat(path, &st))
		return;

	for (int i = 0; i < 5; i++) {
		if (stat(path, &st))
			return;
		pv_log(WARN, "%s still exists. Removing...", path);
		pv_fs_path_remove(path, false);
		sleep(1);
	}

	pv_log(ERROR, "%s still exists after retries", path);
}

// Remove lxc.monitor.<name> and any lxc.monitor.<name>-<digit>* variants
// that LXC creates when it finds the preferred path occupied.
static void pv_cgroup_remove_monitor_variants(const char *tree,
					      const char *name)
{
	DIR *d = opendir(tree);
	if (!d)
		return;

	char prefix[NAME_MAX];
	int plen = snprintf(prefix, sizeof(prefix), "lxc.monitor.%s", name);
	if (plen < 0 || (size_t)plen >= sizeof(prefix)) {
		closedir(d);
		return;
	}

	struct dirent *entry;
	while ((entry = readdir(d)) != NULL) {
		if (strncmp(entry->d_name, prefix, plen))
			continue;

		const char *rest = entry->d_name + plen;
		// match exact or "<prefix>-<digit>..."
		if (*rest != '\0' &&
		    !(*rest == '-' && isdigit((unsigned char)*(rest + 1))))
			continue;

		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/%s", tree, entry->d_name);
		pv_cgroup_remove_retry(path);
	}

	closedir(d);
}

// Clean lxc/<name>/ and lxc.monitor.<name>[-N]/ leaves in a single hierarchy.
static void pv_cgroup_remove_hierarchy_leaves(const char *hierarchy,
					      const char *name)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/lxc/%s", hierarchy, name);
	pv_cgroup_remove_retry(path);

	pv_cgroup_remove_monitor_variants(hierarchy, name);
}

void pv_cgroup_destroy(const char *name)
{
	struct pantavisor *pv = pv_get_instance();

	switch (pv->cgroupv) {
	case CGROUP_UNIFIED:
		pv_cgroup_remove_hierarchy_leaves(pv_cgroup2_base_fs, name);
		break;
	case CGROUP_HYBRID: {
		// Walk every cgroup hierarchy under /sys/fs/cgroup. The
		// container is attached to all v1 controllers plus the v2
		// unified tree; each retains its own lxc/<name>/ and
		// lxc.monitor.<name>[-N]/ leaves that need cleaning.
		DIR *d = opendir("/sys/fs/cgroup");
		if (!d)
			return;

		struct dirent *entry;
		while ((entry = readdir(d)) != NULL) {
			if (entry->d_name[0] == '.')
				continue;

			char hierarchy[PATH_MAX];
			snprintf(hierarchy, sizeof(hierarchy),
				 "/sys/fs/cgroup/%s", entry->d_name);
			pv_cgroup_remove_hierarchy_leaves(hierarchy, name);
		}
		closedir(d);
		break;
	}
	default:
		return;
	}
}
