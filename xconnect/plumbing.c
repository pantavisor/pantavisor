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
#include <stdbool.h>
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
#include <arpa/inet.h>
#include <linux/limits.h>
#include <libgen.h>
#include <stddef.h>

#include "include/xconnect.h"

static int mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	char *p = NULL;

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
// Layout we maintain inside a consumer's /etc/hosts:
//
//     <user content above — preserved verbatim, append-friendly>
//     # >>> pvx-services managed BEGIN — DO NOT EDIT INSIDE THIS BLOCK
//     # Lines between BEGIN and END are rewritten by pv-xconnect on every
//     # service reconcile. Add your own entries ABOVE the BEGIN line or
//     # BELOW the END line; both regions are preserved across reconciles.
//     198.18.x.y	<service>.pv.local	# pvx-services managed
//     ...
//     # <<< pvx-services managed END — safe to append your own lines below
//     <user content below — preserved verbatim, append-friendly>
//
// The fence comments give the user (and append-blind tooling like Docker
// bridge setup or `echo ... >> /etc/hosts` from init scripts) a clear
// visual contract: the inside is ours, everything else is theirs. The
// per-line `# pvx-services managed` marker is still used inside the
// block so we can update individual entries without rewriting siblings.
#define PVX_HOSTS_BEGIN "# >>> pvx-services managed BEGIN"
#define PVX_HOSTS_END   "# <<< pvx-services managed END"
#define PVX_HOSTS_MARK  "# pvx-services managed"

// Block header lines emitted on first install. The trailing newlines
// keep the fputs path simple; we never include leading whitespace so
// matching is straightforward.
#define PVX_HOSTS_BEGIN_LINE                                                   \
	PVX_HOSTS_BEGIN " — DO NOT EDIT INSIDE THIS BLOCK\n"                  \
	"# Lines between BEGIN and END are rewritten by pv-xconnect on every\n" \
	"# service reconcile. Add your own entries ABOVE the BEGIN line or\n" \
	"# BELOW the END line; both regions are preserved across reconciles.\n"
#define PVX_HOSTS_END_LINE PVX_HOSTS_END " — safe to append your own lines below\n"

static int hosts_rewrite_locked(const char *hostname, const char *ip_str_or_null)
{
	// Algorithm:
	//   1. Walk existing /etc/hosts line-by-line.
	//   2. Track whether we're outside / inside / past the managed block.
	//   3. Outside the block: copy through verbatim (user content).
	//   4. Inside the block: drop the prior line for `hostname` (matched
	//      by per-line marker AND hostname). Other managed entries —
	//      different hostnames — are copied through verbatim. The new
	//      entry is emitted just before the END marker if `ip_str_or_null`
	//      is non-NULL.
	//   5. After the loop: if no BEGIN was seen and we have something to
	//      add, append a fresh BEGIN/entry/END block at the end. If we
	//      saw BEGIN but never END (truncated/malformed input), emit the
	//      missing END so future reconciles resume cleanly.
	//
	// We're already inside the consumer mount namespace; paths are
	// container-local. /etc/hosts is small (a few KB at most), so the
	// streaming approach is fine.
	FILE *in = fopen("/etc/hosts", "r");
	FILE *out = fopen("/etc/hosts.pvx.tmp", "w");
	if (!out) {
		if (in)
			fclose(in);
		return -1;
	}

	char line[1024];
	char marker[256];
	snprintf(marker, sizeof(marker), "\t%s\t%s\n", hostname, PVX_HOSTS_MARK);

	enum { ST_BEFORE, ST_INSIDE, ST_AFTER } state = ST_BEFORE;
	bool entry_written = false;

	if (in) {
		while (fgets(line, sizeof(line), in)) {
			if (state == ST_BEFORE) {
				if (strstr(line, PVX_HOSTS_BEGIN)) {
					// Re-emit a fresh BEGIN header (in case
					// someone trimmed the explanatory lines).
					fputs(PVX_HOSTS_BEGIN_LINE, out);
					state = ST_INSIDE;
				} else {
					fputs(line, out);
				}
				continue;
			}
			if (state == ST_INSIDE) {
				if (strstr(line, PVX_HOSTS_END)) {
					// Emit the new entry just before END.
					if (ip_str_or_null && !entry_written) {
						fprintf(out, "%s%s",
							ip_str_or_null, marker);
						entry_written = true;
					}
					fputs(PVX_HOSTS_END_LINE, out);
					state = ST_AFTER;
					continue;
				}
				// Drop the prior line for this hostname so we
				// don't emit duplicates. Other managed lines
				// (different hostnames) are preserved.
				if (strstr(line, PVX_HOSTS_MARK) &&
				    strstr(line, hostname))
					continue;
				// Skip the explanatory header lines that the
				// previous BEGIN block emitted; we re-emit a
				// fresh header above. Match by leading "# ".
				if (line[0] == '#' && line[1] == ' ' &&
				    (strstr(line, "DO NOT EDIT") ||
				     strstr(line, "rewritten by pv-xconnect") ||
				     strstr(line, "Add your own entries") ||
				     strstr(line, "service reconcile")))
					continue;
				fputs(line, out);
				continue;
			}
			// ST_AFTER: copy through.
			fputs(line, out);
		}
		fclose(in);
	}

	// Tail handling:
	//   - never saw BEGIN: append a fresh block if we have something to add
	//   - saw BEGIN but never END (malformed): close the block now
	if (state == ST_BEFORE && ip_str_or_null) {
		fputs(PVX_HOSTS_BEGIN_LINE, out);
		fprintf(out, "%s%s", ip_str_or_null, marker);
		fputs(PVX_HOSTS_END_LINE, out);
	} else if (state == ST_INSIDE) {
		if (ip_str_or_null && !entry_written)
			fprintf(out, "%s%s", ip_str_or_null, marker);
		fputs(PVX_HOSTS_END_LINE, out);
	}

	if (fclose(out) != 0)
		return -1;

	if (rename("/etc/hosts.pvx.tmp", "/etc/hosts") != 0) {
		unlink("/etc/hosts.pvx.tmp");
		return -1;
	}
	return 0;
}

static int hosts_setns_and_rewrite(int consumer_pid, const char *hostname,
				   const char *ip_str_or_null)
{
	int old_ns_fd = -1;
	int target_ns_fd = -1;
	int ret = -1;
	char ns_path[PATH_MAX];

	if (!hostname || !hostname[0])
		return -1;

	old_ns_fd = open("/proc/self/ns/mnt", O_RDONLY);
	if (old_ns_fd < 0) {
		perror("hosts: open current ns");
		return -1;
	}

	snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", consumer_pid);
	target_ns_fd = open(ns_path, O_RDONLY);
	if (target_ns_fd < 0) {
		perror("hosts: open target ns");
		close(old_ns_fd);
		return -1;
	}

	if (setns(target_ns_fd, CLONE_NEWNS) < 0) {
		perror("hosts: setns");
		goto out;
	}

	ret = hosts_rewrite_locked(hostname, ip_str_or_null);
	if (ret != 0)
		fprintf(stderr,
			"hosts: rewrite failed for %s in pid %d (errno=%d %s)\n",
			hostname, consumer_pid, errno, strerror(errno));

out:
	if (setns(old_ns_fd, CLONE_NEWNS) < 0) {
		perror("hosts: setns back");
		exit(1);
	}
	if (old_ns_fd >= 0)
		close(old_ns_fd);
	if (target_ns_fd >= 0)
		close(target_ns_fd);
	return ret;
}

int pvx_helper_inject_hosts_entry(int consumer_pid, const char *hostname,
				  uint32_t ipv4_network_order)
{
	if (consumer_pid <= 0 || !hostname || !ipv4_network_order)
		return -1;

	unsigned char *o = (unsigned char *)&ipv4_network_order;
	char ip_str[INET_ADDRSTRLEN];
	snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", o[0], o[1], o[2],
		 o[3]);
	return hosts_setns_and_rewrite(consumer_pid, hostname, ip_str);
}

int pvx_helper_remove_hosts_entry(int consumer_pid, const char *hostname)
{
	if (consumer_pid <= 0 || !hostname)
		return -1;
	return hosts_setns_and_rewrite(consumer_pid, hostname, NULL);
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