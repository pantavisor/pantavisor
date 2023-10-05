/*
 * Copyright (c) 2023 Pantacor Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "disk_utils.h"
#include "disk.h"
#include "logserver/logserver.h"
#include "utils/tsh.h"
#include "utils/fs.h"

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <errno.h>
#include <ctype.h>
#include <mntent.h>
#include <linux/limits.h>

#define MODULE_NAME "disk-utils"
#define pv_log(level, msg, ...) vlog(MODULE_NAME, level, msg, ##__VA_ARGS__)
#include "log.h"

struct mount_ops {
	char *name;
	int flag;
};

struct mount_ops mount_options[] = {
	{ "MS_DIRSYNC", MS_DIRSYNC },
	{ "MS_LAZYTIME", MS_LAZYTIME },
	{ "MS_MANDLOCK", MS_MANDLOCK },
	{ "MS_NOATIME", MS_NOATIME },
	{ "MS_NODEV", MS_NODEV },
	{ "MS_NODIRATIME", MS_NODIRATIME },
	{ "MS_NOEXEC", MS_NOEXEC },
	{ "MS_NOSUID", MS_NOSUID },
	{ "MS_RDONLY", MS_RDONLY },
	{ "MS_REC", MS_REC },
	{ "MS_RELATIME", MS_RELATIME },
	{ "MS_SILENT", MS_SILENT },
	{ "MS_STRICTATIME", MS_STRICTATIME },
	{ "MS_SYNCHRONOUS", MS_SYNCHRONOUS },
	// { "MS_NOSYMFOLLOW", MS_NOSYMFOLLOW },
};

#define PV_DISK_MOUNT_OPTIONS_SIZE                                             \
	sizeof(mount_options) / sizeof(struct mount_ops)

// internal commands
#define PV_DISK_UTILS_CMD_FORMAT "mkfs.%s %s %s"
#define PV_DISK_UTILS_CMD_MKSWAP "mkswap %s %s"
#define PV_DISK_UTILS_CMD_SWAPON "swapon %s %s"
#define PV_DISK_UTILS_CMD_SWAPOFF "swapoff %s"
#define PV_DISK_UTILS_CMD_CREATE_FILE "dd if=/dev/zero of=%s bs=%s count=1"

// buffer size to read mounts
#define PV_MNTENT_BUF_SIZE PATH_MAX * 2 + sizeof(int) * 2 + 512

static void remove_whitespace(char *str)
{
	size_t j = 0;
	for (size_t i = 0; i < strlen(str); ++i) {
		if (isspace(str[i]))
			continue;

		str[j] = str[i];
		++j;
	}
	str[j] = '\0';
}

static int parse_mount_ops(const char *options)
{
	int flags = 0;
	char *ops = strdup(options);
	remove_whitespace(ops);

	if (!ops)
		return -1;

	char *tmp = NULL;
	char *tok = strtok_r(ops, ",", &tmp);
	while (tok) {
		for (size_t i = 0; i < PV_DISK_MOUNT_OPTIONS_SIZE; ++i) {
			if (!strcmp(tok, mount_options[i].name))
				flags |= mount_options[i].flag;
		}
	}

	free(ops);

	return flags;
}

static int subscribe_pipe(int *cmd_pipe, const char *name, int level)
{
	errno = 0;
	if (pipe(cmd_pipe) == -1) {
		pv_log(ERROR, "cannot create pipe for %s, err: %s", name,
		       strerror(errno));
		return -1;
	}

	pv_logserver_subscribe_fd(cmd_pipe[0], "pantavisor", name, level);

	return 0;
}

static int run_command(char *cmd, const char *out_name, const char *err_name)
{
	int wstatus = 0;
	int ret = 0;
	int out_pipe[2] = { 0 };
	int err_pipe[2] = { 0 };

	if (subscribe_pipe(out_pipe, out_name, INFO) != 0 ||
	    subscribe_pipe(err_pipe, err_name, WARN) != 0) {
		return -1;
	}

	ret = tsh_run_io(cmd, 1, &wstatus, NULL, out_pipe, err_pipe);

	if (ret < 0) {
		pv_log(ERROR, "command: %s error: %s", cmd);
		return ret;
	} else if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus)) {
		pv_log(ERROR, "command failed %s status: %d", cmd,
		       WEXITSTATUS(wstatus));
		ret = -1;
	} else if (WIFEXITED(wstatus)) {
		pv_log(DEBUG, "command succeeded: %s", cmd);
		ret = 0;
	} else if (WIFSIGNALED(wstatus)) {
		pv_log(ERROR, "command signalled %s: %d", cmd,
		       WTERMSIG(wstatus));
		ret = -2;
	} else {
		pv_log(ERROR, "command failed with wstatus: %d", wstatus);
		ret = -3;
	}
	close(out_pipe[1]);
	close(err_pipe[1]);

	return ret;
}

int pv_disk_utils_run_cmd(const char *tmpl, const char *out_name,
			  const char *err_name, ...)
{
	va_list ap;
	va_start(ap, err_name);

	char *cmd = NULL;
	int n = vasprintf(&cmd, tmpl, ap);
	va_end(ap);

	if (n < 0) {
		free(cmd);
		return -1;
	}

	if (!out_name)
		out_name = "disk-utils-info";

	if (!err_name)
		err_name = "disk-utils-error";

	int ret = run_command(cmd, out_name, err_name);
	free(cmd);

	return ret;
}

pv_disk_status_t pv_disk_utils_is_mounted(struct pv_disk *disk,
					  const char *source,
					  bool check_mount_point)
{
	FILE *fd = setmntent(source, "r");
	if (!fd) {
		pv_log(WARN, "error cannot open source to check disk %s",
		       disk->name);
		return DISK_STATUS_ERROR;
	}

	char buf[PV_MNTENT_BUF_SIZE] = { 0 };
	struct mntent entry_buf = { 0 };
	pv_disk_status_t status = DISK_STATUS_NOT_MOUNTED;

	struct mntent *entry = NULL;
	while ((entry = getmntent_r(fd, &entry_buf, buf, PV_MNTENT_BUF_SIZE)) !=
	       NULL) {
		if (disk->path && !strcmp(disk->path, entry->mnt_fsname)) {
			status = DISK_STATUS_MOUNTED;
			break;
		}

		if (check_mount_point &&
		    !strcmp(disk->mount_target, entry->mnt_dir)) {
			status = DISK_STATUS_ERROR;
			pv_log(WARN,
			       "disk %s wants to mount at %s but mount point is already used by %s",
			       disk->name, entry->mnt_dir, entry->mnt_fsname);
			break;
		}
	}
	endmntent(fd);

	return status;
}

int pv_disk_utils_mount(struct pv_disk *disk)
{
	const char *format = pv_disk_format_to_str(disk->format);

	int flags = 0;
	if (disk->mount_ops) {
		char *flags_str = strdup(disk->mount_ops);
		flags = parse_mount_ops(flags_str);
		free(flags_str);
	}

	pv_fs_mkdir_p(disk->mount_target, 0755);

	if (mount(disk->path, disk->mount_target, format, flags, NULL) != 0) {
		pv_log(WARN, "cannot mount %s to %s: %s", disk->name,
		       disk->mount_target, strerror(errno));
		return -1;
	}

	disk->mounted = true;
	pv_log(DEBUG, "disk %s successfully mounted at %s", disk->name,
	       disk->mount_target);

	return 0;
}

int pv_disk_utils_umount(struct pv_disk *disk)
{
	int err = umount(disk->mount_target);
	if (err != 0) {
		pv_log(WARN, "cannot umount %s from %s, device %s: %s",
		       disk->name, disk->mount_target, disk->path,
		       strerror(errno));
		return -1;
	}
	disk->mounted = false;
	return 0;
}

int pv_disk_utils_format(struct pv_disk *disk)
{
	const char *format = pv_disk_format_to_str(disk->format);
	const char *format_ops = disk->format_ops ? disk->format_ops : " ";

	return pv_disk_utils_run_cmd(PV_DISK_UTILS_CMD_FORMAT, NULL, NULL,
				     format, format_ops, disk->path);
}

int pv_disk_utils_mkswap(struct pv_disk *disk)
{
	const char *format_ops = disk->format_ops ? disk->format_ops : " ";

	int err = pv_disk_utils_run_cmd(PV_DISK_UTILS_CMD_MKSWAP, NULL, NULL,
					format_ops, disk->path);
	if (err != 0) {
		pv_log(ERROR, "cannot format swap device %s", disk->name);
		return -1;
	}

	pv_log(DEBUG, "mkswap OK, device %s format as swap", disk->name);

	return 0;
}

int pv_disk_utils_swapon(struct pv_disk *disk)
{
	const char *mount_ops = disk->mount_ops ? disk->mount_ops : " ";

	int err = pv_disk_utils_run_cmd(PV_DISK_UTILS_CMD_SWAPON, NULL, NULL,
					mount_ops, disk->path);
	if (err != 0) {
		pv_log(ERROR, "cannot activate swap device %s swapon failed",
		       disk->name);
		return -1;
	}

	disk->mounted = true;
	pv_log(DEBUG, "swap device %s) ready!", disk->name);
	return 0;
}

int pv_disk_utils_swapoff(struct pv_disk *disk)
{
	int err = pv_disk_utils_run_cmd(PV_DISK_UTILS_CMD_SWAPOFF, NULL, NULL,
					disk->path);
	if (err != 0) {
		pv_log(WARN, "cannot deactivate swap device %s swapoff failed",
		       disk->name);
		return -1;
	}
	disk->mounted = false;

	return 0;
}

int pv_disk_utils_create_file(const char *path, const char *size)
{
	int err = pv_disk_utils_run_cmd(PV_DISK_UTILS_CMD_CREATE_FILE, NULL,
					NULL, path, size);
	if (err != 0) {
		pv_log(WARN, "cannot create file %s", path);
		return -1;
	}
	return 0;
}
